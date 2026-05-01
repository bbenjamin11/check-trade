#!/usr/bin/env python3
"""
Contrôleur Flask MVC - Version refactorisée avec architecture propre
Utilise les nouveaux parseurs abstraits et respecte la séparation des responsabilités.
"""

from __future__ import annotations

import sys

# Forcer UTF-8 sur stdout/stderr (corrige les UnicodeEncodeError sur Windows cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

import base64
import json
import os
import re
import tempfile
import time
from functools import wraps
from pathlib import Path
import logging
import csv
import io

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, Response, jsonify, request, send_from_directory, session

# Import du modèle parseur
import sys
sys.path.append(str(Path(__file__).parent.parent))
from models.parsers import PDFTradeRepublicParser

# Import des anciennes fonctions pour la rétrocompatibilité
# TODO: À terme, tout migrer vers les modèles
from parser import (
    add_known_merchant_category,
    fusionner_pdf_dans_releve,
    load_categories_json,
    reappliquer_categories_csv,
    COLNAMES,
)

# 
#  CONFIGURATION
# 

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
VIEWS_DIR = ROOT / "views"
load_dotenv(str(ROOT / ".env"))

# Logger
log_file = ROOT / "app.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s : %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("app_mvc")

# Flask app
app = Flask(__name__, 
           static_folder=str(VIEWS_DIR / "static"), 
           static_url_path="/static")
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(32).hex()

if not os.getenv("FLASK_SECRET_KEY"):
    logger.warning("[WARNING] FLASK_SECRET_KEY absent du .env — sessions temporaires.")

# 
#  CONSTANTES ET SÉCURITÉ
# 

MAX_ATTEMPTS: int = 5
LOCKOUT_SECONDS: int = 60
MAX_FILE_SIZE_BYTES = 3 * 1024 * 1024  # 3 MB
MIN_DELAY_BETWEEN_ATTEMPTS: float = 1.5
PBKDF2_ITERS = 600_000

# Anti-bot User-Agent patterns
_BOT_UA_PATTERNS = [
    r"python-requests", r"curl/", r"wget/", r"libwww", r"scrapy",
    r"go-http-client", r"java/", r"nikto", r"sqlmap", r"nmap",
    r"masscan", r"zgrab", r"dirbuster", r"nuclei", r"^$"
]
_BOT_UA_RE = re.compile("|".join(_BOT_UA_PATTERNS), re.IGNORECASE)

# Structures de sécurité
_login_attempts: dict[str, dict] = {}
_request_log: dict[str, list[float]] = {}
_session_auth: dict[str, dict[str, str]] = {}

RATE_LIMIT_WINDOW: float = 10.0
RATE_LIMIT_MAX: int = 20
ENC_MAGIC = b"CTENC1\n"

# 
#  SERVICES MÉTIER (À TERME, DÉPLACER VERS models/services/)
# 

class ParseService:
    """Service de parsing - encapsule la logique métier."""
    
    def __init__(self):
        self.trade_republic_parser = PDFTradeRepublicParser()
    
    def parse_pdf(self, pdf_path: Path) -> list[list[str]]:
        """Parse un PDF et retourne les transactions."""
        try:
            transactions = self.trade_republic_parser.extract_csv(pdf_path)
            logger.info(f"[OK] {len(transactions)} transactions extraites de {pdf_path.name}")
            return transactions
        except Exception as e:
            logger.error(f"[ERROR] Erreur parsing {pdf_path.name}: {e}")
            raise
    
    def transactions_to_csv(self, transactions: list[list[str]]) -> str:
        """Convertit les transactions en CSV."""
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";")
        writer.writerow(COLNAMES)
        writer.writerows(transactions)
        return output.getvalue()


class SecurityService:
    """Service de sécurité - gestion authentification et chiffrement."""
    
    @staticmethod
    def get_client_ip() -> str:
        return request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr) or "unknown"
    
    @staticmethod
    def is_bot_request() -> bool:
        user_agent = request.headers.get("User-Agent", "")
        return bool(_BOT_UA_RE.search(user_agent))
    
    @staticmethod
    def check_rate_limit(ip: str) -> bool:
        now = time.monotonic()
        if ip not in _request_log:
            _request_log[ip] = []
        
        # Nettoyer les anciennes requêtes
        _request_log[ip] = [t for t in _request_log[ip] if now - t <= RATE_LIMIT_WINDOW]
        
        if len(_request_log[ip]) >= RATE_LIMIT_MAX:
            return False
        
        _request_log[ip].append(now)
        return True
    
    @staticmethod
    def encrypt_csv(csv_text: str, pin: str) -> bytes:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
        key = base64.urlsafe_b64encode(kdf.derive(pin.encode("utf-8")))
        token = Fernet(key).encrypt(csv_text.encode("utf-8"))
        return ENC_MAGIC + base64.urlsafe_b64encode(salt) + b"\n" + token


# Instances des services
parse_service = ParseService()
security_service = SecurityService()

# 
#  MIDDLEWARE ET DÉCORATEURS
# 

def require_auth(f):
    """Décorateur pour vérifier l'authentification."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Vérification anti-bot
        if security_service.is_bot_request():
            logger.warning(f"🤖 Bot détecté: {request.headers.get('User-Agent', 'N/A')}")
            return jsonify({"error": "Accès refusé"}), 403
        
        # Vérification rate limiting
        client_ip = security_service.get_client_ip()
        if not security_service.check_rate_limit(client_ip):
            logger.warning(f" Rate limit dépassé pour {client_ip}")
            return jsonify({"error": "Trop de requêtes"}), 429
        
        return f(*args, **kwargs)
    return decorated

# 
#  ROUTES - VUES
# 

@app.route("/")
def index():
    """Route principale - sert l'interface statique."""
    static_dir = app.static_folder
    if static_dir and Path(static_dir).exists():
        return send_from_directory(static_dir, "index.html")
    return "Interface non trouvée", 404

# 
#  ROUTES - API
# 

@app.route("/api/parse", methods=["POST"])
@require_auth
def api_parse():
    """
    Route principale de parsing PDF vers CSV.
    Utilise le nouveau parseur abstrait PDFTradeRepublicParser.
    """
    try:
        # Validation du fichier
        if "pdf" not in request.files:
            return jsonify({"error": "Champ 'pdf' manquant"}), 400
        
        fichier = request.files["pdf"]
        
        # Vérification taille
        fichier.stream.seek(0, os.SEEK_END)
        size = fichier.stream.tell()
        fichier.stream.seek(0)
        
        if size > MAX_FILE_SIZE_BYTES:
            logger.warning(f" Fichier trop gros: {size/1024:.1f} Ko")
            return jsonify({"error": "Fichier trop volumineux (max 3 Mo)"}), 413
        
        if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
            return jsonify({"error": "Le fichier doit être un PDF"}), 400
        
        # Traitement avec le service de parsing
        fd, path = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        tmp_pdf = Path(path)
        
        try:
            fichier.save(tmp_pdf)
            transactions = parse_service.parse_pdf(tmp_pdf)
            
            if not transactions:
                return jsonify({"error": "Aucune transaction extraite"}), 422
            
            # Conversion en CSV
            csv_content = parse_service.transactions_to_csv(transactions)
            
            logger.info(f"[OK] Parse réussi: {len(transactions)} transactions")
            
            return Response(
                csv_content,
                mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": "attachment; filename=transactions.csv"},
            )
            
        finally:
            tmp_pdf.unlink(missing_ok=True)
            
    except Exception as e:
        logger.error(f"[ERROR] Erreur API parse: {e}")
        return jsonify({"error": f"Erreur de traitement: {str(e)}"}), 500


@app.route("/api/health", methods=["GET"])
def api_health():
    """Route de santé de l'application."""
    return jsonify({
        "status": "ok",
        "parser": "PDFTradeRepublicParser",
        "architecture": "MVC"
    })


@app.route("/api/info", methods=["GET"])
def api_info():
    """Informations sur l'application."""
    return jsonify({
        "app": "Check Trade",
        "version": "2.0-MVC",
        "architecture": {
            "model": "models/parsers/",
            "view": "views/static/", 
            "controller": "controllers/app_mvc.py"
        },
        "parsers": ["PDFTradeRepublicParser"],
        "features": [
            "Classification automatique des marchands",
            "Catégorisation intelligente",
            "Architecture MVC extensible"
        ]
    })

# 
#  GESTION D'ERREURS
# 

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Route non trouvée"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erreur interne: {error}")
    return jsonify({"error": "Erreur interne du serveur"}), 500

# 
#  POINT D'ENTRÉE
# 

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
    
    logger.info("[START] Démarrage Check Trade MVC")
    logger.info(f" Dossier static: {app.static_folder}")
    logger.info(f"[TOOLS] Mode debug: {debug}")
    logger.info(f"[WEB] Port: {port}")
    
    app.run(host="0.0.0.0", port=port, debug=debug)