#!/usr/bin/env python3
"""
App.py - Point d'entrée Flask (Application Layer)
Sépare l'infrastructure web des contrôleurs métier
"""

import logging
import os
import sys
from pathlib import Path

# Forcer UTF-8 sur stdout/stderr (corrige les UnicodeEncodeError sur Windows cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

# Configuration
ROOT = Path(__file__).parent

# ------------ LOGGER CONFIG --------------------------------------------------
# Fichier (logs/app.log) + stdout (stdout est capté par "docker compose logs"
# sans avoir besoin d'ouvrir le fichier).
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s : %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("app")

from flask import Flask

app = Flask(__name__,
           static_folder=str(ROOT / "views" / "static"),
           static_url_path="/static")

app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(32).hex()
if not os.getenv("FLASK_SECRET_KEY"):
    logger.warning("FLASK_SECRET_KEY absent du .env — les sessions expirent au redémarrage.")

# Import et enregistrement des routes
from controllers.api_controller import api_bp
from controllers.web_controller import web_bp

# Enregistrement des blueprints
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(web_bp)

# Gestion d'erreurs globale
@app.errorhandler(404)
def not_found(error):
    return {"error": "Route non trouvée"}, 404

@app.errorhandler(500)
def internal_error(error):
    logger.exception("Erreur interne non gérée")
    return {"error": "Erreur interne du serveur"}, 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
    logger.info("Serveur : http://127.0.0.1:%d", port)
    app.run(host="0.0.0.0", port=port, debug=debug)
