#!/usr/bin/env python3
"""
Contrôleur Flask : sert la vue statique et expose /api/parse (PDF → CSV).
Détection anti-bot : User-Agent, rate-limit fréquence, honeypot field.
"""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import time
from functools import wraps
from pathlib import Path
import logging

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, Response, jsonify, request, send_from_directory, session

from parser import (
    add_known_merchant_category,
    extraire_transactions,
    fusionner_pdf_dans_releve,
    load_categories_json,
    reappliquer_categories_csv,
)

ROOT = Path(os.path.abspath(os.path.dirname(__file__)))
DATA_DIR = ROOT / "data"
load_dotenv(str(ROOT / ".env"))

# ------------ LOGGER CONFIG --------------------------------------------------
log_file = ROOT / "app.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s : %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("app")

app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(32).hex()
if not os.getenv("FLASK_SECRET_KEY"):
    logger.warning("⚠️  FLASK_SECRET_KEY absent du .env — les sessions expirent au redémarrage.")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
MAX_ATTEMPTS: int = 5
LOCKOUT_SECONDS: int = 60

# Limite de taille de fichier (3 MB)
MAX_FILE_SIZE_BYTES = 3 * 1024 * 1024  # 3 Megabytes

# Anti-bot : délai minimum entre deux tentatives PIN (secondes)
MIN_DELAY_BETWEEN_ATTEMPTS: float = 1.5

# Anti-bot : User-Agents suspects (robots courants, scripts, scanners)
_BOT_UA_PATTERNS: list[str] = [
    r"python-requests",
    r"curl/",
    r"wget/",
    r"libwww",
    r"scrapy",
    r"go-http-client",
    r"java/",
    r"nikto",
    r"sqlmap",
    r"nmap",
    r"masscan",
    r"zgrab",
    r"dirbuster",
    r"nuclei",
    r"^$",          # UA vide
]
_BOT_UA_RE = re.compile("|".join(_BOT_UA_PATTERNS), re.IGNORECASE)

# Structure : { ip: {"attempts": int, "locked_until": float, "last_attempt": float} }
_login_attempts: dict[str, dict] = {}

# Structure rate-limit global (toutes routes) : { ip: [timestamp, ...] }
_request_log: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW: float = 10.0   # secondes
RATE_LIMIT_MAX: int = 20          # requêtes max par fenêtre (toutes routes confondues)

# Secrets de session en mémoire (ne jamais sérialiser en cookie/session)
_session_auth: dict[str, dict[str, str]] = {}

# Marqueur de format du CSV chiffré
ENC_MAGIC = b"CTENC1\n"
PBKDF2_ITERS = 390_000


# ---------------------------------------------------------------------------
# Helpers anti-bot
# ---------------------------------------------------------------------------

def _get_client_ip() -> str:
    """Retourne l'IP réelle du client."""
    return (
        request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        .split(",")[0]
        .strip()
    )


def _is_bot_user_agent() -> bool:
    """Retourne True si le User-Agent correspond à un bot/script connu."""
    ua = request.headers.get("User-Agent", "")
    return bool(_BOT_UA_RE.search(ua))


def _is_rate_limited(ip: str) -> bool:
    """
    Fenêtre glissante : bloque si > RATE_LIMIT_MAX requêtes en RATE_LIMIT_WINDOW secondes.
    Nettoie les entrées expirées à chaque appel.
    """
    now = time.monotonic()
    timestamps = _request_log.get(ip, [])
    # Garde uniquement les timestamps dans la fenêtre
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    timestamps.append(now)
    _request_log[ip] = timestamps
    return len(timestamps) > RATE_LIMIT_MAX


def _too_fast(ip: str) -> bool:
    """
    Vérifie que l'utilisateur n'enchaîne pas les tentatives PIN trop rapidement
    (protection contre le brute-force rapide même avant le blocage).
    """
    record = _login_attempts.get(ip, {})
    last = record.get("last_attempt", 0.0)
    return (time.monotonic() - last) < MIN_DELAY_BETWEEN_ATTEMPTS


def _bot_response() -> tuple:
    """Réponse générique renvoyée aux bots (volontairement vague)."""
    return jsonify({"error": "Requête refusée."}), 403


# ---------------------------------------------------------------------------
# Décorateur anti-bot (appliqué sur /api/auth/pin et peut l'être ailleurs)
# ---------------------------------------------------------------------------

def bot_guard(f):
    """
    Décorateur : vérifie UA suspect + rate-limit global.
    À placer AVANT @require_pin si combiné.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        ip = _get_client_ip()

        if _is_bot_user_agent():
            logger.warning("🤖 Bot UA détecté — IP: %s UA: %s", ip, request.headers.get("User-Agent", ""))
            return _bot_response()

        if _is_rate_limited(ip):
            logger.warning("🚦 Rate-limit dépassé — IP: %s", ip)
            return jsonify({"error": "Trop de requêtes.", "retry_after": RATE_LIMIT_WINDOW}), 429

        return f(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Verrouillage brute-force PIN
# ---------------------------------------------------------------------------

def _is_locked(ip: str) -> tuple[bool, float]:
    record = _login_attempts.get(ip)
    if not record:
        return False, 0.0
    locked_until = record.get("locked_until", 0.0)
    if locked_until and time.monotonic() < locked_until:
        return True, round(locked_until - time.monotonic(), 1)
    return False, 0.0


def _record_failure(ip: str) -> int:
    if ip not in _login_attempts:
        _login_attempts[ip] = {"attempts": 0, "locked_until": 0.0, "last_attempt": 0.0}
    record = _login_attempts[ip]
    if record["locked_until"] and time.monotonic() >= record["locked_until"]:
        record["attempts"] = 0
        record["locked_until"] = 0.0
    record["attempts"] += 1
    record["last_attempt"] = time.monotonic()
    if record["attempts"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.monotonic() + LOCKOUT_SECONDS
        return 0
    return MAX_ATTEMPTS - record["attempts"]


def _record_success(ip: str) -> None:
    _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# PIN helpers
# ---------------------------------------------------------------------------

def _derive_pin_key(pin: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode("utf-8")))


def _encrypt_csv_text(csv_text: str, pin: str) -> bytes:
    salt = os.urandom(16)
    key = _derive_pin_key(pin, salt)
    token = Fernet(key).encrypt(csv_text.encode("utf-8"))
    return ENC_MAGIC + base64.urlsafe_b64encode(salt) + b"\n" + token


def _decrypt_csv_bytes(blob: bytes, pin: str) -> str:
    if not blob.startswith(ENC_MAGIC):
        return blob.decode("utf-8-sig")
    lines = blob.split(b"\n", 2)
    if len(lines) < 3:
        raise ValueError("Format chiffré invalide.")
    salt = base64.urlsafe_b64decode(lines[1])
    token = lines[2]
    key = _derive_pin_key(pin, salt)
    try:
        plain = Fernet(key).decrypt(token)
    except InvalidToken as e:
        raise ValueError("PIN incorrect.") from e
    return plain.decode("utf-8")


def _sanitize_user_id(raw_user: str) -> str:
    user = (raw_user or "").strip().lower()
    user = re.sub(r"[^a-z0-9._-]+", "_", user)
    user = user.strip("._-")
    return user


def _store_session_auth(user_id: str, pin: str) -> None:
    token = os.urandom(18).hex()
    _session_auth[token] = {"user_id": user_id, "pin": pin}
    session["auth_token"] = token


def _get_session_pin() -> str | None:
    token = session.get("auth_token")
    if not token:
        return None
    auth = _session_auth.get(token)
    if not auth:
        return None
    return auth.get("pin")


def _get_session_user() -> str | None:
    token = session.get("auth_token")
    if not token:
        return None
    auth = _session_auth.get(token)
    if not auth:
        return None
    return auth.get("user_id")


def _pin_required() -> bool:
    # Le PIN sert de clé de chiffrement du CSV : toujours requis pour accéder aux routes protégées.
    return True


def _releve_path(user_id: str) -> Path:
    return DATA_DIR / "users" / user_id / "Releve.csv"


def _user_prefs_path(user_id: str) -> Path:
    return DATA_DIR / "users" / user_id / "known_merchants.json"


def _merchant_key(merchant: str) -> str:
    return merchant.strip().upper()


def _load_user_known_merchants(user_id: str) -> dict[str, str]:
    path = _user_prefs_path(user_id)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, str):
            kk = _merchant_key(k)
            if kk:
                out[kk] = v.strip()
    return out


def _save_user_known_merchants(user_id: str, mapping: dict[str, str]) -> None:
    path = _user_prefs_path(user_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = dict(sorted(mapping.items(), key=lambda kv: kv[0]))
    path.write_text(json.dumps(ordered, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_releve_csv_text(path: Path, pin: str) -> str:
    data = path.read_bytes()
    return _decrypt_csv_bytes(data, pin)


def _write_releve_csv_text(path: Path, csv_text: str, pin: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_encrypt_csv_text(csv_text, pin))


def require_pin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not _pin_required():
            return f(*args, **kwargs)
        if not _get_session_pin() or not _get_session_user():
            return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
        return f(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/auth/status", methods=["GET"])
def api_auth_status():
    need = _pin_required()
    ok = (not need) or (bool(_get_session_pin()) and bool(_get_session_user()))
    return jsonify({"pin_required": need, "authenticated": ok})


@app.route("/api/auth/pin", methods=["POST"])
@bot_guard
def api_auth_pin():
    body = request.get_json(silent=True) or {}
    submitted = str(body.get("pin") or "").strip()
    submitted_user = _sanitize_user_id(str(body.get("user") or ""))
    if not submitted_user:
        return jsonify({"error": "Identifiant utilisateur requis."}), 400
    if not submitted:
        return jsonify({"error": "PIN requis."}), 400

    ip = _get_client_ip()

    # ── Blocage actif ? ──────────────────────────────────────────────────────
    locked, remaining = _is_locked(ip)
    if locked:
        return jsonify({
            "error": f"Trop de tentatives. Réessayez dans {remaining} secondes.",
            "locked": True,
            "retry_after": remaining,
        }), 429

    # ── Tentative trop rapide ? (brute-force scriptée) ───────────────────────
    if _too_fast(ip):
        logger.warning("⚡ Tentative trop rapide — IP: %s", ip)
        return jsonify({
            "error": "Veuillez patienter avant de réessayer.",
            "retry_after": MIN_DELAY_BETWEEN_ATTEMPTS,
        }), 429

    # ── Honeypot : champ « website » doit rester VIDE ───────────────────────
    # Un bot qui remplit tous les champs sera piégé ici.
    if body.get("website"):
        logger.warning("🍯 Honeypot déclenché — IP: %s", ip)
        # Fausse réponse positive pour ne pas alerter le bot
        return jsonify({"ok": True}), 200

    releve = _releve_path(submitted_user)
    legacy_releve = DATA_DIR / "Releve.csv"
    pin_ok = True
    try:
        if not releve.exists() and legacy_releve.exists():
            releve.parent.mkdir(parents=True, exist_ok=True)
            legacy_releve.replace(releve)
            logger.info("📦 Migration ancien Releve.csv vers utilisateur %s.", submitted_user)
        if releve.exists():
            data = releve.read_bytes()
            if data.startswith(ENC_MAGIC):
                _decrypt_csv_bytes(data, submitted)
            else:
                # Migration transparente : premier PIN saisi devient la clé de chiffrement.
                _write_releve_csv_text(releve, data.decode("utf-8-sig"), submitted)
                logger.info("🔐 Migration Releve.csv en mode chiffré pour utilisateur %s.", submitted_user)
    except Exception:
        pin_ok = False

    if not pin_ok:
        remaining_attempts = _record_failure(ip)
        if remaining_attempts == 0:
            return jsonify({
                "error": f"Code incorrect. Compte bloqué {LOCKOUT_SECONDS} secondes.",
                "locked": True,
                "retry_after": LOCKOUT_SECONDS,
            }), 429
        return jsonify({
            "error": f"Code incorrect. {remaining_attempts} tentative(s) restante(s).",
            "remaining_attempts": remaining_attempts,
        }), 403

    _record_success(ip)
    _store_session_auth(submitted_user, submitted)
    return jsonify({"ok": True})


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    token = session.pop("auth_token", None)
    if token:
        _session_auth.pop(token, None)
    session.clear()
    return jsonify({"ok": True})


# ... (routes inchangées ci-dessous)
@app.route("/api/parse", methods=["POST"])
@require_pin
def api_parse():
    if "pdf" not in request.files:
        return jsonify({"error": "Champ 'pdf' manquant"}), 400
    fichier = request.files["pdf"]

    # Vérification taille fichier
    fichier.stream.seek(0, os.SEEK_END)
    size = fichier.stream.tell()
    fichier.stream.seek(0)
    if size > MAX_FILE_SIZE_BYTES:
        logger.warning("⛔ Fichier PDF trop gros (%.1f Ko) — IP: %s", size / 1024, _get_client_ip())
        return jsonify({"error": "Fichier PDF trop volumineux (maximum 3 Mo)"}), 413

    if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Le fichier doit être un PDF"}), 400
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    tmp = Path(path)
    try:
        fichier.save(tmp)
        transactions = extraire_transactions(tmp, debug=False)
    finally:
        tmp.unlink(missing_ok=True)
    if not transactions:
        return jsonify({"error": "Aucune transaction extraite"}), 422
    import csv, io
    try:
        from parser import COLNAMES
    except ImportError:
        COLNAMES = ["DATE", "TYPE", "MONEY IN", "MONEY OUT", "BALANCE", "DESCRIPTION"]
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(COLNAMES)
    writer.writerows(transactions)
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=Releve.csv"},
    )


@app.route("/api/load_releve", methods=["GET"])
@require_pin
def load_releve():
    user_id = _get_session_user()
    if not user_id:
        return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
    releve_csv = _releve_path(user_id)
    if not releve_csv.exists():
        return jsonify({"error": "Fichier Releve.csv introuvable"}), 404
    pin = _get_session_pin()
    if not pin:
        return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        csv_text = _read_releve_csv_text(releve_csv, pin)
        tmp_csv.write_text(csv_text, encoding="utf-8")
        user_known = _load_user_known_merchants(user_id)
        reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)
        csv_text = tmp_csv.read_text(encoding="utf-8")
        _write_releve_csv_text(releve_csv, csv_text, pin)
    except Exception:
        return jsonify({"error": "Impossible de déchiffrer Releve.csv avec ce PIN."}), 403
    finally:
        tmp_csv.unlink(missing_ok=True)
    return Response(csv_text, mimetype="text/csv; charset=utf-8")


@app.route("/api/releve/pdf", methods=["POST"])
@require_pin
def api_releve_pdf():
    if "pdf" not in request.files:
        return jsonify({"error": "Champ « pdf » manquant."}), 400
    fichier = request.files["pdf"]

    # Vérification taille fichier
    fichier.stream.seek(0, os.SEEK_END)
    size = fichier.stream.tell()
    fichier.stream.seek(0)
    if size > MAX_FILE_SIZE_BYTES:
        logger.warning("⛔ Fichier PDF trop gros (%.1f Ko) — IP: %s", size / 1024, _get_client_ip())
        return jsonify({"error": "Fichier PDF trop volumineux (maximum 3 Mo)"}), 413

    if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Le fichier doit être un PDF."}), 400
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    tmp = Path(path)
    pin = _get_session_pin()
    user_id = _get_session_user()
    if not pin:
        return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
    if not user_id:
        return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        fichier.save(tmp)
        releve = _releve_path(user_id)
        user_known = _load_user_known_merchants(user_id)
        if releve.exists():
            tmp_csv.write_text(_read_releve_csv_text(releve, pin), encoding="utf-8")
        else:
            tmp_csv.unlink(missing_ok=True)
        stats = fusionner_pdf_dans_releve(tmp, tmp_csv)
        reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)
        _write_releve_csv_text(releve, tmp_csv.read_text(encoding="utf-8"), pin)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp.unlink(missing_ok=True)
        tmp_csv.unlink(missing_ok=True)
    return jsonify({
        "ok": True,
        "added": stats["added"],
        "skipped_duplicates": stats["skipped"],
        "total": stats["total"],
        "message": (
            f"+{stats['added']} transaction(s) ajoutée(s), "
            f"{stats['skipped']} doublon(s) ignoré(s) — {stats['total']} ligne(s) dans Releve.csv."
        ),
    })


@app.route("/api/categories", methods=["GET"])
@require_pin
def api_categories():
    try:
        data = load_categories_json()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({"categories": list(data.get("categories", {}).keys())})


@app.route("/api/categorie", methods=["POST"])
@require_pin
def api_categorie():
    body = request.get_json(silent=True) or {}
    merchant = (body.get("merchant") or "").strip()
    category = (body.get("category") or "").strip()
    if not merchant or not category:
        return jsonify({"error": "Champs « merchant » et « category » requis."}), 400
    user_id = _get_session_user()
    if not user_id:
        return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
    csv_path = _releve_path(user_id)
    if not csv_path.is_file():
        return jsonify({"error": "Releve.csv introuvable — importez d'abord un relevé PDF."}), 404
    pin = _get_session_pin()
    if not pin:
        return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        tmp_csv.write_text(_read_releve_csv_text(csv_path, pin), encoding="utf-8")
        # Règle globale partagée (profite à tous les utilisateurs sans override perso)
        add_known_merchant_category(merchant, category)
        # Override local utilisateur (protège ses préférences futures)
        user_known = _load_user_known_merchants(user_id)
        mk = _merchant_key(merchant)
        if mk:
            user_known[mk] = category
            _save_user_known_merchants(user_id, user_known)
        n = reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)
        _write_releve_csv_text(csv_path, tmp_csv.read_text(encoding="utf-8"), pin)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp_csv.unlink(missing_ok=True)
    return jsonify({
        "ok": True,
        "message": (
            f"Marchand « {merchant} » associé à « {category} ». "
            f"{n} ligne(s) mises à jour dans {csv_path.name}."
        ),
        "transactions": n,
        "csv": csv_path.name,
    })

@app.route("/api/categories/full", methods=["GET"])
@require_pin
def api_categories_full():
    try:
        data = load_categories_json()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(data)


if __name__ == "__main__":
    logger.info("Serveur : http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
