#!/usr/bin/env python3
"""
Contrôleur Flask : sert la vue statique et expose /api/parse (PDF → CSV).
Extraction : module parser (modèle).
"""

from __future__ import annotations

import hmac
import os
import tempfile
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_from_directory, session

from parser import (
    add_known_merchant_category,
    extraire_transactions,
    fusionner_pdf_dans_releve,
    load_categories_json,
    reappliquer_categories_csv,
)

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(32).hex()
if not os.getenv("FLASK_SECRET_KEY"):
    print(
        "⚠️  FLASK_SECRET_KEY absent du .env — les sessions expirent au redémarrage du serveur."
    )


def _pin_app_value() -> str:
    return (os.getenv("PIN_APP") or "").strip()


def _pin_required() -> bool:
    return bool(_pin_app_value())


def _session_pin_ok() -> bool:
    return bool(session.get("app_pin_ok"))


def require_pin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not _pin_required():
            return f(*args, **kwargs)
        if not _session_pin_ok():
            return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
        return f(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/auth/status", methods=["GET"])
def api_auth_status():
    need = _pin_required()
    ok = (not need) or _session_pin_ok()
    return jsonify({"pin_required": need, "authenticated": ok})


@app.route("/api/auth/pin", methods=["POST"])
def api_auth_pin():
    expected = _pin_app_value()
    if not expected:
        return jsonify({"ok": True, "message": "PIN non configuré (PIN_APP vide)."})
    body = request.get_json(silent=True) or {}
    submitted = body.get("pin")
    if submitted is None:
        submitted = ""
    a = str(submitted).encode("utf-8")
    b = expected.encode("utf-8")
    if len(a) != len(b) or not hmac.compare_digest(a, b):
        return jsonify({"error": "Code incorrect."}), 403
    session["app_pin_ok"] = True
    return jsonify({"ok": True})


@app.route("/api/parse", methods=["POST"])
@require_pin
def api_parse():
    if "pdf" not in request.files:
        return jsonify({"error": "Champ 'pdf' manquant"}), 400

    fichier = request.files["pdf"]
    if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Le fichier doit être un PDF"}), 400

    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    tmp = Path(path)
    try:
        fichier.save(tmp)
        # Note: parser.extraire_transactions does not have a 'verbose' arg; uses 'debug' instead
        transactions = extraire_transactions(tmp, debug=False)
    finally:
        tmp.unlink(missing_ok=True)

    if not transactions:
        return jsonify({"error": "Aucune transaction extraite"}), 422

    # Manually generate CSV string (since transactions_to_csv_string is not available)
    import csv
    import io
    # Reimporting COLNAMES from parser, or hard-code if necessary
    try:
        from parser import COLNAMES
    except ImportError:
        COLNAMES = ["DATE", "TYPE", "MONEY IN", "MONEY OUT", "BALANCE", "DESCRIPTION"]

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(COLNAMES)
    writer.writerows(transactions)
    csv_data = output.getvalue()

    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=Releve.csv"},
    )


@app.route("/api/load_releve", methods=["GET"])
@require_pin
def load_releve():
    releve_csv = ROOT / "Releve.csv"
    if not releve_csv.exists():
        return jsonify({"error": "Fichier Releve.csv introuvable"}), 404
    # Flask 2+ : send_from_directory(directory, path)
    return send_from_directory(
        directory=str(ROOT),
        path="Releve.csv",
        mimetype="text/csv; charset=utf-8",
    )


@app.route("/api/releve/pdf", methods=["POST"])
@require_pin
def api_releve_pdf():
    """
    Import d'un relevé PDF : parse, fusion dans Releve.csv, ignore les doublons
    (date, type, entrée, sortie, description).
    Champ formulaire : pdf
    """
    if "pdf" not in request.files:
        return jsonify({"error": "Champ « pdf » manquant."}), 400
    fichier = request.files["pdf"]
    if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Le fichier doit être un PDF."}), 400

    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    tmp = Path(path)
    try:
        fichier.save(tmp)
        stats = fusionner_pdf_dans_releve(tmp, ROOT / "Releve.csv")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp.unlink(missing_ok=True)

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
    """Liste des noms de catégories (clés de cathegorie.json → categories)."""
    try:
        data = load_categories_json()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    names = list(data.get("categories", {}).keys())
    return jsonify({"categories": names})


@app.route("/api/categorie", methods=["POST"])
@require_pin
def api_categorie():
    """
    Enregistre un marchand dans known_merchants, met à jour cathegorie.json,
    puis ré-extrait le PDF et régénère Releve.csv.
    JSON : { "merchant": "...", "category": "🛒 Alimentation / Courses" }
    """
    body = request.get_json(silent=True) or {}
    merchant = (body.get("merchant") or "").strip()
    category = (body.get("category") or "").strip()
    if not merchant or not category:
        return jsonify({"error": "Champs « merchant » et « category » requis."}), 400
    csv_path = ROOT / "Releve.csv"
    if not csv_path.is_file():
        return jsonify({
            "error": "Releve.csv introuvable — importez d’abord un relevé PDF.",
        }), 404
    try:
        add_known_merchant_category(merchant, category)
        n = reappliquer_categories_csv(csv_path)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({
        "ok": True,
        "message": (
            f"Marchand « {merchant} » associé à « {category} ». "
            f"{n} ligne(s) mises à jour dans {csv_path.name}."
        ),
        "transactions": n,
        "csv": csv_path.name,
    })


if __name__ == "__main__":
    print("Serveur : http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
