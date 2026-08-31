#!/usr/bin/env python3
"""
API Controller - Gère les endpoints API REST
Pure logique métier sans couplage Flask (déléguée aux services)
"""

import logging
import os
import tempfile
from functools import wraps
from pathlib import Path

from flask import Blueprint, request, jsonify, Response

# Services métier
from services.parse_service import ParseService
from services.security_service import SecurityService
from services.auth_service import AuthService
from services.credentials_service import TRCredentials
from services.tr_sync_service import TRSyncService
from services.tr_session_store import TRSessionStore

logger = logging.getLogger(__name__)

# Blueprint API
api_bp = Blueprint('api', __name__)

# Instances des services (singletons applicatifs)
parse_service = ParseService()
security = SecurityService()
auth = AuthService()

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MAX_FILE_SIZE = 3 * 1024 * 1024  # 3 Mo


# ---------------------------------------------------------------------------
# Décorateurs de sécurité
# ---------------------------------------------------------------------------

def require_security(f):
    """Anti-bot + rate-limit générique."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if security.is_bot_request():
            return jsonify({"error": "Accès refusé"}), 403
        if not security.check_rate_limit():
            return jsonify({"error": "Trop de requêtes"}), 429
        return f(*args, **kwargs)
    return decorated


def require_pin(f):
    """
    Le PIN sert de clé de chiffrement du CSV utilisateur : requis sur toutes
    les routes qui touchent aux données personnelles.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not auth.get_session_pin() or not auth.get_session_user():
            return jsonify({"error": "Authentification requise.", "auth_required": True}), 401
        return f(*args, **kwargs)
    return decorated


def _validate_pdf_upload():
    """Valide l'upload PDF. Retourne une réponse d'erreur ou None si OK."""
    if "pdf" not in request.files:
        return jsonify({"error": "Champ 'pdf' manquant"}), 400

    fichier = request.files["pdf"]
    fichier.stream.seek(0, 2)
    size = fichier.stream.tell()
    fichier.stream.seek(0)

    if size > MAX_FILE_SIZE:
        return jsonify({"error": "Fichier trop volumineux (max 3 Mo)"}), 413
    if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Le fichier doit être un PDF"}), 400
    return None


# ---------------------------------------------------------------------------
#  ROUTES API - SANTÉ
# ---------------------------------------------------------------------------

@api_bp.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "parser": "PDFTradeRepublicParser",
        "architecture": "MVC-Clean",
    })


@api_bp.route('/info')
def info():
    return jsonify({
        "app": "Check Trade",
        "version": "3.1-Clean-MVC",
        "architecture": {
            "app": "app.py - Infrastructure Flask",
            "controllers": "controllers/ - Logique métier",
            "services": "services/ - Services métier",
            "models": "models/ - Modèles de données",
            "views": "views/ - Interface utilisateur",
        },
        "parsers": ["PDFTradeRepublicParser"],
        "features": ["pin_auth", "encrypted_storage", "tr_sync"],
        "patterns": ["Clean Architecture", "Dependency Injection", "Separation of Concerns"],
    })


# ---------------------------------------------------------------------------
#  ROUTES AUTHENTIFICATION
# ---------------------------------------------------------------------------

@api_bp.route('/auth/status')
def auth_status():
    ok = bool(auth.get_session_pin()) and bool(auth.get_session_user())
    return jsonify({"pin_required": True, "authenticated": ok})


@api_bp.route('/auth/pin', methods=['POST'])
@require_security
def auth_pin():
    """
    Vérifie (ou initialise) le PIN d'un utilisateur.
    Le PIN est aussi la clé de chiffrement de son Releve.csv : il n'existe
    pas de base de mots de passe séparée.
    """
    body = request.get_json(silent=True) or {}
    submitted_pin = str(body.get('pin') or '').strip()
    submitted_user = auth.sanitize_user_id(str(body.get('user') or ''))

    if not submitted_user:
        return jsonify({"error": "Identifiant utilisateur requis."}), 400
    if not submitted_pin:
        return jsonify({"error": "PIN requis."}), 400

    ip = auth.client_ip()

    locked, remaining = auth.is_locked(ip)
    if locked:
        return jsonify({
            "error": f"Trop de tentatives. Réessayez dans {remaining} secondes.",
            "locked": True,
            "retry_after": remaining,
        }), 429

    if auth.too_fast(ip):
        logger.warning("Tentative PIN trop rapide — IP: %s", ip)
        return jsonify({
            "error": "Veuillez patienter avant de réessayer.",
            "retry_after": 1.5,
        }), 429

    # Honeypot anti-bot : le champ "website" doit rester vide
    if body.get('website'):
        logger.warning("Honeypot déclenché — IP: %s", ip)
        return jsonify({"ok": True}), 200

    legacy_global_csv = DATA_DIR / "Releve.csv"
    pin_ok = auth.login(submitted_user, submitted_pin, legacy_global_csv=legacy_global_csv)

    if not pin_ok:
        remaining_attempts = auth.record_failure(ip)
        if remaining_attempts == 0:
            return jsonify({
                "error": "Code incorrect. Compte bloqué 60 secondes.",
                "locked": True,
                "retry_after": 60,
            }), 429
        return jsonify({
            "error": f"Code incorrect. {remaining_attempts} tentative(s) restante(s).",
            "remaining_attempts": remaining_attempts,
        }), 403

    auth.record_success(ip)
    auth.create_session(submitted_user, submitted_pin)
    return jsonify({"ok": True, "user": submitted_user, "message": "Authentification réussie"})


@api_bp.route('/auth/logout', methods=['POST'])
def auth_logout():
    auth.clear_session()
    return jsonify({"ok": True, "message": "Déconnexion réussie"})


# ---------------------------------------------------------------------------
#  ROUTES CATÉGORIES
# ---------------------------------------------------------------------------

@api_bp.route('/categories')
@require_pin
def categories():
    try:
        from parser import load_categories_json
        data = load_categories_json()
        return jsonify({"categories": list(data.get("categories", {}).keys())})
    except Exception:
        return jsonify({"categories": ["Divers"]}), 200


@api_bp.route('/categories/full')
@require_pin
def categories_full():
    try:
        from parser import load_categories_json
        return jsonify(load_categories_json())
    except Exception:
        return jsonify({
            "categories": {
                "Alimentation": {"keywords": ["supermarché"], "merchants": []},
                "Banque / Finance / Investissement": {"keywords": ["banque"], "merchants": []},
                "Divers": {"keywords": [], "merchants": []},
            },
            "known_merchants": {},
            "priority_order": ["known_merchants", "Alimentation", "Banque / Finance / Investissement", "Divers"],
        })


@api_bp.route('/categorie', methods=['POST'])
@require_pin
def update_category():
    """
    Met à jour la catégorie d'un ou plusieurs marchands (règle globale +
    override utilisateur), en un seul cycle déchiffrement/écriture.

    Accepte deux formats de body JSON :
      - un seul marchand :   {"merchant": "...", "category": "..."}
      - un lot (batch) :     {"updates": [{"merchant": "...", "category": "..."}, ...]}
    """
    data = request.get_json(silent=True) or {}

    raw_updates = data.get('updates')
    if not isinstance(raw_updates, list) or not raw_updates:
        # Rétro-compat : ancien format a un seul marchand
        merchant = (data.get('merchant') or '').strip()
        category = (data.get('category') or '').strip()
        raw_updates = [{"merchant": merchant, "category": category}] if merchant and category else []

    updates: list[tuple[str, str]] = []
    for item in raw_updates:
        if not isinstance(item, dict):
            continue
        m = (item.get('merchant') or '').strip()
        c = (item.get('category') or '').strip()
        if m and c:
            updates.append((m, c))

    if not updates:
        return jsonify({"error": "Aucune mise à jour valide (marchand + catégorie requis)"}), 400

    user_id = auth.get_session_user()
    pin = auth.get_session_pin()
    csv_path = auth.releve_path(user_id)
    if not csv_path.is_file():
        return jsonify({"error": "Releve.csv introuvable — importez d'abord un relevé PDF."}), 404

    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        from parser import add_known_merchant_category, reappliquer_categories_csv

        tmp_csv.write_text(auth.read_releve_csv_text(csv_path, pin), encoding="utf-8")

        user_known = auth.load_user_known_merchants(user_id)
        for merchant, category in updates:
            # Règle globale partagée (profite à tous les utilisateurs sans override perso)
            add_known_merchant_category(merchant, category)
            # Override local utilisateur (protège ses préférences futures)
            mk = auth.merchant_key(merchant)
            if mk:
                user_known[mk] = category
        auth.save_user_known_merchants(user_id, user_known)

        # Un seul passage de recategorisation + un seul chiffrement, quel que
        # soit le nombre de marchands modifiés.
        n = reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)
        auth.write_releve_csv_text(csv_path, tmp_csv.read_text(encoding="utf-8"), pin)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp_csv.unlink(missing_ok=True)

    if len(updates) == 1:
        merchant, category = updates[0]
        message = f"Marchand '{merchant}' → '{category}'. {n} ligne(s) mises à jour."
    else:
        message = f"{len(updates)} marchand(s) recatégorisés. {n} ligne(s) mises à jour au total."

    return jsonify({
        "ok": True,
        "message": message,
        "transactions": n,
        "updated_merchants": len(updates),
    })


# ---------------------------------------------------------------------------
#  ROUTES RELEVÉ
# ---------------------------------------------------------------------------

@api_bp.route('/load_releve')
@require_pin
def load_releve():
    """Charge le Releve.csv chiffré de l'utilisateur connecté."""
    user_id = auth.get_session_user()
    pin = auth.get_session_pin()
    releve_csv = auth.releve_path(user_id)
    if not releve_csv.exists():
        return jsonify({"error": "Fichier Releve.csv introuvable"}), 404

    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        from parser import (
            detect_and_flag_cancellations,
            ecrire_csv,
            lire_releve_csv,
            reappliquer_categories_csv,
        )

        csv_text = auth.read_releve_csv_text(releve_csv, pin)
        tmp_csv.write_text(csv_text, encoding="utf-8")
        user_known = auth.load_user_known_merchants(user_id)
        reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)

        # Detection auto des paires debit/credit annulees (carte annulee,
        # remboursement...). Ne touche jamais une ligne deja marquee
        # (STATUS non vide) — un choix utilisateur reste sticky.
        rows = lire_releve_csv(tmp_csv)
        rows, nb_paired = detect_and_flag_cancellations(rows)
        if nb_paired:
            ecrire_csv(rows, tmp_csv)
            logger.info("%d paire(s) de transaction annulee(s) detectee(s) pour %s", nb_paired, user_id)

        csv_text = tmp_csv.read_text(encoding="utf-8")
        auth.write_releve_csv_text(releve_csv, csv_text, pin)
    except Exception:
        return jsonify({"error": "Impossible de déchiffrer Releve.csv avec ce PIN."}), 403
    finally:
        tmp_csv.unlink(missing_ok=True)

    return Response(csv_text, mimetype="text/csv; charset=utf-8")


@api_bp.route('/transaction/status', methods=['POST'])
@require_pin
def transaction_status():
    """
    Change le STATUS d'une transaction : "" (normale), "active" (confirmee
    comme vraie depense, ignoree par la detection auto), "annulee" (exclue
    des totaux) ou "interne" (virement interne, exclue des totaux).
    """
    from parser import (
        ecrire_csv,
        find_row_index,
        lire_releve_csv,
        set_row_status,
        STATUS_ACTIVE,
        STATUS_CANCELLED,
        STATUS_INTERNAL,
    )

    body = request.get_json(silent=True) or {}
    status = (body.get('status') or '').strip()
    if status not in ('', STATUS_ACTIVE, STATUS_CANCELLED, STATUS_INTERNAL):
        return jsonify({"error": f"Statut invalide : {status!r}"}), 400

    user_id = auth.get_session_user()
    pin = auth.get_session_pin()
    csv_path = auth.releve_path(user_id)
    if not csv_path.is_file():
        return jsonify({"error": "Releve.csv introuvable — importez d'abord un relevé PDF."}), 404

    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        tmp_csv.write_text(auth.read_releve_csv_text(csv_path, pin), encoding="utf-8")
        rows = lire_releve_csv(tmp_csv)
        idx = find_row_index(
            rows,
            tr_id=body.get('tr_id') or '',
            date_str=body.get('date') or '',
            type_=body.get('type') or '',
            money_in=body.get('money_in') or '',
            money_out=body.get('money_out') or '',
            description=body.get('description') or '',
        )
        if idx is None:
            return jsonify({"error": "Transaction introuvable."}), 404
        rows = set_row_status(rows, idx, status)
        ecrire_csv(rows, tmp_csv)
        csv_text = tmp_csv.read_text(encoding="utf-8")
        auth.write_releve_csv_text(csv_path, csv_text, pin)
    except IndexError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp_csv.unlink(missing_ok=True)
    return jsonify({"ok": True, "status": status})


@api_bp.route('/transaction/manual', methods=['POST'])
@require_pin
def transaction_manual():
    """
    Ajoute une transaction saisie a la main (ex: virement interne entre
    comptes). Par defaut STATUS="interne" (exclue des totaux) — le
    formulaire peut forcer STATUS="" si c'est une vraie depense/entree.
    """
    from parser import (
        add_known_merchant_category,
        build_manual_transaction_row,
        ecrire_csv,
        lire_releve_csv,
        reappliquer_categories_csv,
        STATUS_ACTIVE,
        STATUS_CANCELLED,
        STATUS_INTERNAL,
    )
    from datetime import date as _d

    body = request.get_json(silent=True) or {}
    date_iso = (body.get('date') or '').strip()
    direction = (body.get('direction') or '').strip()
    description = (body.get('description') or '').strip()
    category = (body.get('category') or '').strip()
    status = (body.get('status') or STATUS_INTERNAL).strip()
    try:
        amount = float(body.get('amount'))
    except (TypeError, ValueError):
        amount = 0.0

    if direction not in ('in', 'out'):
        return jsonify({"error": "Champ « direction » doit valoir 'in' ou 'out'."}), 400
    if amount <= 0:
        return jsonify({"error": "Montant invalide."}), 400
    if not description:
        return jsonify({"error": "Description requise."}), 400
    if not category:
        return jsonify({"error": "Catégorie requise."}), 400
    if status not in ('', STATUS_ACTIVE, STATUS_CANCELLED, STATUS_INTERNAL):
        return jsonify({"error": f"Statut invalide : {status!r}"}), 400
    try:
        y, m, d = (int(x) for x in date_iso.split('-'))
        _d(y, m, d)
    except (ValueError, AttributeError):
        return jsonify({"error": "Date invalide (attendu YYYY-MM-DD)."}), 400

    user_id = auth.get_session_user()
    pin = auth.get_session_pin()
    csv_path = auth.releve_path(user_id)
    if not csv_path.is_file():
        return jsonify({"error": "Releve.csv introuvable — importez d'abord un relevé PDF."}), 404

    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        tmp_csv.write_text(auth.read_releve_csv_text(csv_path, pin), encoding="utf-8")
        row = build_manual_transaction_row(date_iso, direction, amount, description, category, status)
        merchant = row[6]

        try:
            add_known_merchant_category(merchant, category)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        user_known = auth.load_user_known_merchants(user_id)
        mk = auth.merchant_key(merchant)
        if mk:
            user_known[mk] = category
            auth.save_user_known_merchants(user_id, user_known)

        rows = [row] + lire_releve_csv(tmp_csv)
        ecrire_csv(rows, tmp_csv)
        reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)

        csv_text = tmp_csv.read_text(encoding="utf-8")
        auth.write_releve_csv_text(csv_path, csv_text, pin)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp_csv.unlink(missing_ok=True)
    return jsonify({"ok": True, "transaction": row})


@api_bp.route('/releve/pdf', methods=['POST'])
@require_pin
def releve_pdf():
    """Upload PDF avec fusion dans le Releve.csv chiffré de l'utilisateur."""
    validation_result = _validate_pdf_upload()
    if validation_result:
        return validation_result

    user_id = auth.get_session_user()
    pin = auth.get_session_pin()
    fichier = request.files["pdf"]

    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    tmp_pdf = Path(path)
    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)

    try:
        from parser import fusionner_pdf_dans_releve, reappliquer_categories_csv

        fichier.save(tmp_pdf)
        releve = auth.releve_path(user_id)
        user_known = auth.load_user_known_merchants(user_id)

        if releve.exists():
            tmp_csv.write_text(auth.read_releve_csv_text(releve, pin), encoding="utf-8")
        else:
            tmp_csv.unlink(missing_ok=True)

        stats = fusionner_pdf_dans_releve(tmp_pdf, tmp_csv)
        reappliquer_categories_csv(tmp_csv, user_known_merchants=user_known)
        auth.write_releve_csv_text(releve, tmp_csv.read_text(encoding="utf-8"), pin)

        return jsonify({
            "ok": True,
            "added": stats["added"],
            "skipped_duplicates": stats["skipped"],
            "total": stats["total"],
            "message": f"+{stats['added']} transaction(s), {stats['skipped']} doublons ignorés",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp_pdf.unlink(missing_ok=True)
        tmp_csv.unlink(missing_ok=True)


@api_bp.route('/parse', methods=['POST'])
@require_security
@require_pin
def parse_pdf():
    """Parse un PDF en CSV (sans fusion, sans écriture disque)."""
    validation_result = _validate_pdf_upload()
    if validation_result:
        return validation_result

    fichier = request.files["pdf"]
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
        fichier.save(tmp_file.name)
        tmp_path = Path(tmp_file.name)
        try:
            transactions = parse_service.parse_pdf(tmp_path)
            csv_content = parse_service.transactions_to_csv(transactions)
            return Response(
                csv_content,
                mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": "attachment; filename=transactions.csv"},
            )
        except Exception as e:
            return jsonify({"error": f"Erreur de traitement: {str(e)}"}), 500
        finally:
            tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
#  ROUTES SYNC TRADE REPUBLIC
# ---------------------------------------------------------------------------

@api_bp.route('/tr/sync/init', methods=['POST'])
@require_pin
def tr_sync_init():
    """
    ÉTAPE 1 — Initie le login Trade Republic.

    Body JSON : {"phone": "+33...", "pin": "1234"}  (PIN Trade Republic, pas
    le PIN de check-trade — l'app TR mobile reçoit ensuite un push avec un
    code de validation, à renvoyer via /tr/sync/verify).

    Sécurité : aucune persistance des identifiants TR ; l'instance pytr est
    gardée en RAM serveur (TTL 5 min) le temps de l'étape 2.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type doit être application/json"}), 415

    payload = request.get_json(silent=True) or {}
    force_full = bool(payload.get("full"))
    try:
        tr_creds = TRCredentials.from_request(payload)
    except ValueError as e:
        logger.warning("[/tr/sync/init] payload invalide : %s", e)
        return jsonify({"error": str(e)}), 400
    payload = None

    user_id = auth.get_session_user()

    try:
        init_result = TRSyncService().initiate(tr_creds)
    except RuntimeError as e:
        logger.error("[/tr/sync/init] initiate KO : %s", e)
        return jsonify({"error": str(e)}), 502
    except Exception:
        logger.error("[/tr/sync/init] exception inattendue")
        return jsonify({"error": "Erreur interne pendant l'initialisation"}), 500
    finally:
        tr_creds = None

    session_id = TRSessionStore().create(api=init_result.api, user_id=user_id)

    last_event_iso = None if force_full else auth.load_last_tr_sync(user_id)
    sync_mode = "incrementale" if last_event_iso else "complete"

    return jsonify({
        "ok": True,
        "session_id": session_id,
        "countdown_seconds": init_result.countdown_seconds,
        "sync_mode": sync_mode,
        "last_event_iso": last_event_iso,
        "message": f"Code envoyé sur l'app TR. Tu as {init_result.countdown_seconds}s pour le saisir.",
    })


@api_bp.route('/tr/sync/verify', methods=['POST'])
@require_pin
def tr_sync_verify():
    """
    ÉTAPE 2 — Valide le code reçu et lance la synchronisation.

    Body JSON : {"session_id": "...", "code": "1234"}

    Sécurité : l'instance pytr est détruite après usage (succès ou échec).
    En cas d'échec il faut refaire /tr/sync/init.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type doit être application/json"}), 415

    payload = request.get_json(silent=True) or {}
    session_id = (payload.get("session_id") or "").strip()
    code = (payload.get("code") or "").strip()
    force_full = bool(payload.get("full"))
    payload = None

    if not session_id:
        return jsonify({"error": "session_id manquant"}), 400
    if not code or not code.isdigit() or len(code) < 4 or len(code) > 8:
        return jsonify({"error": "code invalide (4-8 chiffres)"}), 400

    user_id = auth.get_session_user()
    pin = auth.get_session_pin()

    store = TRSessionStore()
    try:
        api = store.get(session_id, expected_user_id=user_id)
    except KeyError:
        return jsonify({"error": "Session expirée ou invalide. Recommence depuis l'étape 1."}), 410

    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)

    try:
        releve = auth.releve_path(user_id)
        user_known = auth.load_user_known_merchants(user_id)
        # force_full : ignore le curseur incrementale, re-fetch tout l'historique
        # (utile pour recuperer des transactions manquees par un bug de dedup
        # anterieur, puisqu'une sync incrementale ne redemande jamais les
        # evenements plus anciens que le dernier curseur enregistre).
        last_event_iso = None if force_full else auth.load_last_tr_sync(user_id)

        if releve.exists():
            tmp_csv.write_text(auth.read_releve_csv_text(releve, pin), encoding="utf-8")
        else:
            tmp_csv.unlink(missing_ok=True)
            tmp_csv.touch()

        try:
            result = TRSyncService().complete_and_sync(
                api=api,
                verify_code=code,
                csv_path=tmp_csv,
                user_known_merchants=user_known,
                not_before_iso=last_event_iso,
            )
        except RuntimeError as e:
            logger.error("[/tr/sync/verify] sync KO : %s", e)
            return jsonify({"error": str(e)}), 502
        except Exception:
            logger.error("[/tr/sync/verify] exception inattendue")
            return jsonify({"error": "Erreur interne pendant la synchronisation"}), 500

        auth.write_releve_csv_text(releve, tmp_csv.read_text(encoding="utf-8"), pin)

        if result.latest_event_iso:
            auth.save_last_tr_sync(user_id, result.latest_event_iso)
        if result.cash_amount and result.cash_currency:
            auth.save_tr_balance(user_id, result.cash_amount, result.cash_currency)
    finally:
        tmp_csv.unlink(missing_ok=True)
        store.delete(session_id)
        api = None

    mode = "complete" if result.was_full_sync else "incrementale"
    return jsonify({
        "ok": True,
        "added": result.added,
        "skipped": result.skipped,
        "total": result.total,
        "portfolio_lines": result.portfolio_lines,
        "cash_amount": result.cash_amount,
        "cash_currency": result.cash_currency,
        "sync_mode": mode,
        "message": (
            f"Sync {mode} : +{result.added} transaction(s) ajoutée(s), "
            f"{result.skipped} doublon(s) ignoré(s) — {result.total} ligne(s) au total."
        ),
    })


@api_bp.route('/maintenance/dedupe', methods=['POST'])
@require_pin
def maintenance_dedupe():
    """
    Nettoyage ponctuel : supprime les doublons de contenu crees par le bug
    de dedup pre-TR_ID (une resynchronisation complete pouvait re-ajouter
    tout l'historique deja present, faute de TR_ID sur les vieilles lignes).
    Voir parser.dedupe_releve_by_content pour la regle exacte.
    """
    user_id = auth.get_session_user()
    pin = auth.get_session_pin()
    csv_path = auth.releve_path(user_id)
    if not csv_path.is_file():
        return jsonify({"error": "Releve.csv introuvable"}), 404

    fd_csv, path_csv = tempfile.mkstemp(suffix=".csv")
    os.close(fd_csv)
    tmp_csv = Path(path_csv)
    try:
        from parser import dedupe_releve_by_content

        tmp_csv.write_text(auth.read_releve_csv_text(csv_path, pin), encoding="utf-8")
        stats = dedupe_releve_by_content(tmp_csv)
        auth.write_releve_csv_text(csv_path, tmp_csv.read_text(encoding="utf-8"), pin)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        tmp_csv.unlink(missing_ok=True)

    return jsonify({
        "ok": True,
        "removed": stats["removed"],
        "total": stats["total"],
        "message": f"{stats['removed']} doublon(s) supprimé(s) — {stats['total']} ligne(s) restantes.",
    })


@api_bp.route('/tr/balance')
@require_pin
def tr_balance():
    """
    Dernier solde reel Trade Republic connu (recupere lors de la derniere
    sync reussie). Ne fait AUCUN appel reseau vers TR : juste une lecture
    du fichier persiste localement. Utilise pour affichage au chargement
    de la page, sans attendre une nouvelle sync.
    """
    user_id = auth.get_session_user()
    balance = auth.load_tr_balance(user_id)
    if not balance:
        return jsonify({"ok": True, "known": False})
    return jsonify({
        "ok": True,
        "known": True,
        "amount": balance["amount"],
        "currency": balance["currency"],
        "updated_at": balance.get("updated_at"),
    })
