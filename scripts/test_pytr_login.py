#!/usr/bin/env python3
"""
Script de test ISOLE et STATELESS pour pytr.

Demande phone + PIN a chaque execution. RIEN n'est stocke.
Sert uniquement a valider que pytr fonctionne avec ton compte
AVANT d'integrer le bouton Refresh dans l'interface.

Usage :
    python scripts/test_pytr_login.py

WARNINGS :
- Ne lance PAS ce script si l'app TR mobile est ouverte (deconnexion)
- Aucune sortie ne contient ton PIN (verifier avant de partager des logs)
- Si pytr crashe, ne partage pas la stack trace brute (peut contenir des fragments)
"""

from __future__ import annotations

import getpass
import logging
import sys
from pathlib import Path

# UTF-8 stdout pour eviter les UnicodeEncodeError sous Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

# Permettre l'import depuis la racine du projet
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from services.credentials_service import TRCredentials

# Logging discret - jamais le PIN
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("test_pytr_login")


def prompt_credentials() -> TRCredentials:
    """Saisie interactive. PIN cache. Jamais ecrit nulle part."""
    print("\n=== Test pytr (stateless) ===")
    print("Aucune donnee saisie ne sera stockee.\n")

    phone = input("Phone (format international, ex +33612345678) : ").strip()
    pin = getpass.getpass("PIN Trade Republic (4 chiffres, masque) : ").strip()

    try:
        creds = TRCredentials.from_request({"phone": phone, "pin": pin})
    except ValueError as e:
        print(f"[ERR] {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Best effort : on perd la reference locale au pin
        del pin

    return creds


def run_test(creds: TRCredentials) -> int:
    try:
        from pytr.api import TradeRepublicApi
    except ImportError:
        print(
            "[ERR] pytr n'est pas installe. Lance : pip install pytr",
            file=sys.stderr,
        )
        return 2

    log.info("Tentative de login (creds=%r)", creds)  # __repr__ masque

    api = TradeRepublicApi(phone_no=creds.phone, pin=creds.pin)

    try:
        api.login()
        log.info("Login OK")
    except Exception as e:
        # On NE logge PAS l'exception complete : la stack peut contenir le PIN
        log.error("Login KO : %s", type(e).__name__)
        print(f"[ERR] Login impossible : {type(e).__name__}", file=sys.stderr)
        return 4

    print("\n[1/2] Cash...")
    try:
        cash = api.cash()
        if cash is not None:
            print(f"  -> {_summarize(cash)}")
    except Exception as e:
        log.warning("cash() KO : %s", type(e).__name__)

    print("\n[2/2] Portfolio...")
    try:
        portfolio = api.portfolio()
        if portfolio is not None:
            print(f"  -> {_summarize(portfolio)}")
    except Exception as e:
        log.warning("portfolio() KO : %s", type(e).__name__)

    print("\n[OK] Test termine. Aucune donnee n'a ete sauvegardee.\n")
    return 0


def _summarize(obj) -> str:
    """Resume sans dumper le contenu (peut contenir du sensible)."""
    if isinstance(obj, dict):
        keys = list(obj.keys())[:5]
        return f"dict ({len(obj)} cles, ex: {keys})"
    if isinstance(obj, list):
        return f"list ({len(obj)} elements)"
    return type(obj).__name__


def main() -> int:
    creds = prompt_credentials()
    try:
        return run_test(creds)
    finally:
        # Liberation explicite de la reference (best effort, GC fait le reste)
        del creds


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INTERRUPT]", file=sys.stderr)
        sys.exit(130)
