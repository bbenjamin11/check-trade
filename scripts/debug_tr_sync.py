#!/usr/bin/env python3
"""
Lance une sync Trade Republic avec mode DEBUG active.

Produit dans data/users/<user>/debug/ :
  tr_raw_events.csv   — tous les events bruts recus de l'API (avant tout parsing)
  tr_parse_report.csv — event par event : GARDE ou SUPPRIME + raison du drop

Cela permet de determiner si des transactions manquent a cause de :
  A) L'API ne les envoie pas (absent de tr_raw_events.csv)
  B) Le parser les supprime (present dans tr_raw_events.csv, SUPPRIME dans tr_parse_report.csv)

Lance :
    python scripts/debug_tr_sync.py --user benjamin --full
    python scripts/debug_tr_sync.py --user benjamin          # sync incrementale

Options :
    --user  : identifiant utilisateur (defaut: benjamin)
    --full  : force une sync complete (ignore la date de derniere sync)
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from services.tr_sync_service import TRSyncService
from services.credentials_service import TRCredentials
from controllers.app import _releve_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--user", default="benjamin")
    parser.add_argument("--full", action="store_true",
                        help="Sync complete (ignore la derniere date connue)")
    args = parser.parse_args()

    csv_path = _releve_path(args.user)
    debug_dir = csv_path.parent / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  DEBUG SYNC Trade Republic — user: {args.user}")
    print(f"  Debug output : {debug_dir}")
    print(f"{'='*60}\n")

    # Saisie des identifiants (jamais stockes)
    phone = input("Numero de telephone (+32...) : ").strip()
    pin = getpass.getpass("PIN Trade Republic : ").strip()
    csv_pin = getpass.getpass("PIN check-trade (pour le CSV) : ").strip()

    creds = TRCredentials(phone=phone, pin=pin)
    svc = TRSyncService()

    print("\n[1/3] Connexion a Trade Republic...")
    try:
        init = svc.initiate(creds)
    except RuntimeError as e:
        print(f"[ERR] {e}")
        return 1
    finally:
        del pin

    code = input(f"[2/3] Code de validation recu sur l'app TR ({init.countdown_seconds}s) : ").strip()

    # Pas de filtre de date si --full
    not_before = None
    if not args.full:
        # Essayer de lire la derniere date depuis un fichier de meta si ca existe
        meta_path = csv_path.parent / ".last_sync_iso"
        if meta_path.exists():
            not_before = meta_path.read_text().strip()
            print(f"[3/3] Sync incrementale depuis : {not_before}")
        else:
            print("[3/3] Pas de date de derniere sync, sync complete")
    else:
        print("[3/3] Sync complete (--full)")

    print("\nRecuperation des donnees... (peut prendre quelques secondes)")

    # Charger le CSV dechiffre pour la fusion
    from controllers.app import _decrypt_csv_bytes, _encrypt_csv_text
    blob = csv_path.read_bytes() if csv_path.exists() else b""
    if blob:
        try:
            _ = _decrypt_csv_bytes(blob, csv_pin)
        except ValueError:
            print("[ERR] PIN check-trade incorrect.")
            return 2

    try:
        result = svc.complete_and_sync(
            api=init.api,
            verify_code=code,
            csv_path=csv_path,
            not_before_iso=not_before,
            debug_csv_dir=debug_dir,
        )
    except RuntimeError as e:
        print(f"[ERR] {e}")
        return 1
    finally:
        del csv_pin

    # Sauvegarder la date de derniere sync
    if result.latest_event_iso:
        meta_path = csv_path.parent / ".last_sync_iso"
        meta_path.write_text(result.latest_event_iso)

    # ---- Rapport ----
    print(f"\n{'='*60}")
    print(f"  RESULTAT SYNC")
    print(f"{'='*60}")
    print(f"  Events bruts recus de l'API  : {result.debug_raw_events}")
    print(f"  Transactions parsees (gardes): {result.debug_parsed_rows}")
    print(f"  Supprimes par le parser      : {result.debug_dropped}")
    if result.debug_drop_reasons:
        print(f"\n  Raisons des drops :")
        for reason, count in sorted(result.debug_drop_reasons.items(), key=lambda x: -x[1]):
            print(f"    {reason:<30} : {count}")
    print(f"\n  Ajoutees au CSV              : {result.added}")
    print(f"  Doublons ignores             : {result.skipped}")
    print(f"  Total dans le CSV            : {result.total}")
    print(f"\n  Fichiers debug :")
    print(f"    {debug_dir / 'tr_raw_events.csv'}")
    print(f"    {debug_dir / 'tr_parse_report.csv'}")
    print(f"\n  ATTENTION : ces fichiers contiennent tes donnees financieres en clair.")
    print(f"  Supprime-les apres analyse.\n")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INTERRUPT]", file=sys.stderr)
        sys.exit(130)
