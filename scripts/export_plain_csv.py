#!/usr/bin/env python3
"""
Export du Releve.csv chiffre vers un CSV lisible pour analyse.

Lance :
    python scripts/export_plain_csv.py --user benjamin

Produit :
    data/users/<user>/Releve_debug.csv      — toutes les transactions en clair
    data/users/<user>/Releve_monthly.csv    — resume mensuel (solde, IN, OUT, nb transactions)

ATTENTION : ces fichiers de debug ne sont PAS chiffres.
Supprime-les apres analyse.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import sys
from io import StringIO
from pathlib import Path
from collections import defaultdict

# UTF-8 stdout pour Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from controllers.app import _decrypt_csv_bytes, _releve_path

COLNAMES = ["DATE", "TYPE", "MONEY IN", "MONEY OUT", "BALANCE", "DESCRIPTION", "MERCHANT", "CATEGORY"]

MONTH_ORDER = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_amount(s: str) -> float:
    """Parse '€1.234,56' ou '€1,23' ou '' -> float."""
    if not s or not s.strip():
        return 0.0
    s = s.strip().replace("€", "").replace(" ", "")
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return 0.0


def date_key(date_str: str) -> tuple:
    """'5 Apr 2026' -> (2026, 4, 5)."""
    parts = date_str.strip().split()
    if len(parts) >= 3:
        try:
            return (int(parts[2]), MONTH_ORDER.get(parts[1], 0), int(parts[0]))
        except ValueError:
            pass
    return (0, 0, 0)


def month_label(date_str: str) -> str:
    """'5 Apr 2026' -> '2026-04'."""
    parts = date_str.strip().split()
    if len(parts) >= 3:
        try:
            month_num = MONTH_ORDER.get(parts[1], 0)
            return f"{int(parts[2])}-{month_num:02d}"
        except ValueError:
            pass
    return "0000-00"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--user", default="benjamin", help="Username (defaut: benjamin)")
    args = parser.parse_args()

    csv_path = _releve_path(args.user)
    if not csv_path.exists():
        print(f"[ERR] Pas de Releve.csv pour user={args.user} ({csv_path})")
        return 1

    print(f"\nLecture de {csv_path}")
    pin = getpass.getpass("PIN check-trade (pour decrypter) : ").strip()

    try:
        plain_csv = _decrypt_csv_bytes(csv_path.read_bytes(), pin)
    except ValueError as e:
        print(f"[ERR] {e}")
        return 2
    finally:
        del pin

    reader = csv.reader(StringIO(plain_csv), delimiter=";")
    rows = list(reader)
    if not rows:
        print("[!] CSV vide.")
        return 0

    # Retirer l'en-tete si present
    header = rows[0]
    if header[:1] == ["DATE"] or header == COLNAMES:
        data_rows = rows[1:]
    else:
        data_rows = rows

    print(f"  -> {len(data_rows)} lignes de donnees trouvees")

    # ---- Tri chronologique ----
    data_rows_sorted = sorted(data_rows, key=lambda r: date_key(r[0]) if r else (0, 0, 0))

    # ---- Export CSV en clair (avec solde courant calcule) ----
    debug_path = csv_path.parent / "Releve_debug.csv"
    running = 0.0
    monthly: dict[str, dict] = defaultdict(lambda: {"nb": 0, "in": 0.0, "out": 0.0, "balance_end": 0.0, "has_negative": False})

    with open(debug_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(COLNAMES + ["RUNNING_BALANCE", "ANOMALIE"])

        for row in data_rows_sorted:
            if len(row) < len(COLNAMES):
                row = list(row) + [""] * (len(COLNAMES) - len(row))

            in_amt = parse_amount(row[2])
            out_amt = parse_amount(row[3])
            running += in_amt - out_amt

            anomalie = []
            if running < -0.01:
                anomalie.append("NEGATIF")
            if in_amt > 0 and out_amt > 0:
                anomalie.append("IN+OUT")
            if in_amt == 0 and out_amt == 0:
                anomalie.append("SANS_MOUVEMENT")

            # Si la BALANCE csv est presente, se recaler dessus
            bal_csv = parse_amount(row[4]) if row[4].strip() else None
            if bal_csv is not None and abs(bal_csv - running) > 0.01:
                anomalie.append(f"BALANCE_ECART:{bal_csv - running:+.2f}")
                running = bal_csv  # recalage

            writer.writerow(row[:8] + [f"{running:.2f}", ";".join(anomalie)])

            # Stats mensuelles
            mkey = month_label(row[0])
            monthly[mkey]["nb"] += 1
            monthly[mkey]["in"] += in_amt
            monthly[mkey]["out"] += out_amt
            monthly[mkey]["balance_end"] = running
            if running < -0.01:
                monthly[mkey]["has_negative"] = True

    print(f"  -> Export en clair : {debug_path}")

    # ---- Export resume mensuel ----
    monthly_path = csv_path.parent / "Releve_monthly.csv"
    with open(monthly_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["MOIS", "NB_TRANSACTIONS", "TOTAL_IN", "TOTAL_OUT", "NET", "BALANCE_FIN_MOIS", "NEGATIF"])
        for mkey in sorted(monthly.keys()):
            m = monthly[mkey]
            net = m["in"] - m["out"]
            writer.writerow([
                mkey,
                m["nb"],
                f"{m['in']:.2f}",
                f"{m['out']:.2f}",
                f"{net:.2f}",
                f"{m['balance_end']:.2f}",
                "OUI" if m["has_negative"] else "",
            ])

    print(f"  -> Resume mensuel : {monthly_path}")

    # ---- Rapport console ----
    print(f"\n{'='*70}")
    print(f"  RESUME PAR MOIS")
    print(f"{'='*70}")
    print(f"  {'MOIS':<10} {'NB':>5} {'IN':>12} {'OUT':>12} {'NET':>12} {'BAL_FIN':>12} {'NEG':>5}")
    print(f"  {'-'*68}")
    neg_months = []
    for mkey in sorted(monthly.keys()):
        m = monthly[mkey]
        net = m["in"] - m["out"]
        neg_flag = "⚠" if m["has_negative"] else ""
        print(f"  {mkey:<10} {m['nb']:>5} {m['in']:>12.2f} {m['out']:>12.2f} {net:>12.2f} {m['balance_end']:>12.2f} {neg_flag:>5}")
        if m["has_negative"]:
            neg_months.append(mkey)

    print(f"\n  Total transactions : {len(data_rows_sorted)}")
    if neg_months:
        print(f"  ⚠ Mois en negatif : {', '.join(neg_months)}")
    else:
        print(f"  ✓ Aucun mois en negatif")

    print(f"\n  ATTENTION : {debug_path.name} et {monthly_path.name} ne sont PAS chiffres !")
    print(f"  Supprime-les apres analyse.\n")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INTERRUPT]", file=sys.stderr)
        sys.exit(130)
