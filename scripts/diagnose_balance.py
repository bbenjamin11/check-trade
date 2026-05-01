#!/usr/bin/env python3
"""
Diagnostic du solde Releve.csv.

But : detecter pourquoi le solde devient negatif (impossible sur TR sans decouvert)
ou pourquoi le solde net ne correspond pas a la realite.

Lance :
    python scripts/diagnose_balance.py --user ben

Le script :
1. Decrypt ton Releve.csv (PIN saisi en interactif, jamais stocke)
2. Trie les transactions par date
3. Calcule le solde courant (running balance) ligne par ligne
4. Detecte :
   - Les moments ou le solde devient negatif
   - Les divergences avec la colonne BALANCE quand elle est presente
   - Les doublons probables (meme date + meme montant + description proche)
   - Les lignes avec BALANCE manquante alors qu'on est apres un PDF
   - Les lignes avec MONEY IN ET MONEY OUT (incoherent)
   - Les lignes avec ni IN ni OUT mais balance change

Aucune donnee ne sort du script (rapport en console).
"""

from __future__ import annotations

import argparse
import csv
import getpass
import re
import sys
from io import StringIO
from pathlib import Path

# UTF-8 stdout pour eviter UnicodeEncodeError sous Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Import depuis controllers/app.py pour reutiliser exactement la meme crypto
from controllers.app import _decrypt_csv_bytes, _releve_path

COLNAMES = [
    "DATE", "TYPE", "MONEY IN", "MONEY OUT",
    "BALANCE", "DESCRIPTION", "MERCHANT", "CATEGORY",
]

MONTH_ORDER = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_amount(s: str) -> float:
    """Parse '€1.234,56' ou '€1,23' ou '' -> float (0 si vide)."""
    if not s or not s.strip():
        return 0.0
    s = s.strip().replace("€", "").replace(" ", "")
    # Cas FR : '1.234,56' (point millier, virgule decimale)
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return 0.0


def date_key(date_str: str) -> tuple:
    """'5 Apr 2026' -> (2026, 4, 5). Retourne (0,0,0) si parse echoue."""
    parts = date_str.strip().split()
    if len(parts) >= 3:
        try:
            return (int(parts[2]), MONTH_ORDER.get(parts[1], 0), int(parts[0]))
        except ValueError:
            pass
    return (0, 0, 0)


def short(s: str, n: int = 50) -> str:
    """Tronque une string pour l'affichage."""
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def fmt_eur(amt: float) -> str:
    return f"{amt:>+12.2f}€"


def diagnose(rows: list[list[str]]) -> None:
    """Analyse les lignes et imprime le rapport."""
    if not rows:
        print("[!] CSV vide.")
        return

    # Tri chronologique
    rows = sorted(rows, key=lambda r: date_key(r[0]) if r else (0, 0, 0))

    print(f"\n{'='*90}")
    print(f"  DIAGNOSTIC — {len(rows)} transaction(s)")
    print(f"{'='*90}\n")

    running = 0.0
    first_negative = None
    negative_dips = []
    balance_mismatches = []
    in_and_out = []
    no_movement = []
    by_date_amount: dict = {}
    duplicates_suspect = []

    for i, row in enumerate(rows, 1):
        if len(row) < len(COLNAMES):
            row = list(row) + [""] * (len(COLNAMES) - len(row))
        date, ty, mi, mo, bal, desc, merchant, cat = row[:8]

        in_amt = parse_amount(mi)
        out_amt = parse_amount(mo)
        bal_amt = parse_amount(bal) if bal.strip() else None

        # Anomalie : IN ET OUT sur la meme ligne
        if in_amt > 0 and out_amt > 0:
            in_and_out.append((i, row))

        # Anomalie : ni IN ni OUT
        if in_amt == 0 and out_amt == 0:
            no_movement.append((i, row))

        # Mise a jour du running balance
        running += in_amt - out_amt

        # Premier negatif ?
        if first_negative is None and running < 0:
            first_negative = (i, running, row)

        # Tous les passages en negatif
        if running < 0:
            negative_dips.append((i, running, row))

        # Divergence avec la BALANCE declaree
        if bal_amt is not None:
            delta = bal_amt - running
            if abs(delta) > 0.01:  # tolerance 1 centime
                balance_mismatches.append((i, running, bal_amt, delta, row))
            else:
                # On peut resynchroniser sur la BALANCE declaree (au cas ou il y aurait
                # eu un event manquant en amont)
                running = bal_amt

        # Detection doublons : meme date + meme montant
        key = (date, in_amt, out_amt)
        if key in by_date_amount:
            duplicates_suspect.append((by_date_amount[key], (i, row)))
        else:
            by_date_amount[key] = (i, row)

    # ---- RAPPORT ----

    if first_negative:
        i, run, row = first_negative
        print(f"⚠  PREMIER PASSAGE EN NEGATIF a la ligne #{i}")
        print(f"   Date : {row[0]}  |  Type : {row[1]}")
        print(f"   IN={row[2] or '-'}  OUT={row[3] or '-'}  BALANCE_csv={row[4] or '-'}")
        print(f"   Solde calcule apres cette ligne : {fmt_eur(run)}")
        print(f"   Description : {short(row[5], 70)}")
        print()
        print(f"   Contexte (20 lignes avant) :")
        start = max(0, i - 21)
        ctx_running = 0.0
        for j in range(start):
            r = rows[j]
            ctx_running += parse_amount(r[2]) - parse_amount(r[3])
            ctx_bal = parse_amount(r[4]) if r[4].strip() else None
            if ctx_bal is not None and abs(ctx_bal - ctx_running) > 0.01:
                ctx_running = ctx_bal
        for j in range(start, i):
            r = rows[j]
            in_a = parse_amount(r[2])
            out_a = parse_amount(r[3])
            ctx_running += in_a - out_a
            csv_bal = parse_amount(r[4]) if r[4].strip() else None
            sync_flag = ""
            if csv_bal is not None:
                if abs(csv_bal - ctx_running) > 0.01:
                    sync_flag = f"  ⚠ csv_bal={csv_bal:+.2f} computed={ctx_running:+.2f}"
                ctx_running = csv_bal
            print(f"   #{j+1:4d} {r[0]:>12s} | {r[1]:<14s} | "
                  f"IN={r[2]:>8s} OUT={r[3]:>8s} | "
                  f"running={ctx_running:>+10.2f}{sync_flag} | {short(r[5], 35)}")
        print()
    else:
        print("✓  Aucun passage en negatif detecte.\n")

    if negative_dips:
        print(f"⚠  {len(negative_dips)} ligne(s) au total avec solde negatif "
              f"(jusqu'a {min(d[1] for d in negative_dips):+.2f}€)\n")

    if balance_mismatches:
        print(f"⚠  {len(balance_mismatches)} divergence(s) entre solde calcule et BALANCE csv :")
        for i, run, bal, delta, row in balance_mismatches[:10]:
            print(f"   #{i:4d} {row[0]:>12s} | {row[1]:<14s} | "
                  f"calcule={run:+.2f} csv={bal:+.2f} delta={delta:+.2f}€ "
                  f"| {short(row[5], 30)}")
        if len(balance_mismatches) > 10:
            print(f"   ... et {len(balance_mismatches) - 10} autre(s)")
        print()

    if in_and_out:
        print(f"⚠  {len(in_and_out)} ligne(s) avec MONEY IN ET MONEY OUT remplis (incoherent) :")
        for i, row in in_and_out[:5]:
            print(f"   #{i} {row[0]} | {row[1]} | IN={row[2]} OUT={row[3]} | {short(row[5], 30)}")
        print()

    if no_movement:
        print(f"ℹ  {len(no_movement)} ligne(s) sans mouvement (ni IN ni OUT) — "
              f"normal pour des splits/info, suspect sinon")
        for i, row in no_movement[:3]:
            print(f"   #{i} {row[0]} | {row[1]} | {short(row[5], 50)}")
        if len(no_movement) > 3:
            print(f"   ... et {len(no_movement) - 3} autre(s)")
        print()

    if duplicates_suspect:
        print(f"⚠  {len(duplicates_suspect)} doublon(s) potentiel(s) "
              f"(meme date + meme montant) :")
        for (i1, r1), (i2, r2) in duplicates_suspect[:8]:
            print(f"   • {r1[0]} | IN={r1[2]} OUT={r1[3]}")
            print(f"     #{i1} type={r1[1]:<14s} | {short(r1[5], 60)}")
            print(f"     #{i2} type={r2[1]:<14s} | {short(r2[5], 60)}")
            sim = "(meme description ?)" if r1[5].strip() == r2[5].strip() else "(descriptions differentes)"
            print(f"     {sim}")
            print()
        if len(duplicates_suspect) > 8:
            print(f"   ... et {len(duplicates_suspect) - 8} autre(s)")
        print()

    # Resume final
    final_running = running
    last_csv_bal = None
    for r in reversed(rows):
        if r[4].strip():
            last_csv_bal = parse_amount(r[4])
            break

    print(f"{'='*90}")
    print(f"  SOLDE CALCULE FINAL : {fmt_eur(final_running)}")
    if last_csv_bal is not None:
        print(f"  DERNIERE BALANCE csv : {fmt_eur(last_csv_bal)}")
        delta = last_csv_bal - final_running
        if abs(delta) > 0.01:
            print(f"  ⚠ ECART : {fmt_eur(delta)}  "
                  f"(il manque ce montant en MONEY IN, ou il y a ce surplus en MONEY OUT)")
        else:
            print(f"  ✓ Coherent.")
    print(f"{'='*90}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--user", default="ben", help="Username (defaut: ben)")
    args = parser.parse_args()

    csv_path = _releve_path(args.user)
    if not csv_path.exists():
        print(f"[ERR] Pas de Releve.csv pour user={args.user} ({csv_path})")
        return 1

    print(f"\nLecture de {csv_path.relative_to(ROOT)}")
    pin = getpass.getpass("PIN check-trade (pour decrypter le CSV) : ").strip()

    try:
        plain_csv = _decrypt_csv_bytes(csv_path.read_bytes(), pin)
    except ValueError as e:
        print(f"[ERR] {e}")
        return 2
    finally:
        del pin  # best effort

    reader = csv.reader(StringIO(plain_csv), delimiter=";")
    rows = list(reader)
    if not rows:
        print("[!] CSV vide.")
        return 0
    if rows[0][:1] == ["DATE"] or rows[0] == COLNAMES:
        rows = rows[1:]

    diagnose(rows)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INTERRUPT]", file=sys.stderr)
        sys.exit(130)
