#!/usr/bin/env python3
"""
Parseur PDF Trade Republic - Implémentation spécialisée pour les relevés Trade Republic
"""

import re
from pathlib import Path
from typing import List, Tuple, Dict
from dataclasses import dataclass
import pdfplumber
from .base_parser import Parser

#  Zones X réelles 
X_DAY       = (70,   96)
X_MONTH     = (84,  102)
X_TYPE      = (100, 146)
X_DESC      = (146, 409)
X_MONEY_IN  = (405, 443)
X_MONEY_OUT = (441, 482)
X_BALANCE   = (482, 525)
X_YEAR      = (70,   96)

RE_AMOUNT = re.compile(r"^€[\d,.]+$")
RE_DAY    = re.compile(r"^\d{1,2}$")
RE_MONTH  = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$", re.I)
RE_YEAR   = re.compile(r"^20\d{2}$")

CREDIT_TYPES = frozenset([
    "interest", "deposit", "earnings", "saveback", "refund",
    "reward", "income", "dividend",
])

SKIP_Y_MAX        = 160
SKIP_Y_MIN_FOOTER = 750

#  Nouvelles colonnes 
COLNAMES = [
    "DATE", "TYPE", "MONEY IN", "MONEY OUT",
    "BALANCE", "DESCRIPTION", "MERCHANT", "CATEGORY",
]




class PDFTradeRepublicParser(Parser):
    """Parseur pour les fichiers PDF de Trade Republic avec toutes les fonctionnalités."""
    
    def extract_csv(self, file_path: Path) -> List[List[str]]:
        """Extrait les données d'un fichier PDF de Trade Republic et les retourne sous forme de liste de listes."""
        return self._extraire_transactions(file_path, debug=False)


    def _in_zone(self, x: float, zone: Tuple[int, int]) -> bool:
        """Vérifie si x est dans la zone donnée."""
        return zone[0] <= x < zone[1]

    @dataclass
    class Transaction:
        """Dataclass pour les transactions."""
        day:       str = ""
        month:     str = ""
        year:      str = ""
        type_:     str = ""
        desc:      str = ""
        money_in:  str = ""
        money_out: str = ""
        balance:   str = ""

        def has_date(self) -> bool:
            return bool(self.day and self.month)

        def complet(self) -> bool:
            return bool(self.day and self.month and self.year and self.balance)

    def _is_credit(self, transaction) -> bool:
        """Détermine si une transaction est un crédit."""
        type_low = transaction.type_.lower()
        desc_low = transaction.desc.lower()
        if any(k in type_low for k in CREDIT_TYPES):
            return True
        if "transfer" in type_low:
            return any(k in desc_low for k in ["deposit", "top", "inpayed", "direct debit"])
        return False

    def _extraire_transactions(self, chemin_pdf: Path, debug: bool = False) -> List[List[str]]:
        """Extrait les transactions du PDF avec toute la logique de classification."""
        def dbg(msg: str) -> None:
            if debug:
                print(msg)

        transactions: List[List[str]] = []
        buf = self.Transaction()
        pending_amount: str = ""
        pending_is_out: bool = False

        def flush(raison: str = "") -> None:
            nonlocal pending_amount, pending_is_out
            if not buf.complet():
                dbg(f"  [SKIP-INCOMPLET raison={raison}] {buf}")
                buf.__init__()  # Reset
                pending_amount = ""
                return
            if pending_amount:
                if pending_is_out:
                    buf.money_out = pending_amount
                else:
                    buf.money_in = pending_amount
            if not buf.money_in and not buf.money_out and buf.balance:
                if self._is_credit(buf):
                    buf.money_in = pending_amount
                else:
                    buf.money_out = pending_amount
            
            # Création de la ligne avec classification
            date = f"{buf.day} {buf.month} {buf.year}".strip()
            desc = buf.desc.strip()
            merchant = self._normalize_merchant(desc)
            category = self._categorize(merchant, desc, buf.type_, None)
            
            ligne = [
                date, buf.type_, buf.money_in, buf.money_out,
                buf.balance, desc, merchant, category,
            ]
            transactions.append(ligne)
            dbg(f"  [FLUSH {raison}] {ligne}")
            buf.__init__()  # Reset
            pending_amount = ""
            pending_is_out = False

        with pdfplumber.open(chemin_pdf) as pdf:
            for num_page, page in enumerate(pdf.pages, start=1):
                dbg(f"\n{'='*50} PAGE {num_page}")
                words = page.extract_words()

                lignes_y: Dict[float, List[dict]] = {}
                for w in words:
                    y = round(w["top"], 1)
                    y_key = next((k for k in lignes_y if abs(k - y) <= 2), y)
                    lignes_y.setdefault(y_key, []).append(w)

                for y_key in sorted(lignes_y.keys()):
                    if num_page == 1 and y_key < SKIP_Y_MAX:
                        continue
                    if y_key > SKIP_Y_MIN_FOOTER:
                        continue

                    mots = sorted(lignes_y[y_key], key=lambda w: w["x0"])
                    dbg(f"\n  [Y={y_key:.1f}] " +
                        " | ".join(f"{w['text']}@{w['x0']:.0f}" for w in mots))

                    for w in mots:
                        x   = w["x0"]
                        txt = w["text"]

                        if RE_YEAR.match(txt) and self._in_zone(x, X_YEAR):
                            if buf.has_date() and not buf.year:
                                buf.year = txt
                                flush("YEAR")
                            continue
                        if RE_DAY.match(txt) and self._in_zone(x, X_DAY):
                            buf.day = txt
                            continue
                        if RE_MONTH.match(txt) and self._in_zone(x, X_DAY):
                            buf.month = txt
                            continue
                        if self._in_zone(x, X_TYPE):
                            buf.type_ = (buf.type_ + " " + txt).strip()
                            continue
                        if self._in_zone(x, X_MONEY_IN) and RE_AMOUNT.match(txt):
                            buf.money_in = txt
                            continue
                        if self._in_zone(x, X_MONEY_OUT) and RE_AMOUNT.match(txt):
                            buf.money_out = txt
                            continue
                        if self._in_zone(x, X_BALANCE) and RE_AMOUNT.match(txt):
                            buf.balance = txt
                            continue
                        if self._in_zone(x, X_DESC) or x >= 146:
                            buf.desc = (buf.desc + " " + txt).strip()
                            continue

        if buf.has_date():
            if not buf.year:
                buf.year = "2026"
            flush("EOF")

        print(f"{len(transactions)} transactions extraites")
        return transactions