#!/usr/bin/env python3
"""
Extraction Trade Republic PDF → CSV.
Ajoute deux colonnes : MERCHANT (marchand normalisé) et CATEGORY (catégorie métier).
"""

from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pdfplumber

# ── Zones X réelles ───────────────────────────────────────────────────────────
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

# ── Nouvelles colonnes ────────────────────────────────────────────────────────
COLNAMES = [
    "DATE", "TYPE", "MONEY IN", "MONEY OUT",
    "BALANCE", "DESCRIPTION", "MERCHANT", "CATEGORY",
]

# ══════════════════════════════════════════════════════════════════════════════
#  NORMALISATION MARCHAND
#  Chaque règle : (regex, nom_normalisé)
#  Ordre important : du plus spécifique au plus général
# ══════════════════════════════════════════════════════════════════════════════
_MERCHANT_RULES: list[tuple[re.Pattern, str]] = [
    # ── Bruit Trade Republic ──────────────────────────────────────────────────
    # (nettoyé avant matching, voir normalize_desc())

    # ── Grande distribution ───────────────────────────────────────────────────
    (re.compile(r"carrefour",           re.I), "Carrefour"),
    (re.compile(r"intermarche|intermarché", re.I), "Intermarché"),
    (re.compile(r"delhaize",            re.I), "Delhaize"),
    (re.compile(r"lidl",                re.I), "Lidl"),
    (re.compile(r"colruyt",             re.I), "Colruyt"),
    (re.compile(r"aldi",                re.I), "Aldi"),

    # ── Amazon (toutes variantes) ─────────────────────────────────────────────
    (re.compile(r"amazon|amzn\s*mktp|amazon\.fr|amazon\.com", re.I), "Amazon"),

    # ── Restauration rapide ───────────────────────────────────────────────────
    (re.compile(r"quick\b",             re.I), "Quick"),
    (re.compile(r"burger\s*king",       re.I), "Burger King"),
    (re.compile(r"mc\s*donald|mac\s*donald", re.I), "McDonald's"),
    (re.compile(r"kfc\b",               re.I), "KFC"),
    (re.compile(r"pizza\s*hut",         re.I), "Pizza Hut"),
    (re.compile(r"lunch\s*garden",      re.I), "Lunch Garden"),
    (re.compile(r"frit.?house",         re.I), "Frit'House"),

    # ── Boulangeries ─────────────────────────────────────────────────────────
    (re.compile(r"boulangerie\s+louise",re.I), "Boulangerie Louise"),
    (re.compile(r"boulangerie\s+gozee", re.I), "Boulangerie Gozée"),
    (re.compile(r"boulangerie\s+heind", re.I), "Boulangerie Heindrichs"),

    # ── Bricolage ────────────────────────────────────────────────────────────
    (re.compile(r"brico\b",             re.I), "Brico"),
    (re.compile(r"leroy\s*merlin",      re.I), "Leroy Merlin"),

    # ── Sport ────────────────────────────────────────────────────────────────
    (re.compile(r"decathlon",           re.I), "Decathlon"),
    (re.compile(r"go\s*sport",          re.I), "Go Sport"),

    # ── Mode / Textile ────────────────────────────────────────────────────────
    (re.compile(r"jules\b",             re.I), "Jules"),
    (re.compile(r"orchestra\b",         re.I), "Orchestra"),
    (re.compile(r"veritas\b",           re.I), "Veritas"),
    (re.compile(r"north\s*face",        re.I), "The North Face"),
    (re.compile(r"c\s*&\s*a\b",         re.I), "C&A"),
    (re.compile(r"vinted\b",            re.I), "Vinted"),

    # ── Maison / Déco ────────────────────────────────────────────────────────
    (re.compile(r"ikea",                re.I), "IKEA"),
    (re.compile(r"action\b",            re.I), "Action"),
    (re.compile(r"back\s*market",       re.I), "Back Market"),
    (re.compile(r"jysk\b",              re.I), "JYSK"),

    # ── Santé ────────────────────────────────────────────────────────────────
    (re.compile(r"pharmacie\s+triffaux",re.I), "Pharmacie Triffaux"),
    (re.compile(r"pharmacie\s+briclet", re.I), "Pharmacie Briclet"),
    (re.compile(r"pharmacie",           re.I), "Pharmacie"),
    (re.compile(r"medi.?market",        re.I), "Medi-Market"),
    (re.compile(r"ghdc|hpb\s+mons",     re.I), "Hôpital (GHdC/HPB)"),
    (re.compile(r"bkb\s+dental",        re.I), "BKB Dental"),
    (re.compile(r"cabinet\s+veterin|vetov", re.I), "Vétérinaire"),
    (re.compile(r"centre\s+de\s+guidance", re.I), "Centre de Guidance"),
    (re.compile(r"medi.?market\s+pharmacie", re.I), "Medi-Market Pharmacie"),
    (re.compile(r"pay[* ]*point\s+de\s+mire\s+du\s+b", re.I), "Point de Mire du B"),

    # ── Loisirs / Culture ────────────────────────────────────────────────────
    (re.compile(r"pairi\s+daiza",       re.I), "Pairi Daiza"),
    (re.compile(r"vayamundo",           re.I), "Vayamundo"),
    (re.compile(r"zevent",              re.I), "ZEvent"),
    (re.compile(r"king\s+jouet",        re.I), "King Jouet"),
    (re.compile(r"bd\s+world",          re.I), "BD World"),
    (re.compile(r"neuhaus",             re.I), "Neuhaus"),

    # ── Restaurants / Bars ───────────────────────────────────────────────────
    (re.compile(r"bocca\s+felice",      re.I), "La Bocca Felice"),
    (re.compile(r"glacier\s+devilers",  re.I), "Glacier Devilers"),
    (re.compile(r"pizza\s+del\s+tiglio",re.I), "Pizza Del Tiglio"),
    (re.compile(r"delirium\s+cafe",     re.I), "Delirium Café"),
    (re.compile(r"temple\s+d.?l.?biere",re.I), "Temple de la Bière"),
    (re.compile(r"brasse.?temps",       re.I), "Brasse-Temps"),
    (re.compile(r"cafe\s+des\s+sports", re.I), "Café des Sports"),
    (re.compile(r"poke\s+bulles",       re.I), "Poké Bulles"),
    (re.compile(r"snack\s+sultan",      re.I), "Snack Sultan"),
    (re.compile(r"ls\s+tasty",          re.I), "LS Tasty"),
    (re.compile(r"oil\s*&\s*vinegar",   re.I), "Oil & Vinegar"),
    (re.compile(r"luxus\s+couillet",    re.I), "Luxus Couillet"),
    (re.compile(r"asie\s+a\s+tik",      re.I), "Asie à Tik"),

    # ── Streaming / IA / Abonnements ────────────────────────────────────────
    (re.compile(r"mistral\.ai",         re.I), "Mistral.AI"),
    (re.compile(r"netflix",             re.I), "Netflix"),
    (re.compile(r"spotify",             re.I), "Spotify"),
    (re.compile(r"youtube|google\s+youtube", re.I), "YouTube Premium"),
    (re.compile(r"disney",              re.I), "Disney+"),
    (re.compile(r"apple",               re.I), "Apple"),
    (re.compile(r"mammouth",            re.I), "Mammouth"),
    (re.compile(r"shcmsm",              re.I), "SHCMSM"),
    (re.compile(r"cofeo",               re.I), "Cofeo Services"),

    # ── Transport / Mobilité ─────────────────────────────────────────────────
    (re.compile(r"ryanair",             re.I), "Ryanair"),
    (re.compile(r"charleroi\s+terminal|bsca", re.I), "BSCA (Aéroport Charleroi)"),
    (re.compile(r"texaco",              re.I), "Texaco"),
    (re.compile(r"shell\b",             re.I), "Shell"),
    (re.compile(r"q8\b",                re.I), "Q8"),
    (re.compile(r"autoroutes?\s+asf",   re.I), "Autoroutes ASF"),
    (re.compile(r"parking\s+reep",      re.I), "Parking REEP"),
    (re.compile(r"ghdc\s+bornes\s+parking", re.I), "GHdC Parking"),
    (re.compile(r"charleroi\s+p2a",     re.I), "Parking Charleroi P2A"),
    (re.compile(r"mondial\s+car",       re.I), "Mondial Car"),

    # ── Investissement ───────────────────────────────────────────────────────
    (re.compile(r"savings plan.*?FR0000073272", re.I), "Savings Plan — SAFRAN"),
    (re.compile(r"savings plan.*?IE00B4L5Y983", re.I), "Savings Plan — iShares MSCI World"),
    (re.compile(r"savings plan.*?US67066G1040", re.I), "Savings Plan — NVIDIA"),
    (re.compile(r"savings plan.*?FR0000120271", re.I), "Savings Plan — TotalEnergies"),
    (re.compile(r"savings plan.*?FR0000121972", re.I), "Savings Plan — Schneider Electric"),
    (re.compile(r"savings plan",         re.I), "Savings Plan — Autre"),
    (re.compile(r"execution trade|direct purchase", re.I), "Achat Titre Direct"),
    (re.compile(r"private markets",      re.I), "Private Markets"),

    # ── Divers / Transferts ──────────────────────────────────────────────────
    (re.compile(r"payout to transit",    re.I), "PayOut Transit"),
    (re.compile(r"cash\s+reward|saveback", re.I), "Saveback / Reward"),
    (re.compile(r"vrbo",                 re.I), "VRBO (Location vacances)"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  CATÉGORISATION (cathegorie.json : known_merchants + priority_order + mots-clés)
# ══════════════════════════════════════════════════════════════════════════════
_CAT_CONFIG: dict | None = None

DATA_DIR = Path(__file__).resolve().parent / "data"
CAT_FILE = DATA_DIR / "cathegorie.json"
DEFAULT_PDF = Path(__file__).resolve().parent / "Relevé de compte trade republic 04_2023 - 04_2026.pdf"
DEFAULT_CSV = DATA_DIR / "Releve.csv"

def reload_category_config() -> None:
    """Invalide le cache après modification de cathegorie.json."""
    global _CAT_CONFIG
    _CAT_CONFIG = None


def _get_category_config() -> dict:
    global _CAT_CONFIG
    if _CAT_CONFIG is None:
        if not CAT_FILE.is_file():
            raise FileNotFoundError(f"Fichier catégories introuvable : {CAT_FILE}")
        with open(CAT_FILE, encoding="utf-8") as f:
            _CAT_CONFIG = json.load(f)
    return _CAT_CONFIG


def load_categories_json() -> dict:
    """Lit cathegorie.json sans passer par le cache (pour écriture fusionnée)."""
    with open(CAT_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_categories_json(data: dict) -> None:
    with open(CAT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def add_known_merchant_category(merchant: str, category_name: str) -> None:
    """
    Ajoute ou met à jour known_merchants (clé = marchand en MAJUSCULES).
    Valide que la catégorie existe dans categories.
    """
    data = load_categories_json()
    if category_name not in data["categories"]:
        raise ValueError(f"Catégorie inconnue : {category_name!r}")
    key = merchant.strip().upper()
    if not key:
        raise ValueError("Marchand vide")
    data["known_merchants"][key] = category_name
    save_categories_json(data)
    reload_category_config()


def reparse_pdf_to_releve(
    pdf_path: Path | None = None,
    csv_path: Path | None = None,
) -> tuple[int, Path]:
    """Ré-extrait le PDF et réécrit Releve.csv (chemins par défaut = ./data)."""
    pdf = pdf_path or DEFAULT_PDF
    out = csv_path or DEFAULT_CSV
    if not pdf.is_file():
        raise FileNotFoundError(f"PDF introuvable : {pdf}")
    transactions = extraire_transactions(pdf, debug=False)
    # Crée le dossier data si nécessaire
    out.parent.mkdir(parents=True, exist_ok=True)
    ecrire_csv(transactions, out)
    return len(transactions), out


def _known_merchant_match(merchant_upper: str, key: str) -> bool:
    """Correspondance marchand connu (clés courtes = égalité stricte)."""
    ku = key.upper().strip()
    if not ku:
        return False
    m = merchant_upper.strip()
    if m == ku:
        return True
    if len(ku) <= 3:
        return False
    return ku in m or m in ku


def categorize(merchant: str, raw_desc: str, type_: str) -> str:
    """
    Catégorise via cathegorie.json : known_merchants (priorité),
    puis categories dans priority_order (mots-clés + marchands par catégorie).
    """
    cfg = _get_category_config()
    cats = cfg["categories"]
    known = cfg["known_merchants"]
    order = cfg["priority_order"]
    default = next(
        (n for n in order if n in cats and n.startswith("❓")),
        "❓ Divers",
    )

    desc = _clean_raw(raw_desc)
    haystack = f"{type_} {desc} {merchant}".lower()
    merch_u = merchant.upper().strip()

    for key in sorted(known.keys(), key=len, reverse=True):
        if _known_merchant_match(merch_u, key):
            return known[key]

    for name in order:
        if name == "known_merchants" or name not in cats:
            continue
        entry = cats[name]
        for kw in entry.get("keywords", []):
            if kw.lower() in haystack:
                return name
        for mer in entry.get("merchants", []):
            mu = mer.upper().strip()
            if not mu:
                continue
            if mu in merch_u or merch_u in mu or mu.lower() in haystack:
                return name

    type_low = type_.lower()
    if any(k in type_low for k in ("interest", "dividend", "earnings", "saveback")):
        bank = "🏦 Banque / Finance / Investissement"
        if bank in cats:
            return bank
    if "transfer" in type_low:
        bank = "🏦 Banque / Finance / Investissement"
        if bank in cats:
            return bank
    if "trade" in type_low:
        bank = "🏦 Banque / Finance / Investissement"
        if bank in cats:
            return bank
    return default


def _clean_raw(raw: str) -> str:
    """Nettoyage du bruit avant toute normalisation."""
    s = raw
    # Préfixe parasite "BRUNNENSTRASSE 19-21 10119 BERLIN DESCRIPTION MONEY IN MONEY OUT BALANCE"
    s = re.sub(
        r"BRUNNENSTRASSE\s+\S+\s+\S+\s+BERLIN\s+DESCRIPTION\s+"
        r"MONEY\s+IN\s+MONEY\s+OUT\s+BALANCE\s*",
        "", s, flags=re.I,
    )
    # Quantités trading en début "0.123456 "
    s = re.sub(r"^\d+\.\d{4,}\s+", "", s)
    # Suffixe "null"
    s = re.sub(r"null$", "", s, flags=re.I)
    # Références commande Amazon "*XXXXXXXX"
    s = re.sub(r"\*[A-Z0-9]{6,12}\d?$", "", s)
    return s.strip()


def normalize_merchant(raw_desc: str) -> str:
    """
    Retourne le nom du marchand normalisé.
    Conserve la description originale en fallback.
    """
    s = _clean_raw(raw_desc)
    for pattern, merchant in _MERCHANT_RULES:
        if pattern.search(s):
            return merchant
    # Fallback : nettoyage cosmétique (supprime codes/IDs résiduels)
    s = re.sub(r"\s+[A-Z0-9]{8,}$", "", s)
    s = re.sub(r"\s+\d{3,}$", "", s).strip()
    return s or "—"


# ══════════════════════════════════════════════════════════════════════════════
#  DATACLASS TRANSACTION (inchangée sauf vers_ligne)
# ══════════════════════════════════════════════════════════════════════════════

def in_zone(x: float, zone: tuple[int, int]) -> bool:
    return zone[0] <= x < zone[1]


@dataclass
class Transaction:
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

    def vers_ligne(self) -> list[str]:
        date     = f"{self.day} {self.month} {self.year}".strip()
        desc     = self.desc.strip()
        merchant = normalize_merchant(desc)
        category = categorize(merchant, desc, self.type_)
        return [
            date, self.type_, self.money_in, self.money_out,
            self.balance, desc, merchant, category,
        ]

    def reset(self) -> None:
        self.__init__()  # type: ignore


def is_credit(t: Transaction) -> bool:
    type_low = t.type_.lower()
    desc_low = t.desc.lower()
    if any(k in type_low for k in CREDIT_TYPES):
        return True
    if "transfer" in type_low:
        return any(k in desc_low for k in ["deposit", "top", "inpayed", "direct debit"])
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  EXTRACTION (identique à l'original)
# ══════════════════════════════════════════════════════════════════════════════

def extraire_transactions(chemin_pdf: Path, debug: bool = False) -> list[list[str]]:
    def dbg(msg: str) -> None:
        if debug:
            print(msg)

    transactions: list[list[str]] = []
    buf = Transaction()
    pending_amount: str = ""
    pending_is_out: bool = False

    def flush(raison: str = "") -> None:
        nonlocal pending_amount, pending_is_out
        if not buf.complet():
            dbg(f"  [SKIP-INCOMPLET raison={raison}] {buf}")
            buf.reset()
            pending_amount = ""
            return
        if pending_amount:
            if pending_is_out:
                buf.money_out = pending_amount
            else:
                buf.money_in = pending_amount
        if not buf.money_in and not buf.money_out and buf.balance:
            if is_credit(buf):
                buf.money_in = pending_amount
            else:
                buf.money_out = pending_amount
        transactions.append(buf.vers_ligne())
        dbg(f"  [FLUSH {raison}] {buf.vers_ligne()}")
        buf.reset()
        pending_amount = ""
        pending_is_out = False

    with pdfplumber.open(chemin_pdf) as pdf:
        for num_page, page in enumerate(pdf.pages, start=1):
            dbg(f"\n{'='*50} PAGE {num_page}")
            words = page.extract_words()

            lignes_y: dict[float, list[dict]] = {}
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

                    if RE_YEAR.match(txt) and in_zone(x, X_YEAR):
                        if buf.has_date() and not buf.year:
                            buf.year = txt
                            flush("YEAR")
                        continue
                    if RE_DAY.match(txt) and in_zone(x, X_DAY):
                        buf.day = txt
                        continue
                    if RE_MONTH.match(txt) and in_zone(x, X_DAY):
                        buf.month = txt
                        continue
                    if in_zone(x, X_TYPE):
                        buf.type_ = (buf.type_ + " " + txt).strip()
                        continue
                    if in_zone(x, X_MONEY_IN) and RE_AMOUNT.match(txt):
                        buf.money_in = txt
                        continue
                    if in_zone(x, X_MONEY_OUT) and RE_AMOUNT.match(txt):
                        buf.money_out = txt
                        continue
                    if in_zone(x, X_BALANCE) and RE_AMOUNT.match(txt):
                        buf.balance = txt
                        continue
                    if in_zone(x, X_DESC) or x >= 146:
                        buf.desc = (buf.desc + " " + txt).strip()
                        continue

    if buf.has_date():
        if not buf.year:
            buf.year = "2026"
        flush("EOF")

    print(f"✅  {len(transactions)} transactions extraites")
    return transactions


def ecrire_csv(transactions: list[list[str]], chemin_csv: Path) -> None:
    # Crée le dossier cible si besoin (ie ./data)
    chemin_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(chemin_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(COLNAMES)
        writer.writerows(transactions)
    print(f"✅  CSV : {chemin_csv}")


_MONTH_ORDER = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _normalize_row_width(row: list[str], width: int = len(COLNAMES)) -> list[str]:
    r = list(row) + [""] * width
    return r[:width]


def _transaction_dedup_key(row: list[str]) -> tuple[str, str, str, str, str]:
    """Clé sans solde ni marchand/catégorie (réimport PDF / CSV hétérogènes)."""
    r = _normalize_row_width(row)
    return (
        r[0].strip().lower(),
        r[1].strip().lower(),
        r[2].strip(),
        r[3].strip(),
        r[5].strip().lower(),
    )


def _date_sort_key(row: list[str]) -> tuple[int, int, int]:
    parts = row[0].strip().split()
    if len(parts) >= 3:
        try:
            d, mon, y = int(parts[0]), _MONTH_ORDER.get(parts[1], 0), int(parts[2])
            return (y, mon, d)
        except ValueError:
            pass
    return (0, 0, 0)


def lire_releve_csv(chemin_csv: Path) -> list[list[str]]:
    """Lit Releve.csv existant (sans ligne d'en-tête dans le résultat)."""
    if not chemin_csv.is_file():
        return []
    with open(chemin_csv, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f, delimiter=";")
        rows = list(reader)
    if not rows:
        return []
    hdr = [c.strip() for c in rows[0]]
    if hdr == COLNAMES:
        body = rows[1:]
    else:
        body = rows
    return [r for r in body if any((c or "").strip() for c in r)]


def fusionner_pdf_dans_releve(
    pdf_path: Path,
    csv_path: Path | None = None,
) -> dict[str, int]:
    """
    Extrait le PDF, fusionne avec Releve.csv sans doublons, réécrit le CSV trié par date.
    Doublon = même (date, type, entrée, sortie, description) — insensible à la casse.
    """
    out = csv_path or DEFAULT_CSV
    nouvelles = extraire_transactions(pdf_path, debug=False)
    existantes = [_normalize_row_width(r) for r in lire_releve_csv(out)]

    seen: set[tuple[str, str, str, str, str]] = {
        _transaction_dedup_key(r) for r in existantes
    }
    added = 0
    skipped = 0
    for r in nouvelles:
        r = _normalize_row_width(r)
        k = _transaction_dedup_key(r)
        if k in seen:
            skipped += 1
            continue
        seen.add(k)
        existantes.append(r)
        added += 1

    existantes.sort(key=_date_sort_key)
    ecrire_csv(existantes, out)
    return {"added": added, "skipped": skipped, "total": len(existantes)}


def reappliquer_categories_csv(chemin_csv: Path | None = None) -> int:
    """
    Recalcule MERCHANT et CATEGORY pour chaque ligne à partir de DESCRIPTION et TYPE
    (sans repasser par le PDF — préserve les fusions multi-PDF).
    """
    path = chemin_csv or DEFAULT_CSV
    rows = lire_releve_csv(path)
    if not rows:
        return 0
    out_rows: list[list[str]] = []
    for r in rows:
        r = _normalize_row_width(r)
        desc = r[5]
        typ = r[1]
        merchant = normalize_merchant(desc)
        category = categorize(merchant, desc, typ)
        r[6] = merchant
        r[7] = category
        out_rows.append(r)
    out_rows.sort(key=_date_sort_key)
    ecrire_csv(out_rows, path)
    return len(out_rows)


def main() -> None:
    chemin_pdf = Path("./Relevé de compte trade republic 04_2023 - 04_2026.pdf")
    chemin_csv = DEFAULT_CSV

    if not chemin_pdf.exists():
        print(f"❌  {chemin_pdf} introuvable")
        sys.exit(1)

    transactions = extraire_transactions(chemin_pdf, debug=False)

    print("\n[Aperçu 5 lignes]")
    for row in transactions[:5]:
        print(" | ".join(row))

    # ── Rapport de catégories (bonus) ─────────────────────────────────────────
    from collections import Counter
    cats = Counter(row[7] for row in transactions)
    print("\n[Catégories]")
    for cat, n in cats.most_common():
        print(f"  {cat:40s} → {n:4d} transactions")

    ecrire_csv(transactions, chemin_csv)


if __name__ == "__main__":
    main()
