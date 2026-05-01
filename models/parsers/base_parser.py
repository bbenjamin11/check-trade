import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# 
#  NORMALISATION MARCHAND - COMMUN À TOUS LES PARSEURS
# 
_MERCHANT_RULES: List[Tuple[re.Pattern, str]] = [
    #  Grande distribution 
    (re.compile(r"carrefour",           re.I), "Carrefour"),
    (re.compile(r"intermarche|intermarché", re.I), "Intermarché"),
    (re.compile(r"delhaize",            re.I), "Delhaize"),
    (re.compile(r"lidl",                re.I), "Lidl"),
    (re.compile(r"colruyt",             re.I), "Colruyt"),
    (re.compile(r"aldi",                re.I), "Aldi"),

    #  Amazon (toutes variantes) 
    (re.compile(r"amazon|amzn\s*mktp|amazon\.fr|amazon\.com", re.I), "Amazon"),

    #  Restauration rapide 
    (re.compile(r"quick\b",             re.I), "Quick"),
    (re.compile(r"burger\s*king",       re.I), "Burger King"),
    (re.compile(r"mc\s*donald|mac\s*donald", re.I), "McDonald's"),
    (re.compile(r"kfc\b",               re.I), "KFC"),
    (re.compile(r"pizza\s*hut",         re.I), "Pizza Hut"),
    (re.compile(r"lunch\s*garden",      re.I), "Lunch Garden"),
    (re.compile(r"frit.?house",         re.I), "Frit'House"),

    #  Boulangeries 
    (re.compile(r"boulangerie\s+louise",re.I), "Boulangerie Louise"),
    (re.compile(r"boulangerie\s+gozee", re.I), "Boulangerie Gozée"),
    (re.compile(r"boulangerie\s+heind", re.I), "Boulangerie Heindrichs"),

    #  Bricolage 
    (re.compile(r"brico\b",             re.I), "Brico"),
    (re.compile(r"leroy\s*merlin",      re.I), "Leroy Merlin"),

    #  Sport 
    (re.compile(r"decathlon",           re.I), "Decathlon"),
    (re.compile(r"go\s*sport",          re.I), "Go Sport"),

    #  Mode / Textile 
    (re.compile(r"jules\b",             re.I), "Jules"),
    (re.compile(r"orchestra\b",         re.I), "Orchestra"),
    (re.compile(r"veritas\b",           re.I), "Veritas"),
    (re.compile(r"north\s*face",        re.I), "The North Face"),
    (re.compile(r"c\s*&\s*a\b",         re.I), "C&A"),
    (re.compile(r"vinted\b",            re.I), "Vinted"),

    #  Maison / Déco 
    (re.compile(r"ikea",                re.I), "IKEA"),
    (re.compile(r"action\b",            re.I), "Action"),
    (re.compile(r"back\s*market",       re.I), "Back Market"),
    (re.compile(r"jysk\b",              re.I), "JYSK"),

    #  Santé 
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

    #  Loisirs / Culture 
    (re.compile(r"pairi\s+daiza",       re.I), "Pairi Daiza"),
    (re.compile(r"vayamundo",           re.I), "Vayamundo"),
    (re.compile(r"zevent",              re.I), "ZEvent"),
    (re.compile(r"king\s+jouet",        re.I), "King Jouet"),
    (re.compile(r"bd\s+world",          re.I), "BD World"),
    (re.compile(r"neuhaus",             re.I), "Neuhaus"),

    #  Restaurants / Bars 
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

    #  Streaming / IA / Abonnements 
    (re.compile(r"mistral\.ai",         re.I), "Mistral.AI"),
    (re.compile(r"netflix",             re.I), "Netflix"),
    (re.compile(r"spotify",             re.I), "Spotify"),
    (re.compile(r"youtube|google\s+youtube", re.I), "YouTube Premium"),
    (re.compile(r"disney",              re.I), "Disney+"),
    (re.compile(r"apple",               re.I), "Apple"),
    (re.compile(r"mammouth",            re.I), "Mammouth"),
    (re.compile(r"shcmsm",              re.I), "SHCMSM"),
    (re.compile(r"cofeo",               re.I), "Cofeo Services"),

    #  Transport / Mobilité 
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

    #  Investissement 
    (re.compile(r"savings plan.*?FR0000073272", re.I), "Savings Plan — SAFRAN"),
    (re.compile(r"savings plan.*?IE00B4L5Y983", re.I), "Savings Plan — iShares MSCI World"),
    (re.compile(r"savings plan.*?US67066G1040", re.I), "Savings Plan — NVIDIA"),
    (re.compile(r"savings plan.*?FR0000120271", re.I), "Savings Plan — TotalEnergies"),
    (re.compile(r"savings plan.*?FR0000121972", re.I), "Savings Plan — Schneider Electric"),
    (re.compile(r"savings plan",         re.I), "Savings Plan — Autre"),
    (re.compile(r"execution trade|direct purchase", re.I), "Achat Titre Direct"),
    (re.compile(r"private markets",      re.I), "Private Markets"),

    #  Divers / Transferts 
    (re.compile(r"payout to transit",    re.I), "PayOut Transit"),
    (re.compile(r"cash\s+reward|saveback", re.I), "Saveback / Reward"),
    (re.compile(r"vrbo",                 re.I), "VRBO (Location vacances)"),
]

# 
#  CONFIGURATION CATÉGORIES - COMMUN À TOUS LES PARSEURS
# 
_CAT_CONFIG: Optional[Dict] = None

# Configuration des catégories par défaut
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
CAT_FILE = DATA_DIR / "cathegorie.json"


class Parser(ABC):
    """Classe abstraite pour tous les parseurs."""
    
    def __init__(self):
        self._cat_config: Optional[Dict] = None
    
    @abstractmethod
    def extract_csv(self, file_path: Path) -> List[List[str]]:
        """Extrait les données d'un fichier et les retourne sous forme de liste de listes."""
        pass
    
    # 
    #  MÉTHODES COMMUNES À TOUS LES PARSEURS
    # 
    
    def _get_category_config(self) -> Dict:
        """Charge la configuration des catégories."""
        if self._cat_config is None:
            if CAT_FILE.exists():
                with open(CAT_FILE, encoding="utf-8") as f:
                    self._cat_config = json.load(f)
            else:
                # Configuration par défaut si le fichier n'existe pas
                self._cat_config = {
                    "categories": {
                        " Alimentation": {"keywords": ["supermarché", "alimentaire"], "merchants": []},
                        " Banque / Finance / Investissement": {"keywords": ["banque", "investissement"], "merchants": []},
                        " Divers": {"keywords": [], "merchants": []}
                    },
                    "known_merchants": {},
                    "priority_order": ["known_merchants", " Alimentation", " Banque / Finance / Investissement", " Divers"]
                }
        
        # À ce point, self._cat_config ne peut pas être None
        assert self._cat_config is not None
        return self._cat_config
    
    def _clean_raw(self, raw: str) -> str:
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

    def _normalize_merchant(self, raw_desc: str) -> str:
        """Retourne le nom du marchand normalisé."""
        s = self._clean_raw(raw_desc)
        for pattern, merchant in _MERCHANT_RULES:
            if pattern.search(s):
                return merchant
        # Fallback : nettoyage cosmétique (supprime codes/IDs résiduels)
        s = re.sub(r"\s+[A-Z0-9]{8,}$", "", s)
        s = re.sub(r"\s+\d{3,}$", "", s).strip()
        return s or "—"

    def _known_merchant_match(self, merchant_upper: str, key: str) -> bool:
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

    def _categorize(self, merchant: str, raw_desc: str, type_: str, user_known_merchants: Optional[Dict[str, str]] = None) -> str:
        """Catégorise via cathegorie.json : known_merchants (priorité), puis categories dans priority_order."""
        cfg = self._get_category_config()
        cats = cfg["categories"]
        known = cfg["known_merchants"]
        order = cfg["priority_order"]
        default = next(
            (n for n in order if n in cats and n.startswith("")),
            " Divers",
        )

        desc = self._clean_raw(raw_desc)
        haystack = f"{type_} {desc} {merchant}".lower()
        merch_u = merchant.upper().strip()

        # Priorité 1 : préférences utilisateur (si présentes)
        if user_known_merchants:
            for key in sorted(user_known_merchants.keys(), key=len, reverse=True):
                if self._known_merchant_match(merch_u, key):
                    return user_known_merchants[key]

        # Priorité 2 : mapping global partagé
        for key in sorted(known.keys(), key=len, reverse=True):
            if self._known_merchant_match(merch_u, key):
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
            bank = " Banque / Finance / Investissement"
            if bank in cats:
                return bank
        if "transfer" in type_low:
            bank = " Banque / Finance / Investissement"
            if bank in cats:
                return bank
        if "trade" in type_low:
            bank = " Banque / Finance / Investissement"
            if bank in cats:
                return bank
        return default