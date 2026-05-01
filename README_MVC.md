# Check Trade - Architecture MVC

Parseur de relevés bancaires avec architecture MVC extensible.

## 🚀 Démarrage Rapide

### Installation
```bash
# Activer l'environnement virtuel
source .venv/Scripts/activate  # Linux/Mac
# ou
.venv\Scripts\activate.bat     # Windows

# Installer les dépendances (si nécessaire)
pip install -r requirements.txt
```

### Utilisation

#### Serveur Web (recommandé)
```bash
python main.py                 # Lance le serveur MVC
```
Puis ouvrir : http://127.0.0.1:5000

#### Test du parseur
```bash
python main.py --test          # Teste avec le PDF par défaut
```

#### Options avancées
```bash
python main.py --old           # Lance l'ancien serveur (backup)
python main.py --port 8080     # Port personnalisé
python main.py --info          # Informations du projet
python main.py --help          # Aide complète
```

## 🏗️ Architecture MVC

```
check-trade/
├── main.py                     # Point d'entrée principal
├── models/parsers/            # MODÈLES - Logique métier
│   ├── base_parser.py         # Classe abstraite + méthodes communes
│   ├── pdf_trade_republic_parser.py  # Parseur Trade Republic
│   └── __init__.py
├── controllers/               # CONTRÔLEURS - Orchestration
│   ├── app_mvc.py            # Contrôleur MVC (nouveau)
│   └── app.py                # Contrôleur legacy (backup)
└── views/static/             # VUES - Interface utilisateur
    ├── index.html
    ├── style.css
    └── script.js
```

## 📋 API Routes

| Route | Méthode | Description |
|-------|---------|-------------|
| `/` | GET | Interface principale |
| `/api/parse` | POST | Upload PDF → CSV |
| `/api/health` | GET | Santé de l'application |
| `/api/info` | GET | Informations détaillées |

## 🔧 Parseurs Disponibles

### PDFTradeRepublicParser
- **Format** : PDF Trade Republic
- **Fonctionnalités** :
  - ✅ Classification automatique des marchands
  - ✅ Catégorisation intelligente (22+ catégories)
  - ✅ Normalisation des noms de marchands
  - ✅ Détection des types de transactions
  - ✅ Export CSV avec colonnes : DATE, TYPE, MONEY IN/OUT, BALANCE, DESCRIPTION, MERCHANT, CATEGORY

## 🎯 Extensibilité

### Ajouter un nouveau parseur
```python
# models/parsers/my_new_parser.py
from .base_parser import Parser
from pathlib import Path
from typing import List

class MyNewParser(Parser):
    def extract_csv(self, file_path: Path) -> List[List[str]]:
        # Votre logique de parsing
        # Les méthodes self._normalize_merchant() et self._categorize() 
        # sont automatiquement héritées !
        return transactions
```

### Avantages de l'architecture
- ✅ **Méthodes communes partagées** (normalisation, catégorisation)
- ✅ **Configuration centralisée** (règles marchands, catégories)
- ✅ **Séparation des responsabilités** (MVC)
- ✅ **Facilité de maintenance** et d'extension
- ✅ **Tests isolés** par composant

## 📊 Exemple de Résultats

```
Test du parseur...
Parsing: Relevé de compte trade republic 04_2023 - 04_2026.pdf
1112 transactions extraites
8 colonnes par transaction
22 categories detectees
Test reussi!
```

## 🛠️ Développement

### Structure des données
Chaque transaction contient :
1. **DATE** - Date de la transaction
2. **TYPE** - Type de transaction (Transfer, etc.)
3. **MONEY IN** - Montant entrant
4. **MONEY OUT** - Montant sortant
5. **BALANCE** - Solde
6. **DESCRIPTION** - Description brute
7. **MERCHANT** - Nom du marchand normalisé
8. **CATEGORY** - Catégorie automatique

### Catégories automatiques
- 🛒 Alimentation / Courses
- 🏪 Amazon / E-commerce  
- 🏦 Banque / Finance / Investissement
- 🍽️ Resto / Bar / Café
- ⛽ Transport / Carburant
- 🎮 Streaming / IA / Abonnement
- ... et bien d'autres

## 📝 Notes

- Le projet gère automatiquement la **normalisation des marchands** (ex: "AMZN MKTP" → "Amazon")
- La **catégorisation est intelligente** et basée sur des règles configurables
- L'architecture est **extensible** pour supporter d'autres banques/formats
- Compatible avec l'ancien code via `--old`

---
**Architecture MVC complète et fonctionnelle ! 🎯**