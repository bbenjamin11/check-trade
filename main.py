#!/usr/bin/env python3
"""
Main.py - Point d'entree principal pour Check Trade

Usage:
    python main.py                    # Lance le serveur MVC par defaut
    python main.py --old              # Lance l'ancien serveur
    python main.py --test             # Teste le parseur
    python main.py --help             # Affiche l'aide
"""

import argparse
import os
import sys
from pathlib import Path

# Forcer UTF-8 sur stdout/stderr (corrige les UnicodeEncodeError sur Windows cp1252)
# Doit etre fait AVANT tout print() ou import qui logge
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    # Python < 3.7 ou stream deja redirige : on ignore
    pass

# Ajouter le dossier racine au path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

def run_mvc_server():
    """Lance le serveur MVC avec nouveau parseur."""
    print("Demarrage Check Trade MVC...")
    print("URL: http://127.0.0.1:5000")
    print("Utilise: PDFTradeRepublicParser (architecture MVC)")
    print("Pour arreter: Ctrl+C")
    print("-" * 50)
    
    try:
        from controllers.app import app
        port = int(os.getenv("PORT", 5000))
        debug = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
        app.run(host="0.0.0.0", port=port, debug=debug)
    except KeyboardInterrupt:
        print("\nServeur arrete")
    except Exception as e:
        print(f"Erreur: {e}")

def run_old_server():
    """Lance le serveur Clean Architecture experimental."""
    print("Demarrage Clean Architecture (experimental)...")
    print("URL: http://127.0.0.1:5000")
    print("Pour arreter: Ctrl+C")
    print("-" * 50)
    
    try:
        from app import app
        app.run(host="0.0.0.0", port=5000, debug=False)
    except KeyboardInterrupt:
        print("\nServeur arrete")
    except Exception as e:
        print(f"Erreur: {e}")

def test_parser():
    """Teste le parseur avec le fichier PDF par defaut."""
    print("Test du parseur...")
    
    try:
        from models.parsers import PDFTradeRepublicParser
        from pathlib import Path
        
        parser = PDFTradeRepublicParser()
        pdf_path = Path("Relevé de compte trade republic 04_2023 - 04_2026.pdf")
        
        if not pdf_path.exists():
            print(f"Fichier PDF non trouve: {pdf_path}")
            print("Placez votre fichier PDF dans le dossier racine du projet")
            return
        
        print(f"Parsing: {pdf_path.name}")
        transactions = parser.extract_csv(pdf_path)
        
        print(f"{len(transactions)} transactions extraites")
        print(f"{len(transactions[0]) if transactions else 0} colonnes par transaction")
        
        # Compter les categories (sans affichage des caracteres speciaux)
        if transactions:
            categories = {}
            for t in transactions:
                if len(t) > 7:
                    cat = t[7]
                    categories[cat] = categories.get(cat, 0) + 1
            
            print(f"{len(categories)} categories detectees")
            print("Test reussi!")
        
    except Exception as e:
        print(f"Erreur: {e}")
        import traceback
        traceback.print_exc()

def show_info():
    """Affiche les informations du projet."""
    print("=" * 60)
    print("CHECK TRADE - Architecture MVC")
    print("=" * 60)
    print()
    print("Architecture:")
    print("   models/parsers/     - Parseurs (logique metier)")
    print("   controllers/        - Controleurs Flask")  
    print("   views/static/       - Interface utilisateur")
    print()
    print("Parseurs disponibles:")
    print("   PDFTradeRepublicParser - Releves Trade Republic")
    print()
    print("Routes API:")
    print("   GET  /                 - Interface principale")
    print("   POST /api/parse        - Upload PDF -> CSV")
    print("   GET  /api/health       - Sante de l'application")
    print("   GET  /api/info         - Informations detaillees")
    print()
    print("Commandes:")
    print("   python main.py         - Lance le serveur MVC")
    print("   python main.py --test  - Teste le parseur")
    print("   python main.py --old   - Lance l'ancien serveur")
    print()
    print("Dossier:", ROOT)

def main():
    """Point d'entree principal."""
    parser = argparse.ArgumentParser(
        description="Check Trade - Parseur de releves bancaires",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python main.py                    Lance le serveur MVC
  python main.py --test             Teste le parseur
  python main.py --old              Lance l'ancien serveur
  python main.py --info             Affiche les informations
        """
    )
    
    parser.add_argument(
        "--old", 
        action="store_true",
        help="Lance l'ancien serveur (app.py)"
    )
    
    parser.add_argument(
        "--test", 
        action="store_true",
        help="Teste le parseur avec le fichier PDF par defaut"
    )
    
    parser.add_argument(
        "--info", 
        action="store_true",
        help="Affiche les informations du projet"
    )
    
    parser.add_argument(
        "--port", 
        type=int,
        default=5000,
        help="Port pour le serveur (defaut: 5000)"
    )
    
    args = parser.parse_args()
    
    # Configuration du port
    if args.port != 5000:
        os.environ["PORT"] = str(args.port)
    
    # Execution selon les arguments
    if args.info:
        show_info()
    elif args.test:
        test_parser()
    elif args.old:
        run_old_server()
    else:
        # Par defaut: serveur MVC
        run_mvc_server()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAu revoir!")
    except Exception as e:
        print(f"\nErreur critique: {e}")
        sys.exit(1)