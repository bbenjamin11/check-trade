#!/usr/bin/env python3
"""
Test simple pour vérifier le nouveau parseur PDFTradeRepublicParser
"""

from pathlib import Path
from models.parsers import PDFTradeRepublicParser

def test_parser():
    """Test du nouveau parseur."""
    
    # Chemin du PDF de test
    pdf_path = Path("Relevé de compte trade republic 04_2023 - 04_2026.pdf")
    
    if not pdf_path.exists():
        print(f"Fichier PDF non trouve : {pdf_path}")
        return
    
    print(f"Test du parseur avec : {pdf_path}")
    
    # Créer une instance du parseur
    parser = PDFTradeRepublicParser()
    
    # Extraire les données
    try:
        transactions = parser.extract_csv(pdf_path)
        
        print(f"{len(transactions)} transactions extraites")
        
        # Afficher quelques exemples
        print(f"\nPremiere transaction a {len(transactions[0])} colonnes")
        print("Structure: DATE | TYPE | MONEY IN | MONEY OUT | BALANCE | DESCRIPTION | MERCHANT | CATEGORY")
        print("Parsing successful !")
        
        # Compter les catégories
        categories = {}
        for t in transactions:
            if len(t) > 7:  # S'assurer qu'il y a une colonne catégorie
                cat = t[7]  # Colonne CATEGORY
                categories[cat] = categories.get(cat, 0) + 1
        
        print(f"\nCategories trouvees: {len(categories)}")
        for cat, count in sorted(categories.items()):
            # Enlever les emojis pour l'affichage
            cat_clean = ''.join(c for c in cat if ord(c) < 128)
            print(f"  {cat_clean.strip()}: {count} transactions")
        
    except Exception as e:
        print(f"Erreur lors du parsing : {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_parser()