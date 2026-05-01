#!/usr/bin/env python3
"""
Parse Service - Service métier pour le parsing
Logique pure sans dépendances web
"""

import csv
import io
import logging
from pathlib import Path
from typing import List

# Import du modèle
import sys
sys.path.append(str(Path(__file__).parent.parent))
from models.parsers import PDFTradeRepublicParser

logger = logging.getLogger(__name__)

class ParseService:
    """Service de parsing - encapsule la logique métier."""
    
    def __init__(self):
        self.parser = PDFTradeRepublicParser()
    
    def parse_pdf(self, pdf_path: Path) -> List[List[str]]:
        """
        Parse un PDF et retourne les transactions.
        Logique métier pure.
        """
        try:
            transactions = self.parser.extract_csv(pdf_path)
            logger.info(f"Parse reussi: {len(transactions)} transactions de {pdf_path.name}")
            return transactions
        except Exception as e:
            logger.error(f"Erreur parsing {pdf_path.name}: {e}")
            raise
    
    def transactions_to_csv(self, transactions: List[List[str]]) -> str:
        """
        Convertit les transactions en CSV.
        Logique de sérialisation pure.
        """
        try:
            from parser import COLNAMES
        except ImportError:
            COLNAMES = ["DATE", "TYPE", "MONEY IN", "MONEY OUT", "BALANCE", "DESCRIPTION", "MERCHANT", "CATEGORY"]
        
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";")
        writer.writerow(COLNAMES)
        writer.writerows(transactions)
        
        return output.getvalue()
    
    def get_parser_info(self) -> dict:
        """Retourne les informations du parseur."""
        return {
            "type": type(self.parser).__name__,
            "methods": [method for method in dir(self.parser) if not method.startswith('_')],
            "inherited_methods": [
                "_normalize_merchant", 
                "_categorize", 
                "_clean_raw",
                "_get_category_config"
            ]
        }