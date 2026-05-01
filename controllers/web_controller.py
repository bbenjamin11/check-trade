#!/usr/bin/env python3
"""
Web Controller - Gère l'interface utilisateur
Sert les vues statiques
"""

from flask import Blueprint, send_from_directory
from pathlib import Path

# Blueprint Web
web_bp = Blueprint('web', __name__)

# Configuration
ROOT = Path(__file__).parent.parent
VIEWS_DIR = ROOT / "views" / "static"

@web_bp.route('/')
def index():
    """Page d'accueil - sert l'interface statique."""
    if VIEWS_DIR.exists():
        return send_from_directory(str(VIEWS_DIR), "index.html")
    return "Interface non trouvée", 404

@web_bp.route('/health-web')
def health_web():
    """Santé de l'interface web."""
    return f"Interface web OK - Dossier: {VIEWS_DIR}"