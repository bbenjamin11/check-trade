#!/usr/bin/env python3
"""
API Controller - Gère les endpoints API REST
Pure logique métier sans couplage Flask
"""

import tempfile
import os
from pathlib import Path
from flask import Blueprint, request, jsonify, Response

# Services métier
from services.parse_service import ParseService
from services.security_service import SecurityService

# Blueprint API
api_bp = Blueprint('api', __name__)

# Instances des services
parse_service = ParseService()
security = SecurityService()

# Décorateur de sécurité
def require_security(f):
    """Middleware de sécurité."""
    def decorated(*args, **kwargs):
        # Anti-bot
        if security.is_bot_request():
            return jsonify({"error": "Accès refusé"}), 403
        
        # Rate limiting
        if not security.check_rate_limit():
            return jsonify({"error": "Trop de requêtes"}), 429
        
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# 
#  ROUTES API - LOGIQUE MÉTIER PURE
# 

@api_bp.route('/health')
def health():
    """Santé de l'application."""
    return jsonify({
        "status": "ok",
        "parser": "PDFTradeRepublicParser",
        "architecture": "MVC-Clean"
    })

@api_bp.route('/info')
def info():
    """Informations de l'application."""
    return jsonify({
        "app": "Check Trade",
        "version": "3.0-Clean-MVC",
        "architecture": {
            "app": "app.py - Infrastructure Flask",
            "controllers": "controllers/ - Logique métier",
            "services": "services/ - Services métier", 
            "models": "models/ - Modèles de données",
            "views": "views/ - Interface utilisateur"
        },
        "parsers": ["PDFTradeRepublicParser"],
        "patterns": ["Clean Architecture", "Dependency Injection", "Separation of Concerns"]
    })

# 
#  ROUTES AUTHENTIFICATION
# 

@api_bp.route('/auth/status')
def auth_status():
    """Statut de l'authentification."""
    # Pour l'instant, pas d'authentification requise
    return jsonify({
        "authenticated": True,
        "user": "demo",
        "method": "none"
    })

@api_bp.route('/auth/pin', methods=['POST'])
def auth_pin():
    """Validation du PIN (stub)."""
    data = request.get_json() or {}
    pin = data.get('pin', '')
    user = data.get('user', 'demo')
    
    # Pour l'instant, accepter tous les PINs
    return jsonify({
        "ok": True,
        "user": user,
        "message": "Authentification réussie"
    })

@api_bp.route('/auth/logout', methods=['POST'])
def auth_logout():
    """Déconnexion (stub)."""
    return jsonify({"ok": True, "message": "Déconnexion réussie"})

# 
#  ROUTES CATÉGORIES  
# 

@api_bp.route('/categories')
def categories():
    """Liste simple des catégories."""
    try:
        from parser import load_categories_json
        data = load_categories_json()
        return jsonify({"categories": list(data.get("categories", {}).keys())})
    except Exception as e:
        return jsonify({"categories": [" Divers"]}), 200

@api_bp.route('/categories/full')
def categories_full():
    """Configuration complète des catégories."""
    try:
        from parser import load_categories_json
        data = load_categories_json()
        return jsonify(data)
    except Exception as e:
        # Configuration par défaut
        return jsonify({
            "categories": {
                " Alimentation": {"keywords": ["supermarché"], "merchants": []},
                " Banque / Finance / Investissement": {"keywords": ["banque"], "merchants": []},
                " Divers": {"keywords": [], "merchants": []}
            },
            "known_merchants": {},
            "priority_order": ["known_merchants", " Alimentation", " Banque / Finance / Investissement", " Divers"]
        })

@api_bp.route('/categorie', methods=['POST'])
def update_category():
    """Met à jour la catégorie d'un marchand."""
    data = request.get_json() or {}
    merchant = data.get('merchant', '').strip()
    category = data.get('category', '').strip()
    
    if not merchant or not category:
        return jsonify({"error": "Marchand et catégorie requis"}), 400
    
    try:
        from parser import add_known_merchant_category
        add_known_merchant_category(merchant, category)
        return jsonify({
            "ok": True,
            "message": f"Marchand '{merchant}' → '{category}'"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 
#  ROUTES RELEVÉ
# 

@api_bp.route('/load_releve')
def load_releve():
    """Charge le fichier Releve.csv."""
    try:
        from parser import DEFAULT_CSV, lire_releve_csv, COLNAMES
        import csv, io
        
        if not DEFAULT_CSV.exists():
            return Response("", mimetype="text/csv")
        
        rows = lire_releve_csv(DEFAULT_CSV)
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";")
        writer.writerow(COLNAMES)
        writer.writerows(rows)
        
        return Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/releve/pdf', methods=['POST'])
@require_security  
def releve_pdf():
    """Upload PDF avec fusion dans Releve.csv."""
    try:
        # Validation du fichier
        validation_result = _validate_pdf_upload()
        if validation_result:
            return validation_result
        
        fichier = request.files["pdf"]
        
        # Traitement avec fusion
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        tmp_pdf = Path(path)
        
        try:
            fichier.save(tmp_pdf)
            
            # Fusion avec l'existant
            from parser import fusionner_pdf_dans_releve, reappliquer_categories_csv
            stats = fusionner_pdf_dans_releve(tmp_pdf)
            reappliquer_categories_csv()
            
            return jsonify({
                "ok": True,
                "added": stats["added"],
                "skipped_duplicates": stats["skipped"], 
                "total": stats["total"],
                "message": f"+{stats['added']} transaction(s), {stats['skipped']} doublons ignorés"
            })
            
        finally:
            tmp_pdf.unlink(missing_ok=True)
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/parse', methods=['POST'])
@require_security
def parse_pdf():
    """
    Parse un PDF en CSV.
    Contrôleur pur sans logique de parsing.
    """
    try:
        # Validation des entrées
        validation_result = _validate_pdf_upload()
        if validation_result:
            return validation_result
        
        fichier = request.files["pdf"]
        
        # Traitement via le service
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
            fichier.save(tmp_file.name)
            tmp_path = Path(tmp_file.name)
            
            try:
                # Délégation au service métier
                transactions = parse_service.parse_pdf(tmp_path)
                csv_content = parse_service.transactions_to_csv(transactions)
                
                return Response(
                    csv_content,
                    mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=transactions.csv"}
                )
                
            finally:
                tmp_path.unlink(missing_ok=True)
                
    except Exception as e:
        return jsonify({"error": f"Erreur de traitement: {str(e)}"}), 500

# 
#  FONCTIONS PRIVÉES - LOGIQUE DE VALIDATION
# 

def _validate_pdf_upload():
    """Valide l'upload PDF. Retourne une réponse d'erreur ou None si OK."""
    MAX_FILE_SIZE = 3 * 1024 * 1024  # 3 MB
    
    if "pdf" not in request.files:
        return jsonify({"error": "Champ 'pdf' manquant"}), 400
    
    fichier = request.files["pdf"]
    
    # Vérification taille
    fichier.stream.seek(0, 2)  # Fin du fichier
    size = fichier.stream.tell()
    fichier.stream.seek(0)     # Retour au début
    
    if size > MAX_FILE_SIZE:
        return jsonify({"error": "Fichier trop volumineux (max 3 Mo)"}), 413
    
    if not fichier.filename or not fichier.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Le fichier doit être un PDF"}), 400
    
    return None  # Pas d'erreur