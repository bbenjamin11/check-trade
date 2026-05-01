#!/usr/bin/env python3
"""
Test du nouveau contrôleur MVC
"""

import requests
import time
from pathlib import Path

def test_mvc_controller():
    """Test du contrôleur MVC avec l'API."""
    
    base_url = "http://127.0.0.1:5000"
    
    print("Test du controleur MVC")
    print(f"URL: {base_url}")
    
    # Test 1: Health check
    print("\n1. Test Health Check...")
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Reponse: {response.json()}")
        else:
            print(f"   Erreur: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"   Serveur non accessible: {e}")
        return
    
    # Test 2: Info API
    print("\n2. Test Info API...")
    try:
        response = requests.get(f"{base_url}/api/info", timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   App: {data.get('app')}")
            print(f"   Version: {data.get('version')}")
            print(f"   Parseurs: {data.get('parsers')}")
        else:
            print(f"   Erreur: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"    Erreur requête: {e}")
    
    # Test 3: Page d'accueil
    print("\n3. Test page d'accueil...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print(f"    Erreur requête: {e}")
    
    # Test 4: Upload PDF (si le fichier existe)
    pdf_path = Path("Relevé de compte trade republic 04_2023 - 04_2026.pdf")
    if pdf_path.exists():
        print(f"\n4. Test upload PDF ({pdf_path.name})...")
        try:
            with open(pdf_path, 'rb') as f:
                files = {'pdf': (pdf_path.name, f, 'application/pdf')}
                response = requests.post(f"{base_url}/api/parse", files=files, timeout=30)
            
            print(f"   Status: {response.status_code}")
            print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
            
            if response.status_code == 200:
                # C'est du CSV
                content = response.text
                lines = content.split('\n')
                print(f"    CSV généré: {len(lines)} lignes")
                print(f"   En-têtes: {lines[0] if lines else 'N/A'}")
                if len(lines) > 1:
                    print(f"   Première transaction: {lines[1][:100]}...")
            else:
                print(f"    Erreur: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"    Erreur upload: {e}")
    else:
        print(f"\n4. Test upload PDF:  Fichier {pdf_path} non trouvé")
    
    print(f"\n Tests terminés")

if __name__ == "__main__":
    test_mvc_controller()