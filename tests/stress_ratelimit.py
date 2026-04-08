# tests/stress_ratelimit.py
"""
Envoie 30 requêtes simultanées pour vérifier le rate-limit.
Lancer : python tests/stress_ratelimit.py
Serveur doit tourner sur :5000
"""

from __future__ import annotations

import threading
import time

import requests

URL = "http://127.0.0.1:5000/api/auth/pin"
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
}

results: list[int] = []
lock = threading.Lock()


def send_request():
    try:
        r = requests.post(
            URL,
            json={"pin": "0000", "website": ""},
            headers=HEADERS,
            timeout=5,
        )
        with lock:
            results.append(r.status_code)
    except Exception as e:
        with lock:
            results.append(0)
        print(f"Erreur: {e}")


print(f"Envoi de 30 requêtes simultanées vers {URL}...")
threads = [threading.Thread(target=send_request) for _ in range(30)]
start = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
elapsed = time.time() - start

print(f"\nTerminé en {elapsed:.2f}s")
print(f"Codes reçus : {sorted(set(results))}")
print(f"  200 : {results.count(200)}")
print(f"  403 : {results.count(403)}")
print(f"  429 : {results.count(429)}")
print(f"  Err : {results.count(0)}")

# Vérification : au moins quelques 429
assert results.count(429) > 0, "❌ Rate-limit non déclenché !"
print("\n✅ Rate-limit OK — des 429 ont bien été retournés.")
