# tests/test_security.py
"""
Tests de sécurité : PIN, anti-bot, rate-limit, honeypot.
Lancer : pytest tests/test_security.py -v
Prérequis : PIN_APP=1234 dans .env (ou export PIN_APP=1234)
"""

from __future__ import annotations

import os
import time
import sys

import pytest

# --- Setup sys.path to ensure app.py is importable regardless of test runner location ---
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT_DIR = TESTS_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Force le PIN pour les tests
os.environ.setdefault("PIN_APP", "1234")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-fixe")

# Import APRÈS avoir positionné les variables d'environnement
from app import (
    MAX_ATTEMPTS,
    LOCKOUT_SECONDS,
    MIN_DELAY_BETWEEN_ATTEMPTS,
    RATE_LIMIT_MAX,
    _login_attempts,
    _request_log,
    app,
)

# ── Constantes ────────────────────────────────────────────────────────────────
PIN_OK = sys.argv[1] if len(sys.argv) > 1 else "1234"
PIN_BAD = "0000"
UA_HUMAN = "Mozilla/5.0 (X11; Linux x86_64)"
UA_BOT = "python-requests/2.31.0"
URL = "/api/auth/pin"


# ── Fixture : client de test avec reset état entre chaque test ────────────────

@pytest.fixture(autouse=True)
def reset_state():
    """Vide les compteurs avant chaque test pour isolation totale."""
    _login_attempts.clear()
    _request_log.clear()
    yield
    _login_attempts.clear()
    _request_log.clear()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    # Désactive la protection CSRF/session stricte en test
    app.config["SECRET_KEY"] = "test-secret-key-fixe"
    with app.test_client() as c:
        yield c


def post_pin(client, pin: str, ua: str = UA_HUMAN, website: str = "") -> tuple:
    """Helper : POST /api/auth/pin avec les bons headers."""
    resp = client.post(
        URL,
        json={"pin": pin, "website": website},
        headers={"User-Agent": ua, "Content-Type": "application/json"},
    )
    return resp, resp.get_json()


# ── Tests PIN ─────────────────────────────────────────────────────────────────

class TestPin:

    def test_bon_pin(self, client):
        """PIN correct → 200 ok:true."""
        resp, data = post_pin(client, PIN_OK)
        assert resp.status_code == 200
        assert data["ok"] is True

    def test_mauvais_pin(self, client):
        """PIN incorrect → 403 avec compteur restant."""
        resp, data = post_pin(client, PIN_BAD)
        assert resp.status_code == 403
        assert "remaining_attempts" in data
        assert data["remaining_attempts"] == MAX_ATTEMPTS - 1

    def test_pin_vide(self, client):
        """PIN vide → 403."""
        resp, data = post_pin(client, "")
        assert resp.status_code == 403

    def test_pin_manquant(self, client):
        """Body sans clé pin → 403."""
        resp = client.post(
            URL,
            json={"website": ""},
            headers={"User-Agent": UA_HUMAN},
        )
        assert resp.status_code == 403


# ── Tests blocage après N échecs ─────────────────────────────────────────────

class TestLockout:

    def test_blocage_apres_max_tentatives(self, client):
        """5 échecs → blocage, 6e retourne locked:true."""
        for i in range(MAX_ATTEMPTS - 1):
            resp, _ = post_pin(client, PIN_BAD)
            assert resp.status_code == 403

        # Dernière tentative → déclenche le blocage
        resp, data = post_pin(client, PIN_BAD)
        assert resp.status_code == 429
        assert data.get("locked") is True
        assert "retry_after" in data

    def test_bloque_reste_bloque(self, client):
        """Après blocage, même bon PIN → toujours 429."""
        # Provoque le blocage
        for _ in range(MAX_ATTEMPTS):
            post_pin(client, PIN_BAD)

        # Même avec le bon PIN : bloqué
        resp, data = post_pin(client, PIN_OK)
        assert resp.status_code == 429
        assert data.get("locked") is True

    def test_deblocage_apres_delai(self, client, monkeypatch):
        """Simule l'expiration du blocage sans attendre 60s."""
        # Provoque le blocage
        for _ in range(MAX_ATTEMPTS):
            post_pin(client, PIN_BAD)

        # Simule time.monotonic() APRÈS expiration
        # On manipule directement _login_attempts
        ip = "127.0.0.1"
        if ip in _login_attempts:
            _login_attempts[ip]["locked_until"] = time.monotonic() - 1  # déjà expiré

        resp, data = post_pin(client, PIN_OK)
        assert resp.status_code == 200
        assert data["ok"] is True

    def test_compteur_reset_apres_succes(self, client):
        """2 échecs puis succès → compteur remis à zéro."""
        post_pin(client, PIN_BAD)
        post_pin(client, PIN_BAD)
        post_pin(client, PIN_OK)  # succès → reset

        # On doit pouvoir refaire MAX_ATTEMPTS sans blocage immédiat
        for _ in range(MAX_ATTEMPTS - 1):
            resp, _ = post_pin(client, PIN_BAD)
            assert resp.status_code == 403  # pas encore bloqué


# ── Tests anti-bot User-Agent ─────────────────────────────────────────────────

class TestBotUserAgent:

    @pytest.mark.parametrize("ua", [
        "python-requests/2.31.0",
        "curl/7.88.1",
        "Wget/1.21",
        "Scrapy/2.11",
        "Go-http-client/1.1",
        "sqlmap/1.7",
        "Nikto/2.1.6",
        "",  # UA vide
    ])
    def test_bot_ua_bloque(self, client, ua):
        """Tous les UA bots → 403."""
        resp = client.post(
            URL,
            json={"pin": PIN_OK, "website": ""},
            headers={"User-Agent": ua, "Content-Type": "application/json"},
        )
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "Requête refusée."

    def test_ua_humain_passe(self, client):
        """UA navigateur normal → passe le filtre."""
        resp, data = post_pin(client, PIN_OK, ua=UA_HUMAN)
        assert resp.status_code == 200


# ── Tests honeypot ────────────────────────────────────────────────────────────

class TestHoneypot:

    def test_honeypot_rempli_faux_succes(self, client):
        """Champ website rempli → 200 silencieux (faux succès pour le bot)."""
        resp, data = post_pin(client, PIN_BAD, website="http://spam.example.com")
        # Faux succès : le bot croit avoir réussi
        assert resp.status_code == 200
        assert data.get("ok") is True

    def test_honeypot_vide_traitement_normal(self, client):
        """Champ website vide → traitement normal."""
        resp, data = post_pin(client, PIN_OK, website="")
        assert resp.status_code == 200
        assert data["ok"] is True


# ── Tests rate-limit ──────────────────────────────────────────────────────────

class TestRateLimit:

    def test_rate_limit_depasse(self, client):
        """Plus de RATE_LIMIT_MAX requêtes → 429."""
        last_resp = None
        # On dépasse volontairement la limite
        for _ in range(RATE_LIMIT_MAX + 5):
            last_resp = client.post(
                URL,
                json={"pin": PIN_BAD, "website": ""},
                headers={"User-Agent": UA_HUMAN},
            )
        assert last_resp.status_code == 429
        data = last_resp.get_json()
        assert "retry_after" in data


# ── Tests tentative trop rapide ───────────────────────────────────────────────

class TestTropRapide:

    def test_deux_tentatives_consecutives(self, client):
        """2e tentative immédiate → 429 (trop rapide)."""
        post_pin(client, PIN_BAD)   # 1ère OK
        resp, data = post_pin(client, PIN_BAD)  # 2e trop rapide
        assert resp.status_code == 429
        assert "retry_after" in data

    def test_apres_delai_ok(self, client, monkeypatch):
        """Après délai suffisant, nouvelle tentative autorisée."""
        ip = "127.0.0.1"
        post_pin(client, PIN_BAD)

        # Simule que la dernière tentative était il y a 2s
        if ip in _login_attempts:
            _login_attempts[ip]["last_attempt"] = time.monotonic() - (MIN_DELAY_BETWEEN_ATTEMPTS + 0.5)

        resp, data = post_pin(client, PIN_BAD)
        # Doit retourner 403 (mauvais PIN) et non 429 (trop rapide)
        assert resp.status_code == 403
        assert "remaining_attempts" in data



if __name__ == "__main__":
    import sys
    # Exécute tous les tests de ce fichier
    import pytest

    # Appel explicite à toutes les classes de test et leurs méthodes (main de test de tout)
    # Note : pytest découvre les fonctions automatiquement, mais on peut faire appel direct pour test manuel
    test_classes = [
        TestPin(),
        TestLockout(),
        TestRateLimit(),
        TestTropRapide(),
    ]
    import types

    # Crée un faux client pytest pour les tests manuels
    from types import SimpleNamespace

    class DummyClient:
        pass

    dummy_client = None
    dummy_monkeypatch = None

    for test_class in test_classes:
        for attr in dir(test_class):
            if attr.startswith("test_"):
                func = getattr(test_class, attr)
                # Check si la fonction nécessite des arguments ('client' ou 'monkeypatch')
                import inspect
                args = inspect.getfullargspec(func).args
                # Créé un SimpleNamespace pour injecter un dummy client/monkeypatch si besoin
                imports = globals()
                if "client" in args:
                    if dummy_client is None:
                        # Pour pytest, on préfère laisser pytest gérer le client fixture, donc skip ici
                        continue
                if "monkeypatch" in args:
                    if dummy_monkeypatch is None:
                        continue
                # Appelle la fonction sans arguments (mais tous nos tests ont besoin de fixtures)
                try:
                    func()
                    print(f"{test_class.__class__.__name__}.{attr}: OK")
                except Exception as e:
                    print(f"{test_class.__class__.__name__}.{attr}: FAIL — {e}")
    # Lance pytest pour faire tous les tests correctement
    sys.exit(pytest.main([__file__]))