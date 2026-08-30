#!/usr/bin/env python3
"""
Auth Service - Authentification par PIN + stockage chiffré par utilisateur.

Principe (repris à l'identique de l'ancien controllers/app.py legacy) :
- Pas de base de mots de passe : le PIN saisi sert DIRECTEMENT de clé de
  chiffrement (PBKDF2 -> Fernet) pour le Releve.csv de l'utilisateur.
- Un PIN "correct" est un PIN qui déchiffre avec succès le fichier existant.
- Au tout premier login d'un utilisateur, le PIN saisi devient sa clé.
- Zéro persistance du PIN en clair : uniquement en RAM (session serveur),
  jamais en cookie, jamais en log.
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import request, session

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

# Marqueur de format du CSV chiffré + coût PBKDF2 (ne JAMAIS changer sans
# migration explicite : les fichiers existants sous data/users/*/Releve.csv
# ont été chiffrés avec ces paramètres).
ENC_MAGIC = b"CTENC1\n"
PBKDF2_ITERS = 390_000

# Anti brute-force PIN
MAX_ATTEMPTS: int = 5
LOCKOUT_SECONDS: int = 60
MIN_DELAY_BETWEEN_ATTEMPTS: float = 1.5


class AuthService:
    """
    Singleton thread-safe : un seul état d'auth par process Flask.

    Note : avec plusieurs workers gunicorn, chaque worker a son propre état
    en mémoire (comme dans l'ancien controllers/app.py). Un même utilisateur
    peut donc parfois retomber sur un worker qui ne connaît pas sa session
    et se voir redemander le PIN. C'est une limitation connue, pas une
    régression introduite par ce portage.
    """

    _instance: Optional["AuthService"] = None
    _instance_lock = threading.Lock()

    def __new__(cls) -> "AuthService":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_once()
        return cls._instance

    def _init_once(self) -> None:
        # { ip: {"attempts": int, "locked_until": float, "last_attempt": float} }
        self._login_attempts: dict[str, dict] = {}
        # { token: {"user_id": str, "pin": str} } — jamais sérialisé en cookie
        self._session_auth: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------ IP

    def client_ip(self) -> str:
        return (
            request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
            .split(",")[0]
            .strip()
        )

    # ------------------------------------------------------ Brute-force PIN

    def is_locked(self, ip: str) -> tuple[bool, float]:
        record = self._login_attempts.get(ip)
        if not record:
            return False, 0.0
        locked_until = record.get("locked_until", 0.0)
        if locked_until and time.monotonic() < locked_until:
            return True, round(locked_until - time.monotonic(), 1)
        return False, 0.0

    def too_fast(self, ip: str) -> bool:
        record = self._login_attempts.get(ip, {})
        last = record.get("last_attempt", 0.0)
        return (time.monotonic() - last) < MIN_DELAY_BETWEEN_ATTEMPTS

    def record_failure(self, ip: str) -> int:
        """Retourne le nombre de tentatives restantes (0 = verrouillé)."""
        if ip not in self._login_attempts:
            self._login_attempts[ip] = {"attempts": 0, "locked_until": 0.0, "last_attempt": 0.0}
        record = self._login_attempts[ip]
        if record["locked_until"] and time.monotonic() >= record["locked_until"]:
            record["attempts"] = 0
            record["locked_until"] = 0.0
        record["attempts"] += 1
        record["last_attempt"] = time.monotonic()
        if record["attempts"] >= MAX_ATTEMPTS:
            record["locked_until"] = time.monotonic() + LOCKOUT_SECONDS
            return 0
        return MAX_ATTEMPTS - record["attempts"]

    def record_success(self, ip: str) -> None:
        self._login_attempts.pop(ip, None)

    # ------------------------------------------------------------- Session

    def sanitize_user_id(self, raw_user: str) -> str:
        user = (raw_user or "").strip().lower()
        user = re.sub(r"[^a-z0-9._-]+", "_", user)
        user = user.strip("._-")
        return user

    def create_session(self, user_id: str, pin: str) -> None:
        token = os.urandom(18).hex()
        self._session_auth[token] = {"user_id": user_id, "pin": pin}
        session["auth_token"] = token

    def get_session_pin(self) -> Optional[str]:
        token = session.get("auth_token")
        if not token:
            return None
        auth = self._session_auth.get(token)
        return auth.get("pin") if auth else None

    def get_session_user(self) -> Optional[str]:
        token = session.get("auth_token")
        if not token:
            return None
        auth = self._session_auth.get(token)
        return auth.get("user_id") if auth else None

    def clear_session(self) -> None:
        token = session.pop("auth_token", None)
        if token:
            self._session_auth.pop(token, None)
        session.clear()

    # -------------------------------------------------- Chemins par utilisateur

    def releve_path(self, user_id: str) -> Path:
        return DATA_DIR / "users" / user_id / "Releve.csv"

    def user_prefs_path(self, user_id: str) -> Path:
        return DATA_DIR / "users" / user_id / "known_merchants.json"

    def last_tr_sync_path(self, user_id: str) -> Path:
        return DATA_DIR / "users" / user_id / "last_tr_sync.json"

    def tr_balance_path(self, user_id: str) -> Path:
        return DATA_DIR / "users" / user_id / "tr_balance.json"

    @staticmethod
    def merchant_key(merchant: str) -> str:
        return merchant.strip().upper()

    def load_user_known_merchants(self, user_id: str) -> dict[str, str]:
        path = self.user_prefs_path(user_id)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        out: dict[str, str] = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, str):
                kk = self.merchant_key(k)
                if kk:
                    out[kk] = v.strip()
        return out

    def save_user_known_merchants(self, user_id: str, mapping: dict[str, str]) -> None:
        path = self.user_prefs_path(user_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered = dict(sorted(mapping.items(), key=lambda kv: kv[0]))
        path.write_text(json.dumps(ordered, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_last_tr_sync(self, user_id: str) -> Optional[str]:
        """Timestamp ISO du dernier event synchronisé. None = première sync."""
        path = self.last_tr_sync_path(user_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        iso = data.get("last_event_iso")
        return iso if isinstance(iso, str) and iso else None

    def save_last_tr_sync(self, user_id: str, last_event_iso: str) -> None:
        path = self.last_tr_sync_path(user_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_event_iso": last_event_iso,
            "last_sync_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load_tr_balance(self, user_id: str) -> Optional[dict]:
        """
        Dernier solde reel connu (recupere directement via l'API Trade Republic
        lors de la derniere sync reussie). None si jamais synchronise.
        """
        path = self.tr_balance_path(user_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict) or not data.get("amount"):
            return None
        return data

    def save_tr_balance(self, user_id: str, amount: str, currency: str) -> None:
        path = self.tr_balance_path(user_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "amount": amount,
            "currency": currency,
            "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # --------------------------------------------------- Chiffrement PIN

    @staticmethod
    def _derive_pin_key(pin: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERS,
        )
        return base64.urlsafe_b64encode(kdf.derive(pin.encode("utf-8")))

    def encrypt_csv_text(self, csv_text: str, pin: str) -> bytes:
        salt = os.urandom(16)
        key = self._derive_pin_key(pin, salt)
        token = Fernet(key).encrypt(csv_text.encode("utf-8"))
        return ENC_MAGIC + base64.urlsafe_b64encode(salt) + b"\n" + token

    def decrypt_csv_bytes(self, blob: bytes, pin: str) -> str:
        if not blob.startswith(ENC_MAGIC):
            return blob.decode("utf-8-sig")
        lines = blob.split(b"\n", 2)
        if len(lines) < 3:
            raise ValueError("Format chiffré invalide.")
        salt = base64.urlsafe_b64decode(lines[1])
        token = lines[2]
        key = self._derive_pin_key(pin, salt)
        try:
            plain = Fernet(key).decrypt(token)
        except InvalidToken as e:
            raise ValueError("PIN incorrect.") from e
        return plain.decode("utf-8")

    def read_releve_csv_text(self, path: Path, pin: str) -> str:
        return self.decrypt_csv_bytes(path.read_bytes(), pin)

    def write_releve_csv_text(self, path: Path, csv_text: str, pin: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.encrypt_csv_text(csv_text, pin))

    # ------------------------------------------------------------- Login

    def login(self, user_id: str, pin: str, legacy_global_csv: Optional[Path] = None) -> bool:
        """
        Vérifie le PIN pour user_id (déchiffre son Releve.csv s'il existe).
        Migre un éventuel ancien fichier global/non chiffré au passage.
        Retourne True si le PIN est accepté (fichier absent = premier login,
        toujours accepté ; le PIN saisi devient alors la clé).
        """
        releve = self.releve_path(user_id)
        try:
            if not releve.exists() and legacy_global_csv and legacy_global_csv.exists():
                releve.parent.mkdir(parents=True, exist_ok=True)
                legacy_global_csv.replace(releve)
            if releve.exists():
                data = releve.read_bytes()
                if data.startswith(ENC_MAGIC):
                    self.decrypt_csv_bytes(data, pin)
                else:
                    # Migration transparente : premier PIN saisi devient la clé.
                    self.write_releve_csv_text(releve, data.decode("utf-8-sig"), pin)
            return True
        except Exception:
            return False
