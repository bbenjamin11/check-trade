#!/usr/bin/env python3
"""
TR Session Store - Sessions pytr ephemeres en RAM.

Pourquoi ce module existe :
    Le login pytr est en 2 etapes (initiate -> SMS/push -> complete).
    Entre les 2, on doit conserver l'instance TradeRepublicApi car elle
    detient le _process_id et le cookie WAF necessaires a complete_weblogin().

PRINCIPES :
- Stockage RAM uniquement (process Python). JAMAIS de disque.
- TTL strict (defaut 5 min). Au-dela, la session est jetee.
- Bind a un user_id check-trade : un user A ne peut pas reutiliser le
  session_id d'un user B meme s'il le devine.
- session_id = secrets.token_urlsafe(32) : 256 bits d'entropie.
- Cleanup paresseux a chaque acces + cleanup explicite apres usage.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 300  # 5 minutes


@dataclass
class _Entry:
    """Une session pytr en cours. JAMAIS retournee directement (mutable)."""
    api: object  # TradeRepublicApi (typing souple pour eviter import)
    user_id: str
    created_at: float
    expires_at: float


class TRSessionStore:
    """
    Singleton thread-safe.
    Une seule instance pour tout le process Flask.
    """

    _instance: Optional["TRSessionStore"] = None
    _instance_lock = threading.Lock()

    def __new__(cls) -> "TRSessionStore":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_once()
        return cls._instance

    def _init_once(self) -> None:
        self._sessions: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    # ----------------------------------------------------------- API publique

    def create(self, api, user_id: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
        """
        Cree une session, retourne le session_id.
        api : instance TradeRepublicApi apres initiate_weblogin().
        """
        session_id = secrets.token_urlsafe(32)
        now = time.monotonic()
        entry = _Entry(
            api=api,
            user_id=user_id,
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        with self._lock:
            self._cleanup_expired_locked()
            self._sessions[session_id] = entry
        logger.info("TR session creee user=%s ttl=%ds", user_id, ttl_seconds)
        return session_id

    def get(self, session_id: str, expected_user_id: str):
        """
        Recupere l'instance api liee a session_id.
        Verifie que la session appartient bien au user_id en cours.

        Raises:
            KeyError: session inexistante ou expiree
            PermissionError: session ne correspond pas au user
        """
        with self._lock:
            self._cleanup_expired_locked()
            entry = self._sessions.get(session_id)
            if entry is None:
                raise KeyError("session_id inconnu ou expire")
            if entry.user_id != expected_user_id:
                # Ne PAS dire "user mismatch" : on traite comme inexistant
                # pour ne pas leak d'info a un attaquant qui essaierait des IDs
                logger.warning(
                    "TR session : tentative d'acces avec user_id different "
                    "(attendu=%s, recu=%s)", entry.user_id, expected_user_id
                )
                raise KeyError("session_id inconnu ou expire")
        return entry.api

    def delete(self, session_id: str) -> bool:
        """Supprime une session. Retourne True si quelque chose a ete supprime."""
        with self._lock:
            entry = self._sessions.pop(session_id, None)
        if entry is not None:
            logger.info("TR session supprimee user=%s", entry.user_id)
            return True
        return False

    def count(self) -> int:
        """Helper de monitoring/test."""
        with self._lock:
            self._cleanup_expired_locked()
            return len(self._sessions)

    # ----------------------------------------------------------- internals

    def _cleanup_expired_locked(self) -> None:
        """A appeler avec _lock acquis. Supprime les sessions expirees."""
        now = time.monotonic()
        expired = [sid for sid, e in self._sessions.items() if e.expires_at <= now]
        for sid in expired:
            entry = self._sessions.pop(sid)
            logger.info("TR session expiree user=%s", entry.user_id)
