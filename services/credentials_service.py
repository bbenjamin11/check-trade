#!/usr/bin/env python3
"""
TR Credentials - Conteneur en memoire pour les identifiants Trade Republic.

PRINCIPE : ZERO PERSISTANCE.
- Les identifiants n'existent QUE dans la pile Python pendant un appel
- Aucune ecriture disque
- Aucun stockage en session Flask
- Aucun log

Le seul role de ce module est de fournir un conteneur typé avec un __repr__
qui MASQUE les secrets, pour eviter qu'ils fuitent via une stack trace,
un logger debug, ou un serializer JSON accidentel.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TRCredentials:
    """
    Identifiants Trade Republic en clair, en memoire uniquement.

    Frozen pour eviter mutation accidentelle.
    NE PAS logger, NE PAS serialiser, NE PAS stocker.

    Cycle de vie attendu :
        1. Construit a partir des champs HTTP (request body)
        2. Passe a tr_sync_service
        3. Reference relachee -> garbage collecte
    """

    phone: str  # format international, ex: "+33612345678"
    pin: str    # 4 chiffres

    def __repr__(self) -> str:
        # Anti-fuite dans les traceback / logs / repr de dict
        return f"TRCredentials(phone={self._mask_phone()}, pin=****)"

    def __str__(self) -> str:
        return self.__repr__()

    def _mask_phone(self) -> str:
        if len(self.phone) < 6:
            return "***"
        return self.phone[:4] + "***" + self.phone[-2:]

    @classmethod
    def from_request(cls, payload: dict) -> "TRCredentials":
        """
        Construit depuis un dict (request JSON body).
        Valide le format. Leve ValueError si invalide.
        """
        phone = (payload.get("phone") or "").strip()
        pin = (payload.get("pin") or "").strip()

        if not phone.startswith("+") or len(phone) < 10 or len(phone) > 16:
            raise ValueError("phone invalide (format international attendu, ex +33612345678)")
        if not phone[1:].isdigit():
            raise ValueError("phone invalide (chiffres uniquement apres le +)")
        if not pin.isdigit() or len(pin) != 4:
            raise ValueError("pin invalide (4 chiffres attendus)")

        return cls(phone=phone, pin=pin)
