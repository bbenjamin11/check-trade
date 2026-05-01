#!/usr/bin/env python3
"""
Security Service - Service métier pour la sécurité
Logique pure sans dépendances web (injectées)
"""

import re
import time
import logging
from typing import Optional
from flask import request

logger = logging.getLogger(__name__)

class SecurityService:
    """Service de sécurité - logique métier pure."""
    
    def __init__(self):
        self._request_log = {}
        self._bot_patterns = [
            r"python-requests", r"curl/", r"wget/", r"libwww", r"scrapy",
            r"go-http-client", r"java/", r"nikto", r"sqlmap", r"nmap",
            r"masscan", r"zgrab", r"dirbuster", r"nuclei", r"^$"
        ]
        self._bot_regex = re.compile("|".join(self._bot_patterns), re.IGNORECASE)
        
        # Configuration
        self.RATE_LIMIT_WINDOW = 10.0   # secondes
        self.RATE_LIMIT_MAX = 20        # requêtes max
    
    def is_bot_request(self, user_agent: Optional[str] = None) -> bool:
        """
        Détecte si la requête vient d'un bot.
        Logique pure - user_agent injecté ou via Flask request.
        """
        if user_agent is None:
            user_agent = request.headers.get("User-Agent", "") if request else ""
        
        is_bot = bool(self._bot_regex.search(user_agent))
        if is_bot:
            logger.warning(f"Bot détecté: {user_agent}")
        
        return is_bot
    
    def check_rate_limit(self, client_ip: Optional[str] = None) -> bool:
        """
        Vérifie le rate limiting.
        Logique pure - client_ip injecté ou via Flask request.
        """
        if client_ip is None:
            client_ip = self._get_client_ip() if request else "unknown"
        
        now = time.monotonic()
        
        if client_ip not in self._request_log:
            self._request_log[client_ip] = []
        
        # Nettoyer les anciennes requêtes
        self._request_log[client_ip] = [
            t for t in self._request_log[client_ip] 
            if now - t <= self.RATE_LIMIT_WINDOW
        ]
        
        # Vérifier la limite
        if len(self._request_log[client_ip]) >= self.RATE_LIMIT_MAX:
            logger.warning(f"Rate limit dépassé pour {client_ip}")
            return False
        
        # Enregistrer la requête
        self._request_log[client_ip].append(now)
        return True
    
    def _get_client_ip(self) -> str:
        """Extrait l'IP client de la requête Flask."""
        return request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr) or "unknown"
    
    def get_stats(self) -> dict:
        """Retourne les statistiques de sécurité."""
        active_ips = len([ips for ips in self._request_log.values() if ips])
        total_requests = sum(len(ips) for ips in self._request_log.values())
        
        return {
            "active_ips": active_ips,
            "total_requests": total_requests,
            "rate_limit_window": self.RATE_LIMIT_WINDOW,
            "rate_limit_max": self.RATE_LIMIT_MAX
        }