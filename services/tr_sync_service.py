#!/usr/bin/env python3
"""
TR Sync Service - Synchronisation Trade Republic en 2 etapes.

Flow :
    1. initiate(creds) -> (api, countdown_sec)
       - Cree TradeRepublicApi
       - Appelle initiate_weblogin() -> envoie un push a l'app TR mobile
       - Retourne l'instance + le delai avant expiration du code

    2. complete_and_sync(api, code, csv_path, user_known_merchants)
        - Appelle complete_weblogin(code) -> session WebSocket pretе
        - Pull la timeline complete via WebSocket (asyncio)
        - Convertit au format Releve.csv
        - Fusionne dans csv_path
        - Retourne SyncResult

ZERO PERSISTANCE des creds. L'instance pytr vit en RAM le temps des 2 requetes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from services.credentials_service import TRCredentials

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Resultat d'une sync. Aucun champ sensible."""
    added: int
    skipped: int
    total: int
    portfolio_lines: int
    # ISO timestamp de l'event le plus recent rencontre (pour la prochaine sync incrementale).
    # None si aucun event recu.
    latest_event_iso: Optional[str] = None
    # True si on a fait une sync complete (pas de filtre date), False sinon
    was_full_sync: bool = True
    error: Optional[str] = None
    # Stats de debug (remplies si debug_csv_dir est fourni)
    debug_raw_events: int = 0
    debug_parsed_rows: int = 0
    debug_dropped: int = 0
    debug_drop_reasons: Optional[dict] = None


@dataclass
class InitResult:
    """Retour de initiate_weblogin (sans le PIN/phone)."""
    api: object  # TradeRepublicApi
    countdown_seconds: int  # delai avant expiration du code


class TRSyncService:
    """Service stateless. Aucun etat conserve entre appels."""

    # ============================================================
    # ETAPE 1 - INITIATE
    # ============================================================

    def initiate(self, creds: TRCredentials) -> InitResult:
        try:
            from pytr.api import TradeRepublicApi
        except ImportError:
            raise RuntimeError(
                "pytr n'est pas installe. Lance : pip install pytr playwright "
                "&& playwright install chromium"
            ) from None

        logger.info("TR initiate (creds=%r)", creds)

        api = TradeRepublicApi(
            phone_no=creds.phone,
            pin=creds.pin,
            save_cookies=False,
            waf_token="playwright",
        )

        try:
            countdown = api.initiate_weblogin()
        except Exception as e:
            logger.error("TR initiate KO : %s", type(e).__name__)
            raise RuntimeError(
                f"Initiate Trade Republic echoue ({type(e).__name__})"
            ) from None

        logger.info("TR initiate OK, countdown=%ds", countdown)
        return InitResult(api=api, countdown_seconds=int(countdown))

    # ============================================================
    # ETAPE 2 - COMPLETE + SYNC
    # ============================================================

    def complete_and_sync(
        self,
        api,
        verify_code: str,
        csv_path: Path,
        user_known_merchants: Optional[dict] = None,
        not_before_iso: Optional[str] = None,
        debug_csv_dir: Optional[Path] = None,
    ) -> SyncResult:
        """
        Termine le login avec le code recu sur l'app TR mobile,
        puis fait la sync.

        Args:
            not_before_iso: si fourni, on arrete la pagination des qu'on rencontre
                un event plus ancien. None = sync complete (premiere fois).
            debug_csv_dir: si fourni, sauvegarde dans ce dossier :
                - tr_raw_events.csv   : tous les events bruts recus de l'API
                - tr_parse_report.csv : rapport event par event (garde/supprime + raison)
        """
        if not verify_code or not verify_code.isdigit():
            raise RuntimeError("Code de verification invalide")

        try:
            api.complete_weblogin(verify_code)
        except Exception as e:
            logger.error("TR complete_weblogin KO : %s", type(e).__name__)
            raise RuntimeError(
                f"Validation code Trade Republic echouee ({type(e).__name__})"
            ) from None

        logger.info("TR login complet, debut sync timeline")

        try:
            timeline_events, portfolio_count, latest_iso = asyncio.run(
                self._fetch_data_async(api, not_before_iso=not_before_iso)
            )
        except Exception as e:
            logger.error("TR fetch async KO : %s", type(e).__name__)
            raise RuntimeError(
                f"Recuperation des donnees TR echouee ({type(e).__name__})"
            ) from None

        # ---- DEBUG : sauvegarde des events bruts ----
        drop_reasons: dict[str, int] = {}
        if debug_csv_dir is not None:
            self._write_debug_csvs(timeline_events, debug_csv_dir, drop_reasons)

        # Conversion au format Releve.csv
        new_rows = [self._event_to_csv_row(evt) for evt in timeline_events]
        dropped_count = sum(1 for r in new_rows if r is None)
        new_rows = [r for r in new_rows if r is not None]

        from parser import (
            ecrire_csv,
            lire_releve_csv,
            _normalize_row_width,
            _transaction_dedup_key,
            _date_sort_key,
            reappliquer_categories_csv,
        )

        existing = [_normalize_row_width(r) for r in lire_releve_csv(csv_path)]
        seen = {_transaction_dedup_key(r) for r in existing}

        added = 0
        skipped = 0
        for row in new_rows:
            row = _normalize_row_width(row)
            key = _transaction_dedup_key(row)
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            existing.append(row)
            added += 1

        existing.sort(key=_date_sort_key)
        ecrire_csv(existing, csv_path)
        reappliquer_categories_csv(csv_path, user_known_merchants=user_known_merchants)

        logger.info(
            "TR sync done : +%d, %d doublons, total=%d, portfolio=%d | "
            "raw_events=%d parsed=%d dropped=%d",
            added, skipped, len(existing), portfolio_count,
            len(timeline_events), len(new_rows), dropped_count,
        )

        return SyncResult(
            added=added,
            skipped=skipped,
            total=len(existing),
            portfolio_lines=portfolio_count,
            latest_event_iso=latest_iso,
            was_full_sync=(not_before_iso is None),
            debug_raw_events=len(timeline_events),
            debug_parsed_rows=len(new_rows),
            debug_dropped=dropped_count,
            debug_drop_reasons=drop_reasons if drop_reasons else None,
        )

    # ============================================================
    # FETCH ASYNC (WebSocket)
    # ============================================================

    async def _fetch_data_async(
        self,
        api,
        not_before_iso: Optional[str] = None,
    ) -> tuple[list[dict], int, Optional[str]]:
        events: list[dict] = []
        portfolio_positions = 0
        latest_iso: Optional[str] = None

        try:
            await api.timeline_transactions()
            events, latest_iso = await self._collect_paginated_until(
                api, "timelineTransactions", not_before_iso=not_before_iso
            )

            try:
                await api.portfolio()
                _, _, portfolio_resp = await asyncio.wait_for(api.recv(), timeout=10)
                if isinstance(portfolio_resp, dict):
                    positions = (
                        portfolio_resp.get("positions")
                        or portfolio_resp.get("data")
                        or []
                    )
                    portfolio_positions = len(positions) if isinstance(positions, list) else 0
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("TR portfolio KO (non bloquant) : %s", type(e).__name__)

        finally:
            try:
                await api.close()
            except Exception:
                pass

        return events, portfolio_positions, latest_iso

    async def _collect_paginated_until(
        self,
        api,
        expected_type: str,
        not_before_iso: Optional[str] = None,
    ) -> tuple[list[dict], Optional[str]]:
        """
        Pagine la subscription jusqu'a epuisement ou rencontre d'un event
        plus ancien que not_before_iso (sync incrementale).

        IMPORTANT : la timeline TR est triee par date DESC (recent -> ancien).
        """
        all_items: list[dict] = []
        latest_iso: Optional[str] = None
        max_pages = 100

        for page_idx in range(max_pages):
            try:
                _, subscription, response = await asyncio.wait_for(
                    api.recv(), timeout=15
                )
            except asyncio.TimeoutError:
                logger.warning("Timeout recv() apres %d pages", len(all_items))
                break

            if subscription.get("type") != expected_type:
                continue

            items = response.get("items") or []
            stop_pagination = False

            for evt in items:
                ts = evt.get("timestamp") if isinstance(evt, dict) else None
                if not isinstance(ts, str):
                    continue

                if latest_iso is None or ts > latest_iso:
                    latest_iso = ts

                if not_before_iso is not None and ts <= not_before_iso:
                    logger.info(
                        "Sync incrementale : stop a la page %d, event ts=%s <= %s",
                        page_idx, ts, not_before_iso,
                    )
                    stop_pagination = True
                    break

                all_items.append(evt)

            if stop_pagination:
                break

            cursor = (response.get("cursors") or {}).get("after")
            if not cursor:
                break

            if expected_type == "timelineTransactions":
                await api.timeline_transactions(after=cursor)
            else:
                logger.warning("Pagination non geree pour type=%s", expected_type)
                break

        return all_items, latest_iso

    # ============================================================
    # DEBUG : EXPORT EVENTS BRUTS
    # ============================================================

    @staticmethod
    def _event_to_csv_row_debug(evt: dict) -> tuple[Optional[list[str]], str]:
        """
        Comme _event_to_csv_row mais retourne aussi la raison du drop.
        Retourne (row_ou_None, raison). raison="" si OK.
        """
        if not isinstance(evt, dict):
            return None, "not_a_dict"

        ts_raw = evt.get("timestamp")
        if not ts_raw:
            return None, "no_timestamp"
        try:
            dt = datetime.fromisoformat(ts_raw[:19])  # noqa: F841
        except (TypeError, ValueError):
            return None, "bad_timestamp_format"

        amount = evt.get("amount") or {}
        if isinstance(amount, dict):
            try:
                amt_value = float(amount.get("value", 0))
            except (TypeError, ValueError):
                return None, "amount_value_not_float"
        else:
            try:
                amt_value = float(amount)
            except (TypeError, ValueError):
                return None, "amount_not_float"

        if amt_value == 0:
            return None, "amount_zero"

        row = TRSyncService._event_to_csv_row(evt)
        if row is None:
            return None, "unknown_drop"
        return row, ""

    @staticmethod
    def _write_debug_csvs(
        events: list[dict],
        out_dir: Path,
        drop_reasons_out: dict,
    ) -> None:
        """
        Ecrit deux fichiers dans out_dir :
        - tr_raw_events.csv   : dump brut de chaque event API
        - tr_parse_report.csv : rapport GARDE/SUPPRIME + raison
        """
        import csv as _csv
        import json as _json

        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1. Fichier brut
        raw_path = out_dir / "tr_raw_events.csv"
        all_keys: list[str] = []
        seen_keys: set[str] = set()
        for evt in events:
            if isinstance(evt, dict):
                for k in evt.keys():
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_keys.append(k)

        with open(raw_path, "w", newline="", encoding="utf-8") as fh:
            writer = _csv.writer(fh, delimiter=";")
            writer.writerow(["#"] + all_keys)
            for i, evt in enumerate(events, 1):
                if not isinstance(evt, dict):
                    writer.writerow([i] + ["<non-dict>"] * len(all_keys))
                    continue
                row_out = [i]
                for k in all_keys:
                    val = evt.get(k, "")
                    if isinstance(val, (dict, list)):
                        val = _json.dumps(val, ensure_ascii=False)
                    row_out.append(val)
                writer.writerow(row_out)

        logger.info("DEBUG raw events -> %s (%d events)", raw_path, len(events))

        # 2. Rapport de parsing
        report_path = out_dir / "tr_parse_report.csv"
        headers = [
            "#", "TIMESTAMP", "EVENT_TYPE", "TITLE", "SUBTITLE",
            "AMOUNT_RAW", "STATUT", "RAISON_DROP",
            "DATE_PARSEE", "TYPE_INFERE", "MONEY_IN", "MONEY_OUT",
        ]
        drop_reasons_out.clear()

        with open(report_path, "w", newline="", encoding="utf-8") as fh:
            writer = _csv.writer(fh, delimiter=";")
            writer.writerow(headers)

            for i, evt in enumerate(events, 1):
                if not isinstance(evt, dict):
                    writer.writerow([i, "", "", "", "", "", "SUPPRIME", "not_a_dict",
                                     "", "", "", ""])
                    drop_reasons_out["not_a_dict"] = drop_reasons_out.get("not_a_dict", 0) + 1
                    continue

                ts = evt.get("timestamp", "")
                etype = evt.get("eventType", "")
                title = evt.get("title", "")
                subtitle = (evt.get("subtitle") or "").replace("\n", " ")
                amount_raw = _json.dumps(evt.get("amount", ""), ensure_ascii=False)

                row_parsed, reason = TRSyncService._event_to_csv_row_debug(evt)

                if row_parsed is not None:
                    statut = "GARDE"
                    date_p = row_parsed[0]
                    type_p = row_parsed[1]
                    min_p = row_parsed[2]
                    mout_p = row_parsed[3]
                else:
                    statut = "SUPPRIME"
                    date_p = type_p = min_p = mout_p = ""
                    drop_reasons_out[reason] = drop_reasons_out.get(reason, 0) + 1

                writer.writerow([
                    i, ts, etype, title, subtitle, amount_raw,
                    statut, reason,
                    date_p, type_p, min_p, mout_p,
                ])

        total = len(events)
        kept = total - sum(drop_reasons_out.values())
        logger.info(
            "DEBUG parse report : %d events, %d gardes, %d supprimes. Raisons: %s -> %s",
            total, kept, sum(drop_reasons_out.values()), drop_reasons_out, report_path,
        )

    # ============================================================
    # CONVERSION EVENT -> LIGNE Releve.csv
    # ============================================================

    @staticmethod
    def _event_to_csv_row(evt: dict) -> Optional[list[str]]:
        """
        Convertit un event timelineTransactions au format Releve.csv :
            [DATE, TYPE, MONEY IN, MONEY OUT, BALANCE, DESCRIPTION, MERCHANT, CATEGORY]
        """
        if not isinstance(evt, dict):
            return None

        ts_raw = evt.get("timestamp")
        if not ts_raw:
            return None
        try:
            dt = datetime.fromisoformat(ts_raw[:19])
        except (TypeError, ValueError):
            return None

        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        date_str = f"{dt.day} {months[dt.month - 1]} {dt.year}"

        amount = evt.get("amount") or {}
        if isinstance(amount, dict):
            try:
                amt_value = float(amount.get("value", 0))
            except (TypeError, ValueError):
                return None
        else:
            try:
                amt_value = float(amount)
            except (TypeError, ValueError):
                return None

        money_in = ""
        money_out = ""
        formatted = f"euro{abs(amt_value):.2f}".replace("euro", "€").replace(".", ",")
        if amt_value > 0:
            money_in = formatted
        elif amt_value < 0:
            money_out = formatted
        else:
            return None

        title = (evt.get("title") or "").strip()
        subtitle = (evt.get("subtitle") or "").replace("\n", " ").strip()
        description = f"{title} {subtitle}".strip()

        tr_type = TRSyncService._infer_type(
            evt.get("eventType") or "",
            title,
            subtitle,
        )

        return [
            date_str,
            tr_type,
            money_in,
            money_out,
            "",
            description,
            "",
            "",
        ]

    @staticmethod
    def _infer_type(event_type: str, title: str, subtitle: str) -> str:
        et = (event_type or "").lower()
        txt = (title + " " + subtitle).lower()

        if "card" in et or "card" in txt:
            return "Card payment"
        if "deposit" in et or "einzahlung" in txt or "deposit" in txt:
            return "Deposit"
        if "withdraw" in et or "auszahlung" in txt or "withdrawal" in txt:
            return "Withdrawal"
        if "dividend" in et or "dividend" in txt or "dividende" in txt:
            return "Dividend"
        if "interest" in et or "zins" in txt or "interest" in txt:
            return "Interest"
        if "saving" in et or "sparplan" in txt:
            return "SavingsPlan"
        if "saveback" in et or "saveback" in txt:
            return "Saveback"
        if "round" in et or "round" in txt:
            return "RoundUp"
        if "buy" in et or "kauf" in txt or "purchase" in txt:
            return "Buy"
        if "sell" in et or "verkauf" in txt:
            return "Sell"
        if "fee" in et or "gebühr" in txt or "fee" in txt:
            return "Fee"
        return "Transfer"
