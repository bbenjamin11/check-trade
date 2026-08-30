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
    # Solde cash REEL recupere directement via l'API TR (pas un calcul local).
    # None si la recuperation a echoue (non bloquant, la sync reste valide).
    cash_amount: Optional[str] = None
    cash_currency: Optional[str] = None
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
            timeline_events, portfolio_count, latest_iso, cash_amount, cash_currency = asyncio.run(
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

        # Conversion au format Releve.csv (1 event peut donner 0, 1 ou 2 lignes)
        new_rows = []
        dropped_count = 0
        for evt in timeline_events:
            rows = self._event_to_csv_rows(evt)
            if rows:
                new_rows.extend(rows)
            else:
                dropped_count += 1

        from parser import (
            ecrire_csv,
            lire_releve_csv,
            _normalize_row_width,
            _DedupTracker,
            _date_sort_key,
            reappliquer_categories_csv,
        )

        existing = [_normalize_row_width(r) for r in lire_releve_csv(csv_path)]
        tracker = _DedupTracker()
        for r in existing:
            tracker.add(r)

        added = 0
        skipped = 0
        for row in new_rows:
            row = _normalize_row_width(row)
            if tracker.is_duplicate(row):
                skipped += 1
                continue
            tracker.add(row)
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
            cash_amount=cash_amount,
            cash_currency=cash_currency,
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
    ) -> tuple[list[dict], int, Optional[str], Optional[str], Optional[str]]:
        portfolio_positions = 0
        latest_iso: Optional[str] = None
        cash_amount: Optional[str] = None
        cash_currency: Optional[str] = None

        try:
            # --- 1. timelineTransactions ---
            await api.timeline_transactions()
            tx_events, latest_iso_tx = await self._collect_paginated_until(
                api, "timelineTransactions", not_before_iso=not_before_iso
            )
            logger.info("timelineTransactions : %d events", len(tx_events))

            # --- 2. timelineActivityLog (saveback credits, rewards, etc.) ---
            activity_events: list[dict] = []
            latest_iso_act: Optional[str] = None
            try:
                await api.timeline_activity_log()
                activity_events, latest_iso_act = await self._collect_paginated_until(
                    api, "timelineActivityLog", not_before_iso=not_before_iso
                )
                logger.info("timelineActivityLog : %d events", len(activity_events))
            except Exception as e:
                logger.warning("timelineActivityLog KO (non bloquant) : %s", type(e).__name__)

            # --- Fusion par ID (dedup) ---
            seen_ids: set[str] = set()
            events: list[dict] = []
            for evt in tx_events:
                eid = evt.get("id") if isinstance(evt, dict) else None
                if eid and eid not in seen_ids:
                    seen_ids.add(eid)
                    events.append(evt)
                elif not eid:
                    events.append(evt)

            activity_only = 0
            for evt in activity_events:
                eid = evt.get("id") if isinstance(evt, dict) else None
                if eid and eid not in seen_ids:
                    seen_ids.add(eid)
                    events.append(evt)
                    activity_only += 1
                elif not eid:
                    events.append(evt)
                    activity_only += 1

            logger.info(
                "Fusion : %d tx + %d activity = %d total (%d uniquement dans activity)",
                len(tx_events), len(activity_events), len(events), activity_only,
            )

            # latest_iso = le plus recent des deux
            candidates = [t for t in [latest_iso_tx, latest_iso_act] if t is not None]
            latest_iso = max(candidates) if candidates else None

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

            # --- Solde cash reel (type "cash", cf. pytr) ---
            try:
                await api.cash()
                _, _, cash_resp = await asyncio.wait_for(api.recv(), timeout=10)
                if isinstance(cash_resp, list) and cash_resp:
                    first = cash_resp[0]
                    cash_amount = str(first.get("amount")) if first.get("amount") is not None else None
                    cash_currency = first.get("currencyId")
                logger.info("TR cash : %s %s", cash_amount, cash_currency)
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("TR cash KO (non bloquant) : %s", type(e).__name__)

        finally:
            try:
                await api.close()
            except Exception:
                pass

        return events, portfolio_positions, latest_iso, cash_amount, cash_currency

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
                logger.warning("Timeout recv() apres %d pages / %d items collectes", page_idx, len(all_items))
                break

            recv_type = subscription.get("type") if isinstance(subscription, dict) else repr(subscription)
            logger.debug(
                "[PAGE %d] recv type=%r expected=%r items_so_far=%d",
                page_idx, recv_type, expected_type, len(all_items),
            )

            if recv_type != expected_type:
                logger.warning(
                    "[PAGE %d] TYPE INATTENDU ignore : %r (attendu=%r). "
                    "Subscription complete : %r | Response keys : %s",
                    page_idx, recv_type, expected_type,
                    subscription, list(response.keys()) if isinstance(response, dict) else repr(response),
                )
                continue

            items = response.get("items") or []
            logger.debug("[PAGE %d] %d items recus", page_idx, len(items))
            stop_pagination = False

            for item_idx, evt in enumerate(items):
                ts = evt.get("timestamp") if isinstance(evt, dict) else None
                if not isinstance(ts, str):
                    logger.warning(
                        "[PAGE %d / item %d] timestamp ignoré : valeur=%r type=%s | evt keys=%s",
                        page_idx, item_idx, ts, type(ts).__name__,
                        list(evt.keys()) if isinstance(evt, dict) else repr(evt),
                    )
                    continue

                if latest_iso is None or ts > latest_iso:
                    latest_iso = ts

                if not_before_iso is not None and ts <= not_before_iso:
                    logger.info(
                        "Sync incrementale : stop page=%d item=%d, event ts=%s <= not_before=%s",
                        page_idx, item_idx, ts, not_before_iso,
                    )
                    stop_pagination = True
                    break

                logger.debug(
                    "[PAGE %d / item %d] GARDE ts=%s eventType=%r title=%r amount=%r",
                    page_idx, item_idx, ts,
                    evt.get("eventType"), evt.get("title"), evt.get("amount"),
                )
                all_items.append(evt)

            logger.info(
                "[PAGE %d] traitement fini : %d items page, %d total collectes, stop=%s",
                page_idx, len(items), len(all_items), stop_pagination,
            )

            if stop_pagination:
                break

            cursor = (response.get("cursors") or {}).get("after")
            if not cursor:
                logger.info("[PAGE %d] Pas de curseur 'after' -> fin pagination", page_idx)
                break

            if expected_type == "timelineTransactions":
                await api.timeline_transactions(after=cursor)
            elif expected_type == "timelineActivityLog":
                await api.timeline_activity_log(after=cursor)
            else:
                logger.warning("Pagination non geree pour type=%s", expected_type)
                break

        logger.info(
            "_collect_paginated_until TERMINE : %d items total, latest_iso=%s",
            len(all_items), latest_iso,
        )
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
    # CONVERSION EVENT -> LIGNE(S) Releve.csv
    # ============================================================

    @staticmethod
    def _event_to_csv_rows(evt: dict) -> list[list[str]]:
        """
        Convertit un event TR en 0, 1 ou 2 lignes Releve.csv.
        Format ligne : [DATE, TYPE, MONEY IN, MONEY OUT, BALANCE, DESCRIPTION, MERCHANT, CATEGORY]

        Cas spécial SAVEBACK_AGGREGATE : génère 2 lignes
          1) Saveback credit  +amt  (TR t'offre l'argent)
          2) Saveback buy     -amt  (cet argent achète des actions)
        Logique identique à pytr/transactions.py ConditionalEventType.SAVEBACK.
        """
        if not isinstance(evt, dict):
            return []

        ts_raw = evt.get("timestamp")
        if not ts_raw:
            return []
        try:
            dt = datetime.fromisoformat(ts_raw[:19])
        except (TypeError, ValueError):
            return []

        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        date_str = f"{dt.day} {months[dt.month - 1]} {dt.year}"

        amount = evt.get("amount") or {}
        if isinstance(amount, dict):
            try:
                amt_value = float(amount.get("value", 0))
            except (TypeError, ValueError):
                return []
        else:
            try:
                amt_value = float(amount)
            except (TypeError, ValueError):
                return []

        if amt_value == 0:
            return []

        title = (evt.get("title") or "").strip()
        subtitle = (evt.get("subtitle") or "").replace("\n", " ").strip()
        description = f"{title} {subtitle}".strip()
        event_type = evt.get("eventType") or ""
        eid = str(evt.get("id") or "").strip()

        def _fmt(v: float) -> str:
            return f"€{abs(v):.2f}".replace(".", ",")

        # --- Cas SAVEBACK_AGGREGATE : 2 lignes (credit + buy) ---
        # IMPORTANT : chaque sous-ligne recoit un TR_ID distinct (suffixe) sinon
        # la dedup id-based les traiterait comme un seul et meme doublon.
        if event_type == "SAVEBACK_AGGREGATE":
            # Ligne 1 : crédit TR → money_in
            credit_row = [
                date_str, "Saveback",
                _fmt(abs(amt_value)), "",  # money_in
                "", f"Saveback credit {description}".strip(), "", "",
                f"{eid}:credit" if eid else "",
            ]
            # Ligne 2 : investissement → money_out
            invest_row = [
                date_str, "Saveback",
                "", _fmt(abs(amt_value)),  # money_out
                "", f"Saveback invest {description}".strip(), "", "",
                f"{eid}:invest" if eid else "",
            ]
            return [credit_row, invest_row]

        # --- Cas général ---
        money_in = ""
        money_out = ""
        if amt_value > 0:
            money_in = _fmt(amt_value)
        else:
            money_out = _fmt(amt_value)

        tr_type = TRSyncService._infer_type(event_type, title, subtitle)

        return [[date_str, tr_type, money_in, money_out, "", description, "", "", eid]]

    @staticmethod
    def _event_to_csv_row(evt: dict) -> Optional[list[str]]:
        """Rétro-compat : retourne la première ligne uniquement (utilisé par le debug)."""
        rows = TRSyncService._event_to_csv_rows(evt)
        return rows[0] if rows else None

    # Mapping explicite des eventTypes connus -> type CSV
    # Basé sur pytr/event.py PPEventType mapping
    _EVENT_TYPE_MAP: dict[str, str] = {
        # Dépôts
        "PAYMENT_INBOUND":                      "Deposit",
        "PAYMENT_INBOUND_APPLE_PAY":            "Deposit",
        "PAYMENT_INBOUND_GOOGLE_PAY":           "Deposit",
        "PAYMENT_INBOUND_SEPA_DIRECT_DEBIT":    "Deposit",
        "PAYMENT_INBOUND_CREDIT_CARD":          "Deposit",
        "BANK_TRANSACTION_INCOMING":            "Deposit",
        "CARD_REFUND":                          "Deposit",    # remboursement carte
        # Retraits
        "PAYMENT_OUTBOUND":                     "Withdrawal",
        "OUTGOING_TRANSFER":                    "Withdrawal",
        "OUTGOING_TRANSFER_DELEGATION":         "Withdrawal",
        # Carte
        "CARD_TRANSACTION":                     "Card payment",
        "CARD_VERIFICATION":                    "Card payment",
        # Intérêts
        "INTEREST_PAYOUT":                      "Interest",
        "INTEREST_PAYOUT_CREATED":              "Interest",
        # Dividendes / revenus
        "DIVIDEND":                             "Dividend",
        "CREDIT":                               "Dividend",
        "SSP_CORPORATE_ACTION_CASH":            "Dividend",
        # Plans d'épargne
        "SAVINGS_PLAN_EXECUTED":                "SavingsPlan",
        "SAVINGS_PLAN_INVOICE_CREATED":         "SavingsPlan",
        "TRADING_SAVINGSPLAN_EXECUTED":         "SavingsPlan",
        # Saveback / rewards
        "SAVEBACK_AGGREGATE":                   "Saveback",
        "ACQUISITION_TRADE_PERK":               "Saveback",
        "benefits_saveback_execution":          "Saveback",
        "CASH_PERK":                            "Reward",
        # Taxes
        "TAX_CORRECTION":                       "Tax refund",
        "TAX_REFUND":                           "Tax refund",
        # Marchés privés
        "PRIVATE_MARKET_FUND_TRADE_EXECUTED":   "Buy",
        # Trades
        "TRADE_INVOICE":                        "Trade",
    }

    @staticmethod
    def _infer_type(event_type: str, title: str, subtitle: str) -> str:
        # 1. Lookup exact dans le mapping
        et_raw = (event_type or "").strip()
        mapped = TRSyncService._EVENT_TYPE_MAP.get(et_raw)
        if mapped:
            return mapped

        # 2. Heuristiques sur eventType + texte (fallback)
        et = et_raw.lower()
        txt = (title + " " + subtitle).lower()

        if "card" in et or "card" in txt:
            return "Card payment"
        if "deposit" in et or "inbound" in et or "einzahlung" in txt or "deposit" in txt:
            return "Deposit"
        if "withdraw" in et or "outbound" in et or "auszahlung" in txt or "withdrawal" in txt:
            return "Withdrawal"
        if "dividend" in et or "dividend" in txt or "dividende" in txt:
            return "Dividend"
        if "interest" in et or "zins" in txt or "interest" in txt:
            return "Interest"
        if "saving" in et or "sparplan" in txt:
            return "SavingsPlan"
        if "saveback" in et or "saveback" in txt:
            return "Saveback"
        if "reward" in et or "reward" in txt or "bonus" in txt or "perk" in et:
            return "Reward"
        if "round" in et or "round" in txt:
            return "RoundUp"
        if "buy" in et or "kauf" in txt or "purchase" in txt:
            return "Buy"
        if "sell" in et or "verkauf" in txt:
            return "Sell"
        if "fee" in et or "gebühr" in txt or "fee" in txt:
            return "Fee"
        if "tax" in et or "steuer" in txt:
            return "Tax refund"
        return "Transfer"
