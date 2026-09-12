"""
backend/services/correlation_engine.py
────────────────────────────────────────
Multi-Factor Risk-Weighted Security Event & Threat Correlation Engine.

Formula:
  Score = w_domain * S_domain + w_path * S_path + w_intel * S_intel + w_dedicated_ip * S_dedicated_ip

Weights:
  w_domain       = 0.40 (0.0 if registered_domain is known multi-tenant shared infrastructure)
  w_path         = 0.25
  w_intel        = 0.25
  w_dedicated_ip = 0.10

Threshold: 0.65
Time Window: 24 hours
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import Alert
from backend.schemas.soc import SecurityEventSchema
from backend.utils.domain import normalize_canonical_domain
from src.utils.logger import logger

CORRELATION_WEIGHT_DOMAIN = 0.40
CORRELATION_WEIGHT_PATH = 0.25
CORRELATION_WEIGHT_INTEL = 0.25
CORRELATION_WEIGHT_DEDICATED_IP = 0.10
CORRELATION_THRESHOLD = 0.65
CORRELATION_WINDOW_HOURS = 24


class CorrelationResult:

    def __init__(
        self,
        score: float,
        is_correlated: bool,
        matching_alert_ids: list[int],
        matched_indicators: list[str],
        details: dict[str, Any],
    ):
        self.score = score
        self.is_correlated = is_correlated
        self.matching_alert_ids = matching_alert_ids
        self.matched_indicators = matched_indicators
        self.details = details


class CorrelationEngine:
    """Multi-factor event & alert correlation service."""

    def compute_correlation_score(
        self,
        event_norm: dict[str, Any],
        candidate_norm: dict[str, Any],
        event_has_intel: bool = False,
        candidate_has_intel: bool = False,
    ) -> float:
        """Calculate the multi-factor risk score between two event/alert indicators."""
        score = 0.0

        # 1. Domain Score (0.40) - Skipped if shared multi-tenant infra
        if (
            not event_norm.get("is_shared_infra")
            and not candidate_norm.get("is_shared_infra")
            and event_norm.get("registered_domain")
            and candidate_norm.get("registered_domain")
            and event_norm.get("registered_domain") == candidate_norm.get("registered_domain")
        ):
            score += CORRELATION_WEIGHT_DOMAIN

        # 2. Path Score (0.25)
        if (
            event_norm.get("path") != "/"
            and candidate_norm.get("path") != "/"
            and event_norm.get("path") == candidate_norm.get("path")
        ):
            score += CORRELATION_WEIGHT_PATH

        # 3. Threat Intel Match (0.25)
        if event_has_intel and candidate_has_intel:
            score += CORRELATION_WEIGHT_INTEL

        # 4. Dedicated IP Match (0.10)
        if (
            event_norm.get("is_ip")
            and candidate_norm.get("is_ip")
            and event_norm.get("registered_domain") == candidate_norm.get("registered_domain")
        ):
            score += CORRELATION_WEIGHT_DEDICATED_IP

        return round(score, 4)

    def correlate_event(
        self,
        session: Session,
        event: SecurityEventSchema,
    ) -> CorrelationResult:
        """
        Correlate an incoming SecurityEvent against existing Alerts created in the past 24 hours.

        Enforces parameterized queries, user scoping, and time window bounds.
        Fails safely on any query error.
        """
        try:
            event_norm = normalize_canonical_domain(event.indicator_value)
            window_start = datetime.now(timezone.utc) - timedelta(hours=CORRELATION_WINDOW_HOURS)

            # Query recent alerts in the 24h window for the same user or system scope
            stmt = select(Alert).where(
                Alert.first_seen_at >= window_start,
            )

            if event.user_id is not None:
                stmt = stmt.where(Alert.user_id == event.user_id)
            else:
                stmt = stmt.where(Alert.user_id.is_(None))

            stmt = stmt.order_by(Alert.last_seen_at.desc()).limit(100)
            recent_alerts = session.scalars(stmt).all()

            best_score = 0.0
            matching_ids: list[int] = []
            matched_indicators: list[str] = []

            event_has_intel = event.event_type.value in (
                "ZERO_DAY_DETECTED",
                "HIGH_RISK_ENRICHMENT",
            ) or bool(event.payload.get("has_intel"))

            for alert in recent_alerts:
                cand_norm = normalize_canonical_domain(alert.indicator_value)
                cand_has_intel = alert.rule_name in (
                    "ZERO_DAY_INGESTION",
                    "HIGH_RISK_ENRICHMENT",
                )

                score = self.compute_correlation_score(
                    event_norm=event_norm,
                    candidate_norm=cand_norm,
                    event_has_intel=event_has_intel,
                    candidate_has_intel=cand_has_intel,
                )

                if score > best_score:
                    best_score = score

                if score >= CORRELATION_THRESHOLD:
                    matching_ids.append(alert.id)
                    matched_indicators.append(alert.indicator_value)

            is_correlated = best_score >= CORRELATION_THRESHOLD

            return CorrelationResult(
                score=best_score,
                is_correlated=is_correlated,
                matching_alert_ids=matching_ids,
                matched_indicators=matched_indicators,
                details={
                    "event_indicator": event.indicator_value,
                    "normalized_domain": event_norm.get("registered_domain"),
                    "is_shared_infra": event_norm.get("is_shared_infra"),
                    "candidates_evaluated": len(recent_alerts),
                },
            )

        except Exception as exc:
            logger.error("[CORRELATION_ENGINE] Correlation evaluation failed safely: %s", exc)
            return CorrelationResult(
                score=0.0,
                is_correlated=False,
                matching_alert_ids=[],
                matched_indicators=[],
                details={"error": str(exc)},
            )


correlation_engine = CorrelationEngine()
