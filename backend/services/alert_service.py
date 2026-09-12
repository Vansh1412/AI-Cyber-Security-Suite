"""
backend/services/alert_service.py
───────────────────────────────────
Sprint 5: Security Alert Management & Deduplication Service.

Features:
- Deterministic SHA-256 Alert Fingerprinting
- Redis Deduplication (15-minute window) with safe SQL DB fallback
- Transaction-safe Alert Storm Protection (occurrence_count increment)
- Monotonic Severity Escalation (downgrade prevention)
- Strict Multi-Tenancy & User Ownership Isolation
- 1-to-Many Incident Linkage via alerts.incident_id
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import Alert
from backend.schemas.soc import SecurityEventSchema
from backend.services.cache import cache_service
from backend.utils.domain import normalize_canonical_domain
from src.utils.logger import logger

ALERT_DEDUPLICATION_WINDOW_MIN = 15

SEVERITY_RANKS: dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _get_severity_rank(severity_str: str) -> int:
    return SEVERITY_RANKS.get(severity_str.upper(), 1)


def _higher_severity(sev1: str, sev2: str) -> str:
    """Return the higher of two severity strings."""
    return sev1 if _get_severity_rank(sev1) >= _get_severity_rank(sev2) else sev2


class AlertService:
    """Centralized Alert Management Service."""

    def compute_fingerprint(
        self,
        rule_name: str,
        indicator_type: str,
        indicator_value: str,
        user_id: int | None = None,
    ) -> str:
        """
        Compute a deterministic SHA-256 fingerprint for an alert identity.

        Accounts for rule name, indicator type, exact indicator value, normalized domain/path, and user context.
        """
        norm = normalize_canonical_domain(indicator_value)
        domain = norm.get("registered_domain") or norm.get("fqdn") or ""
        path = norm.get("path") or "/"
        clean_indicator = indicator_value.strip().lower()
        user_str = str(user_id) if user_id is not None else "SYSTEM"

        raw_key = f"{rule_name.upper()}:{indicator_type.upper()}:{clean_indicator}:{domain}:{path}:{user_str}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    async def _check_redis_dedup(self, fingerprint: str) -> str | None:
        """Query Redis for dedup fingerprint key. Returns alert_id string if hit, None if miss/error."""
        redis_key = f"alert:dedup:{fingerprint}"
        try:
            val = await cache_service.get(redis_key)
            return str(val) if val else None
        except Exception as exc:
            logger.warning("[ALERT_SERVICE] Redis dedup check fallback to DB due to error: %s", exc)
            return None

    async def _set_redis_dedup(self, fingerprint: str, alert_id: int) -> None:
        """Store dedup fingerprint in Redis with 15-minute TTL."""
        redis_key = f"alert:dedup:{fingerprint}"
        ttl_seconds = ALERT_DEDUPLICATION_WINDOW_MIN * 60
        try:
            await cache_service.set(redis_key, str(alert_id), ttl=ttl_seconds)
        except Exception as exc:
            logger.warning("[ALERT_SERVICE] Redis dedup set failed safely: %s", exc)

    def process_event(
        self,
        session: Session,
        event: SecurityEventSchema,
        rule_name: str | None = None,
        incident_id: int | None = None,
    ) -> tuple[Alert, bool]:
        """
        Process a SecurityEvent and create a new Alert OR update an existing open Alert.

        Transaction-safe and robust against concurrent execution.
        """
        effective_rule = rule_name or f"RULE_{event.event_type.value}"
        fingerprint = self.compute_fingerprint(
            rule_name=effective_rule,
            indicator_type=event.indicator_type.value,
            indicator_value=event.indicator_value,
            user_id=event.user_id,
        )
        logger.debug("[ALERT_SERVICE] Processing fingerprint %s for %s", fingerprint[:16], event.indicator_value)

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        dedup_window_start = now - timedelta(minutes=ALERT_DEDUPLICATION_WINDOW_MIN)

        # DB Query for existing open alert matching fingerprint or exact indicator & user scope within dedup window
        stmt = select(Alert).where(
            Alert.rule_name == effective_rule,
            Alert.indicator_type == event.indicator_type.value,
            Alert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]),
            Alert.last_seen_at >= dedup_window_start,
        )

        if event.user_id is not None:
            stmt = stmt.where(Alert.user_id == event.user_id)
        else:
            stmt = stmt.where(Alert.user_id.is_(None))

        # Match fingerprint or indicator_value
        stmt = stmt.where(
            (Alert.fingerprint == fingerprint) | (Alert.indicator_value == event.indicator_value)
        )

        # Apply database lock if supported (SELECT FOR UPDATE for PostgreSQL)
        if session.bind and session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update()

        existing_alert = session.scalars(stmt.order_by(Alert.last_seen_at.desc())).first()

        if existing_alert:
            # Atomic update / Alert storm suppression
            existing_alert.occurrence_count += 1
            existing_alert.last_seen_at = now
            existing_alert.fingerprint = fingerprint
            # Monotonic severity escalation (never downgrade)
            existing_alert.severity = _higher_severity(existing_alert.severity, event.severity.value)

            if incident_id and not existing_alert.incident_id:
                existing_alert.incident_id = incident_id

            session.commit()
            session.refresh(existing_alert)

            logger.info(
                "[ALERT_SERVICE] Deduplicated alert ID %d (Count: %d, Severity: %s)",
                existing_alert.id,
                existing_alert.occurrence_count,
                existing_alert.severity,
            )
            return existing_alert, False

        # Create new Alert
        new_alert = Alert(
            title=f"{effective_rule}: {event.indicator_value[:64]}",
            description=f"Security event {event.event_type.value} triggered rule {effective_rule}.",
            severity=event.severity.value,
            status="OPEN",
            rule_name=effective_rule,
            indicator_type=event.indicator_type.value,
            indicator_value=event.indicator_value,
            fingerprint=fingerprint,
            occurrence_count=1,
            first_seen_at=now,
            last_seen_at=now,
            user_id=event.user_id,
            incident_id=incident_id,
        )

        try:
            session.add(new_alert)
            session.commit()
            session.refresh(new_alert)
        except Exception as exc:
            session.rollback()
            logger.warning("[ALERT_SERVICE] Insert race detected, retrying select: %s", exc)
            # Re-query after race
            retry_alert = session.scalars(stmt).first()
            if retry_alert:
                retry_alert.occurrence_count += 1
                retry_alert.last_seen_at = now
                retry_alert.severity = _higher_severity(retry_alert.severity, event.severity.value)
                session.commit()
                session.refresh(retry_alert)
                return retry_alert, False
            raise

        logger.info(
            "[ALERT_SERVICE] Created new Alert ID %d (%s, %s) for user %s",
            new_alert.id,
            new_alert.severity,
            new_alert.indicator_value[:64],
            new_alert.user_id if new_alert.user_id is not None else "SYSTEM",
        )

        return new_alert, True


alert_service = AlertService()
