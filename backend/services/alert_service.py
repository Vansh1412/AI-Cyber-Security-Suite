"""
backend/services/alert_service.py
───────────────────────────────────
Sprint 5 Phase 5C: Security Alert Management, Triage & Deduplication Service.

Features:
- Deterministic SHA-256 Alert Fingerprinting
- Redis Deduplication (15-minute window) with safe SQL DB fallback
- Transaction-safe Alert Storm Protection (occurrence_count increment)
- Monotonic Severity Escalation (downgrade prevention)
- Strict Multi-Tenancy & User Ownership Isolation
- Authoritative 4-state Alert Triage Lifecycle (OPEN, ACKNOWLEDGED, RESOLVED, DISMISSED)
- Idempotent self-transitions with zero audit log pollution
- Recurrence handling: new qualifying event on terminal alerts creates fresh OPEN alert
- Decoupled from IncidentService (alert triage never mutates incidents)
- Bounded 24-hour Telemetry & Deduplication Savings Ratio
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from backend.database.models import Alert, AuditEvent, Notification, SOCEventStream, User
from backend.schemas.alerts import (
    ALERT_STATUS_TRANSITIONS,
    AlertStatsResponse,
    AlertStatus,
)
from backend.schemas.soc import SecurityEventSchema
from backend.services.cache import cache_service
from backend.services.event_broadcaster import event_broadcaster
from backend.services.notification_service import notification_service
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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── SQLite Concurrency Synchronization Locks ──────────────────────────────────
_sqlite_alert_thread_locks: dict[int, threading.Lock] = {}
_sqlite_alert_thread_guard = threading.Lock()
_sqlite_alert_async_locks: dict[tuple[int, int], asyncio.Lock] = {}


def _get_sqlite_alert_thread_lock(user_id: int) -> threading.Lock:
    """Return a thread-safe threading.Lock for user_id on non-PostgreSQL engines."""
    with _sqlite_alert_thread_guard:
        if user_id not in _sqlite_alert_thread_locks:
            _sqlite_alert_thread_locks[user_id] = threading.Lock()
        return _sqlite_alert_thread_locks[user_id]


def _get_sqlite_alert_async_lock(user_id: int) -> asyncio.Lock:
    """Return an asyncio.Lock bound to current event loop for user_id."""
    try:
        loop = asyncio.get_running_loop()
        key = (id(loop), user_id)
        if key not in _sqlite_alert_async_locks:
            _sqlite_alert_async_locks[key] = asyncio.Lock()
        return _sqlite_alert_async_locks[key]
    except RuntimeError:
        return asyncio.Lock()


# ── Session Execution Helpers (AsyncSession | Session) ─────────────────────────

async def _execute(session: Session | AsyncSession, stmt: Any) -> Any:
    if isinstance(session, AsyncSession):
        return await session.execute(stmt)
    return session.execute(stmt)


async def _commit(session: Session | AsyncSession) -> None:
    if isinstance(session, AsyncSession):
        await session.commit()
    else:
        session.commit()


async def _rollback(session: Session | AsyncSession) -> None:
    if isinstance(session, AsyncSession):
        await session.rollback()
    else:
        session.rollback()


async def _flush(session: Session | AsyncSession) -> None:
    if isinstance(session, AsyncSession):
        await session.flush()
    else:
        session.flush()


async def _refresh(session: Session | AsyncSession, obj: Any) -> None:
    if isinstance(session, AsyncSession):
        await session.refresh(obj)
    else:
        session.refresh(obj)


# ── Domain Exceptions ──────────────────────────────────────────────────────────

class AlertServiceError(Exception):
    """Base exception for alert service errors."""
    pass


class AlertNotFoundError(AlertServiceError):
    """Raised when an alert is not found or inaccessible under tenant scope."""
    pass


class AlertAccessDeniedError(AlertServiceError):
    """Raised when an operation violates tenant boundaries."""
    pass


class AlertInvalidTransitionError(AlertServiceError):
    """Raised when an alert status transition violates the state machine."""
    pass


class AlertValidationError(AlertServiceError):
    """Raised when alert input parameters fail business validation."""
    pass


def _create_audit_event(
    session: Session | AsyncSession,
    action: str,
    actor_user_id: int | None,
    target_resource: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditEvent:
    """Emit an immutable audit event for an alert triage operation."""
    audit = AuditEvent(
        event_uuid=str(uuid.uuid4()),
        action=action,
        actor_user_id=actor_user_id,
        target_resource=target_resource,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        created_at=_utcnow(),
    )
    session.add(audit)
    return audit


class AlertService:
    """Centralized Alert Management & Triage Service."""

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
        Process a SecurityEvent and create a new Alert OR update an existing open/acknowledged Alert.

        Terminal alerts (RESOLVED or DISMISSED) are excluded from the candidate check, ensuring
        that threat recurrence creates a brand-new Alert entity without silent suppression.
        """
        effective_rule = rule_name or f"RULE_{event.event_type.value}"
        fingerprint = self.compute_fingerprint(
            rule_name=effective_rule,
            indicator_type=event.indicator_type.value,
            indicator_value=event.indicator_value,
            user_id=event.user_id,
        )
        logger.debug("[ALERT_SERVICE] Processing fingerprint %s for %s", fingerprint[:16], event.indicator_value)

        now = _utcnow()
        dedup_window_start = now - timedelta(minutes=ALERT_DEDUPLICATION_WINDOW_MIN)

        # Candidate query: strictly matches active (OPEN or ACKNOWLEDGED) alerts within dedup window
        stmt = select(Alert).where(
            Alert.rule_name == effective_rule,
            Alert.indicator_type == event.indicator_type.value,
            Alert.status.in_([AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value]),
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
            old_severity = existing_alert.severity
            new_severity = _higher_severity(old_severity, event.severity.value)
            is_escalation = _get_severity_rank(new_severity) > _get_severity_rank(old_severity)

            # Atomic update / Alert storm suppression
            existing_alert.occurrence_count += 1
            existing_alert.last_seen_at = now
            existing_alert.fingerprint = fingerprint
            # Monotonic severity escalation (never downgrade)
            existing_alert.severity = new_severity

            if incident_id and not existing_alert.incident_id:
                existing_alert.incident_id = incident_id

            notif_soc_event = None
            if is_escalation:
                notif_soc_event = notification_service.create_in_app_and_outbox_for_alert(
                    session, existing_alert, is_escalation=True, old_severity=old_severity
                )

            # Sprint 5 Phase 5E: Durable SOC Event Stream
            soc_event_payload = {
                "id": existing_alert.alert_uuid,
                "target_id": str(existing_alert.target_id) if getattr(existing_alert, "target_id", None) else None,
                "severity": existing_alert.severity,
                "status": existing_alert.status,
                "occurrence_count": existing_alert.occurrence_count,
                "is_escalation": is_escalation,
                "rule_name": existing_alert.rule_name,
                "indicator_value": existing_alert.indicator_value,
            }
            soc_event = SOCEventStream(
                event_id=str(uuid.uuid4()),
                tenant_id=existing_alert.user_id if existing_alert.user_id is not None else 0,
                channel="alerts",
                event_type="alert_updated",
                aggregate_id=existing_alert.alert_uuid,
                payload_json=soc_event_payload,
                created_at=now,
            )
            session.add(soc_event)

            session.flush()
            soc_cursor_id = soc_event.cursor_id or 0
            notif_cursor_id = notif_soc_event.cursor_id if notif_soc_event else 0

            session.commit()
            session.refresh(existing_alert)

            event_broadcaster.publish_event_nowait(
                event_type="alert_updated",
                channel="alerts",
                tenant_id=existing_alert.user_id if existing_alert.user_id is not None else 0,
                payload=soc_event_payload,
                aggregate_id=existing_alert.alert_uuid,
                cursor_id=soc_cursor_id,
            )
            if notif_soc_event and notif_cursor_id:
                event_broadcaster.publish_event_nowait(
                    event_type="notification_dispatched",
                    channel="notifications",
                    tenant_id=notif_soc_event.tenant_id,
                    payload=notif_soc_event.payload_json,
                    aggregate_id=notif_soc_event.aggregate_id,
                    cursor_id=notif_cursor_id,
                )

            logger.info(
                "[ALERT_SERVICE] Deduplicated alert ID %d (Count: %d, Severity: %s, Escalated: %s)",
                existing_alert.id,
                existing_alert.occurrence_count,
                existing_alert.severity,
                is_escalation,
            )
            return existing_alert, False

        # Create new Alert (also runs on recurrence when past alert was RESOLVED or DISMISSED)
        new_alert = Alert(
            title=f"{effective_rule}: {event.indicator_value[:64]}",
            description=f"Security event {event.event_type.value} triggered rule {effective_rule}.",
            severity=event.severity.value,
            status=AlertStatus.OPEN.value,
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
            notif_soc_event = notification_service.create_in_app_and_outbox_for_alert(
                session, new_alert, is_escalation=False
            )
            soc_event_payload = {
                "id": new_alert.alert_uuid,
                "target_id": str(new_alert.target_id) if getattr(new_alert, "target_id", None) else None,
                "severity": new_alert.severity,
                "status": new_alert.status,
                "rule_name": new_alert.rule_name,
                "indicator_type": new_alert.indicator_type,
                "indicator_value": new_alert.indicator_value,
                "occurrence_count": 1,
            }
            soc_event = SOCEventStream(
                event_id=str(uuid.uuid4()),
                tenant_id=new_alert.user_id if new_alert.user_id is not None else 0,
                channel="alerts",
                event_type="alert_created",
                aggregate_id=new_alert.alert_uuid,
                payload_json=soc_event_payload,
                created_at=now,
            )
            session.add(soc_event)

            session.flush()
            soc_cursor_id = soc_event.cursor_id or 0
            notif_cursor_id = notif_soc_event.cursor_id if notif_soc_event else 0

            session.commit()
            session.refresh(new_alert)

            event_broadcaster.publish_event_nowait(
                event_type="alert_created",
                channel="alerts",
                tenant_id=new_alert.user_id if new_alert.user_id is not None else 0,
                payload=soc_event_payload,
                aggregate_id=new_alert.alert_uuid,
                cursor_id=soc_cursor_id,
            )
            if notif_soc_event and notif_cursor_id:
                event_broadcaster.publish_event_nowait(
                    event_type="notification_dispatched",
                    channel="notifications",
                    tenant_id=notif_soc_event.tenant_id,
                    payload=notif_soc_event.payload_json,
                    aggregate_id=notif_soc_event.aggregate_id,
                    cursor_id=notif_cursor_id,
                )
        except Exception as exc:
            session.rollback()
            logger.warning("[ALERT_SERVICE] Insert race detected, retrying select: %s", exc)
            retry_alert = session.scalars(stmt).first()
            if retry_alert:
                retry_alert.occurrence_count += 1
                retry_alert.last_seen_at = now
                retry_alert.severity = _higher_severity(retry_alert.severity, event.severity.value)
                soc_event_payload = {
                    "id": retry_alert.alert_uuid,
                    "target_id": str(retry_alert.target_id) if getattr(retry_alert, "target_id", None) else None,
                    "severity": retry_alert.severity,
                    "status": retry_alert.status,
                    "occurrence_count": retry_alert.occurrence_count,
                    "rule_name": retry_alert.rule_name,
                    "indicator_value": retry_alert.indicator_value,
                }
                soc_event = SOCEventStream(
                    event_id=str(uuid.uuid4()),
                    tenant_id=retry_alert.user_id if retry_alert.user_id is not None else 0,
                    channel="alerts",
                    event_type="alert_updated",
                    aggregate_id=retry_alert.alert_uuid,
                    payload_json=soc_event_payload,
                    created_at=now,
                )
                session.add(soc_event)
                session.flush()
                retry_cursor_id = soc_event.cursor_id or 0
                session.commit()
                session.refresh(retry_alert)
                event_broadcaster.publish_event_nowait(
                    event_type="alert_updated",
                    channel="alerts",
                    tenant_id=retry_alert.user_id if retry_alert.user_id is not None else 0,
                    payload=soc_event_payload,
                    aggregate_id=retry_alert.alert_uuid,
                    cursor_id=retry_cursor_id,
                )
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

    # ── Phase 5C Triage Methods ───────────────────────────────────────────────

    async def list_alerts(
        self,
        session: Session | AsyncSession,
        current_user: User,
        page: int = 1,
        page_size: int = 20,
        severity: str | None = None,
        status: str | None = None,
        rule_name: str | None = None,
        indicator_type: str | None = None,
        incident_id: int | None = None,
    ) -> dict[str, Any]:
        """List alerts filtered by criteria and strictly scoped to current tenant (or global for admin)."""
        is_admin = getattr(current_user, "role", "user") == "admin"
        query = select(Alert)

        if not is_admin:
            query = query.where(Alert.user_id == current_user.id)

        if severity:
            query = query.where(Alert.severity == severity.upper().strip())
        if status:
            query = query.where(Alert.status == status.upper().strip())
        if rule_name:
            query = query.where(Alert.rule_name == rule_name.strip())
        if indicator_type:
            query = query.where(Alert.indicator_type == indicator_type.upper().strip())
        if incident_id is not None:
            query = query.where(Alert.incident_id == incident_id)

        total_stmt = select(func.count()).select_from(query.subquery())
        total_res = await _execute(session, total_stmt)
        total = total_res.scalar() or 0

        offset = max(0, (page - 1) * page_size)
        items_stmt = query.order_by(Alert.last_seen_at.desc()).offset(offset).limit(page_size)
        items_res = await _execute(session, items_stmt)
        items = list(items_res.scalars().all())

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_next": (page * page_size) < total,
        }

    async def get_alert_by_uuid(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
    ) -> Alert:
        """Retrieve single alert detail by UUID. Non-admins cannot view other tenants' alerts (HTTP 404)."""
        is_admin = getattr(current_user, "role", "user") == "admin"
        stmt = select(Alert).where(Alert.alert_uuid == alert_uuid.strip())
        if not is_admin:
            stmt = stmt.where(Alert.user_id == current_user.id)

        res = await _execute(session, stmt)
        alert = res.scalars().first()
        if not alert:
            raise AlertNotFoundError(f"Alert '{alert_uuid}' not found.")
        return alert

    async def _lock_and_get_alert(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
    ) -> Alert:
        """Fetch alert with pessimistic row-level locking (Postgres) or session lock."""
        is_admin = getattr(current_user, "role", "user") == "admin"
        stmt = select(Alert).where(Alert.alert_uuid == alert_uuid.strip())
        if not is_admin:
            stmt = stmt.where(Alert.user_id == current_user.id)

        bind = getattr(session, "bind", None)
        if bind and getattr(bind.dialect, "name", "") == "postgresql":
            stmt = stmt.with_for_update()

        res = await _execute(session, stmt)
        alert = res.scalars().first()
        if not alert:
            raise AlertNotFoundError(f"Alert '{alert_uuid}' not found.")
        return alert

    async def acknowledge_alert(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        notes: str | None = None,
        triage_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        """Acknowledge an alert (OPEN -> ACKNOWLEDGED). Idempotent if already acknowledged."""
        tenant_key = current_user.id if getattr(current_user, "id", None) else 0
        if isinstance(session, AsyncSession):
            async with _get_sqlite_alert_async_lock(tenant_key):
                return await self._do_acknowledge(session, alert_uuid, current_user, notes, triage_notes, ip_address)
        else:
            with _get_sqlite_alert_thread_lock(tenant_key):
                return await self._do_acknowledge(session, alert_uuid, current_user, notes, triage_notes, ip_address)

    async def _do_acknowledge(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        notes: str | None = None,
        triage_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        alert = await self._lock_and_get_alert(session, alert_uuid, current_user)

        # Idempotent self-transition
        if alert.status == AlertStatus.ACKNOWLEDGED.value:
            return alert

        current_status = AlertStatus(alert.status)
        allowed_targets = ALERT_STATUS_TRANSITIONS.get(current_status, set())
        if AlertStatus.ACKNOWLEDGED not in allowed_targets:
            raise AlertInvalidTransitionError(
                f"Cannot transition alert from {alert.status} to ACKNOWLEDGED."
            )

        prev_status = alert.status
        alert.status = AlertStatus.ACKNOWLEDGED.value
        alert.acknowledged_at = _utcnow()
        effective_notes = triage_notes or notes
        if effective_notes:
            alert.triage_notes = effective_notes

        _create_audit_event(
            session=session,
            action="ALERT_ACKNOWLEDGED",
            actor_user_id=current_user.id,
            target_resource="alerts",
            resource_id=alert.alert_uuid,
            details={"previous_status": prev_status, "new_status": "ACKNOWLEDGED"},
            ip_address=ip_address,
        )
        soc_ack_payload = {
            "id": alert.alert_uuid,
            "status": "ACKNOWLEDGED",
            "previous_status": prev_status,
            "severity": alert.severity,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "notes": effective_notes,
        }
        soc_ack_event = SOCEventStream(
            event_id=str(uuid.uuid4()),
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            channel="alerts",
            event_type="alert_updated",
            aggregate_id=alert.alert_uuid,
            payload_json=soc_ack_payload,
            created_at=_utcnow(),
        )
        session.add(soc_ack_event)

        await _flush(session)
        soc_cursor_id = soc_ack_event.cursor_id or 0
        await _commit(session)
        await _refresh(session, alert)

        event_broadcaster.publish_event_nowait(
            event_type="alert_updated",
            channel="alerts",
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            payload=soc_ack_payload,
            aggregate_id=alert.alert_uuid,
            cursor_id=soc_cursor_id,
        )
        return alert

    async def resolve_alert(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        notes: str | None = None,
        resolution_notes: str | None = None,
        triage_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        """Resolve an alert (OPEN/ACKNOWLEDGED -> RESOLVED). Idempotent if already resolved."""
        tenant_key = current_user.id if getattr(current_user, "id", None) else 0
        if isinstance(session, AsyncSession):
            async with _get_sqlite_alert_async_lock(tenant_key):
                return await self._do_resolve(session, alert_uuid, current_user, notes, resolution_notes, triage_notes, ip_address)
        else:
            with _get_sqlite_alert_thread_lock(tenant_key):
                return await self._do_resolve(session, alert_uuid, current_user, notes, resolution_notes, triage_notes, ip_address)

    async def _do_resolve(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        notes: str | None = None,
        resolution_notes: str | None = None,
        triage_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        alert = await self._lock_and_get_alert(session, alert_uuid, current_user)

        # Idempotent self-transition
        if alert.status == AlertStatus.RESOLVED.value:
            return alert

        current_status = AlertStatus(alert.status)
        allowed_targets = ALERT_STATUS_TRANSITIONS.get(current_status, set())
        if AlertStatus.RESOLVED not in allowed_targets:
            raise AlertInvalidTransitionError(
                f"Cannot transition alert from {alert.status} to RESOLVED."
            )

        prev_status = alert.status
        alert.status = AlertStatus.RESOLVED.value
        alert.resolved_at = _utcnow()
        effective_notes = resolution_notes or triage_notes or notes
        if effective_notes:
            alert.triage_notes = effective_notes

        _create_audit_event(
            session=session,
            action="ALERT_RESOLVED",
            actor_user_id=current_user.id,
            target_resource="alerts",
            resource_id=alert.alert_uuid,
            details={"previous_status": prev_status, "new_status": "RESOLVED", "notes": effective_notes},
            ip_address=ip_address,
        )
        soc_res_payload = {
            "id": alert.alert_uuid,
            "status": "RESOLVED",
            "previous_status": prev_status,
            "severity": alert.severity,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "notes": effective_notes,
        }
        soc_res_event = SOCEventStream(
            event_id=str(uuid.uuid4()),
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            channel="alerts",
            event_type="alert_updated",
            aggregate_id=alert.alert_uuid,
            payload_json=soc_res_payload,
            created_at=_utcnow(),
        )
        session.add(soc_res_event)

        await _flush(session)
        soc_cursor_id = soc_res_event.cursor_id or 0
        await _commit(session)
        await _refresh(session, alert)

        event_broadcaster.publish_event_nowait(
            event_type="alert_updated",
            channel="alerts",
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            payload=soc_res_payload,
            aggregate_id=alert.alert_uuid,
            cursor_id=soc_cursor_id,
        )
        return alert

    async def dismiss_alert(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        dismiss_reason: str | None = None,
        reason: str | None = None,
        triage_notes: str | None = None,
        notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        """Dismiss an alert as false positive or benign noise. Idempotent if already dismissed."""
        clean_reason = (dismiss_reason or reason or "").strip()
        clean_notes = triage_notes or notes
        if not clean_reason or len(clean_reason) < 3:
            raise AlertValidationError("dismiss_reason is required and must be at least 3 characters.")

        tenant_key = current_user.id if getattr(current_user, "id", None) else 0
        if isinstance(session, AsyncSession):
            async with _get_sqlite_alert_async_lock(tenant_key):
                return await self._do_dismiss(session, alert_uuid, current_user, clean_reason, clean_notes, ip_address)
        else:
            with _get_sqlite_alert_thread_lock(tenant_key):
                return await self._do_dismiss(session, alert_uuid, current_user, clean_reason, clean_notes, ip_address)

    async def _do_dismiss(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        clean_reason: str,
        clean_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        alert = await self._lock_and_get_alert(session, alert_uuid, current_user)

        # Idempotent self-transition
        if alert.status == AlertStatus.DISMISSED.value:
            return alert

        current_status = AlertStatus(alert.status)
        allowed_targets = ALERT_STATUS_TRANSITIONS.get(current_status, set())
        if AlertStatus.DISMISSED not in allowed_targets:
            raise AlertInvalidTransitionError(
                f"Cannot transition alert from {alert.status} to DISMISSED."
            )

        prev_status = alert.status
        alert.status = AlertStatus.DISMISSED.value
        alert.dismissed_at = _utcnow()
        alert.dismiss_reason = clean_reason
        if clean_notes:
            alert.triage_notes = clean_notes

        _create_audit_event(
            session=session,
            action="ALERT_DISMISSED",
            actor_user_id=current_user.id,
            target_resource="alerts",
            resource_id=alert.alert_uuid,
            details={"previous_status": prev_status, "new_status": "DISMISSED", "dismiss_reason": clean_reason},
            ip_address=ip_address,
        )
        soc_dis_payload = {
            "id": alert.alert_uuid,
            "status": "DISMISSED",
            "previous_status": prev_status,
            "severity": alert.severity,
            "dismissed_at": alert.dismissed_at.isoformat() if alert.dismissed_at else None,
            "dismiss_reason": clean_reason,
            "notes": clean_notes,
        }
        soc_dis_event = SOCEventStream(
            event_id=str(uuid.uuid4()),
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            channel="alerts",
            event_type="alert_updated",
            aggregate_id=alert.alert_uuid,
            payload_json=soc_dis_payload,
            created_at=_utcnow(),
        )
        session.add(soc_dis_event)

        await _flush(session)
        soc_cursor_id = soc_dis_event.cursor_id or 0
        await _commit(session)
        await _refresh(session, alert)

        event_broadcaster.publish_event_nowait(
            event_type="alert_updated",
            channel="alerts",
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            payload=soc_dis_payload,
            aggregate_id=alert.alert_uuid,
            cursor_id=soc_cursor_id,
        )
        return alert

    async def reopen_alert(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        reopen_notes: str | None = None,
        notes: str | None = None,
        triage_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        """Reopen a resolved, dismissed, or acknowledged alert back to OPEN."""
        tenant_key = current_user.id if getattr(current_user, "id", None) else 0
        if isinstance(session, AsyncSession):
            async with _get_sqlite_alert_async_lock(tenant_key):
                return await self._do_reopen(session, alert_uuid, current_user, reopen_notes, notes, triage_notes, ip_address)
        else:
            with _get_sqlite_alert_thread_lock(tenant_key):
                return await self._do_reopen(session, alert_uuid, current_user, reopen_notes, notes, triage_notes, ip_address)

    async def _do_reopen(
        self,
        session: Session | AsyncSession,
        alert_uuid: str,
        current_user: User,
        reopen_notes: str | None = None,
        notes: str | None = None,
        triage_notes: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        alert = await self._lock_and_get_alert(session, alert_uuid, current_user)

        # Idempotent self-transition
        if alert.status == AlertStatus.OPEN.value:
            return alert

        current_status = AlertStatus(alert.status)
        allowed_targets = ALERT_STATUS_TRANSITIONS.get(current_status, set())
        if AlertStatus.OPEN not in allowed_targets:
            raise AlertInvalidTransitionError(
                f"Cannot transition alert from {alert.status} to OPEN."
            )

        prev_status = alert.status
        alert.status = AlertStatus.OPEN.value
        alert.resolved_at = None
        alert.dismissed_at = None
        alert.acknowledged_at = None
        alert.dismiss_reason = None
        effective_notes = reopen_notes or triage_notes or notes
        if effective_notes:
            alert.triage_notes = effective_notes

        _create_audit_event(
            session=session,
            action="ALERT_REOPENED",
            actor_user_id=current_user.id,
            target_resource="alerts",
            resource_id=alert.alert_uuid,
            details={"previous_status": prev_status, "new_status": "OPEN", "reopen_notes": effective_notes},
            ip_address=ip_address,
        )

        if alert.user_id is not None:
            reopen_notif = Notification(
                notification_uuid=str(uuid.uuid4()),
                user_id=alert.user_id,
                title=f"Alert Reopened: {alert.title}"[:255],
                message=f"Alert {alert.alert_uuid} was reopened. Triage resumed.",
                severity=alert.severity,
                is_read=False,
                link_url=f"/alerts/{alert.alert_uuid}",
                created_at=_utcnow(),
            )
            session.add(reopen_notif)

        soc_reopen_payload = {
            "id": alert.alert_uuid,
            "status": "OPEN",
            "previous_status": prev_status,
            "severity": alert.severity,
            "notes": effective_notes,
        }
        soc_reopen_event = SOCEventStream(
            event_id=str(uuid.uuid4()),
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            channel="alerts",
            event_type="alert_updated",
            aggregate_id=alert.alert_uuid,
            payload_json=soc_reopen_payload,
            created_at=_utcnow(),
        )
        session.add(soc_reopen_event)

        await _flush(session)
        soc_cursor_id = soc_reopen_event.cursor_id or 0
        await _commit(session)
        await _refresh(session, alert)

        event_broadcaster.publish_event_nowait(
            event_type="alert_updated",
            channel="alerts",
            tenant_id=alert.user_id if alert.user_id is not None else 0,
            payload=soc_reopen_payload,
            aggregate_id=alert.alert_uuid,
            cursor_id=soc_cursor_id,
        )
        return alert

    async def get_alert_stats(
        self,
        session: Session | AsyncSession,
        current_user: User,
    ) -> AlertStatsResponse:
        """
        Compute authoritative telemetry over instantaneous snapshot and rolling 24-hour window.

        Deduplication savings ratio is computed across candidate alert entities touched in W24:
        ratio = 1.0 - (D_distinct / N_occurrences)
        """
        is_admin = getattr(current_user, "role", "user") == "admin"
        query = select(Alert)
        if not is_admin:
            query = query.where(Alert.user_id == current_user.id)

        all_alerts_res = await _execute(session, query)
        all_alerts = list(all_alerts_res.scalars().all())

        now_utc = _utcnow()
        w24_start = now_utc - timedelta(hours=24)

        by_status: dict[str, int] = {
            AlertStatus.OPEN.value: 0,
            AlertStatus.ACKNOWLEDGED.value: 0,
            AlertStatus.RESOLVED.value: 0,
            AlertStatus.DISMISSED.value: 0,
        }
        by_severity: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for a in all_alerts:
            st = a.status.upper() if a.status else "OPEN"
            if st in by_status:
                by_status[st] += 1
            sev = a.severity.upper() if a.severity else "MEDIUM"
            if sev in by_severity:
                by_severity[sev] += 1

        # Rolling 24-hour observation horizon
        candidate_alerts_24h = [
            a for a in all_alerts if a.last_seen_at and a.last_seen_at.replace(tzinfo=timezone.utc) >= w24_start
        ]

        distinct_count_24h = len(candidate_alerts_24h)
        total_occurrences_24h = sum(a.occurrence_count for a in candidate_alerts_24h)

        if total_occurrences_24h <= 0 or distinct_count_24h <= 0:
            dedup_savings_ratio = 0.0
        else:
            raw_ratio = 1.0 - (float(distinct_count_24h) / float(total_occurrences_24h))
            dedup_savings_ratio = max(0.0, min(1.0, round(raw_ratio, 4)))

        velocity_per_hour = round(distinct_count_24h / 24.0, 2)

        return AlertStatsResponse(
            total_alerts=len(all_alerts),
            open_alerts=by_status[AlertStatus.OPEN.value],
            acknowledged_alerts=by_status[AlertStatus.ACKNOWLEDGED.value],
            resolved_alerts=by_status[AlertStatus.RESOLVED.value],
            dismissed_alerts=by_status[AlertStatus.DISMISSED.value],
            by_severity=by_severity,
            by_status=by_status,
            alerts_last_24h=distinct_count_24h,
            alert_velocity_per_hour=velocity_per_hour,
            dedup_savings_ratio=dedup_savings_ratio,
        )


alert_service = AlertService()

