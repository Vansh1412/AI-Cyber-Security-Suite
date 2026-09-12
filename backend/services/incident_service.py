"""
backend/services/incident_service.py
──────────────────────────────────────
Sprint 5 Phase 4: Incident Management Services.

Provides service layer for:
- Incident creation and retrieval
- Alert-to-incident attachment and detachment
- Multi-tenant ownership isolation and system incident scoping
- Incident lifecycle state machine validation
- Monotonic severity escalation
- Aggregated derived summary computation
- Concurrency-safe transactions
- Audit event creation via AuditEvent model
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from backend.database.models import Alert, AuditEvent, Incident, User
from backend.schemas.soc import (
    INCIDENT_STATUS_TRANSITIONS,
    EventSeverity,
    IncidentAggregateSummary,
    IncidentCreate,
    IncidentStatus,
    IncidentUpdate,
)
from backend.utils.domain import normalize_canonical_domain
from src.utils.logger import logger

SEVERITY_RANKS: dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _get_severity_rank(severity_str: str) -> int:
    return SEVERITY_RANKS.get(str(severity_str).upper(), 1)


def _higher_severity(sev1: str, sev2: str) -> str:
    """Return the higher of two severity strings."""
    return sev1 if _get_severity_rank(sev1) >= _get_severity_rank(sev2) else sev2


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Domain Exceptions ──────────────────────────────────────────────────────────

class IncidentServiceError(Exception):
    """Base exception for incident service operations."""

    pass


class IncidentNotFoundError(IncidentServiceError):
    """Raised when an incident is not found or not accessible under tenant scope."""

    pass


class IncidentAccessDeniedError(IncidentServiceError):
    """Raised when a user attempts an unauthorized operation."""

    pass


class IncidentValidationError(IncidentServiceError):
    """Raised when validation or state transition fails."""

    pass


class IncidentConflictError(IncidentServiceError):
    """Raised when alert attachment conflicts with existing assignment."""

    pass


# ── Session Execution Helpers ──────────────────────────────────────────────────

async def _execute(session: Session | AsyncSession, stmt):
    if isinstance(session, AsyncSession):
        return await session.execute(stmt)
    return session.execute(stmt)


async def _commit(session: Session | AsyncSession):
    if isinstance(session, AsyncSession):
        await session.commit()
    else:
        session.commit()


async def _rollback(session: Session | AsyncSession):
    if isinstance(session, AsyncSession):
        await session.rollback()
    else:
        session.rollback()


async def _refresh(session: Session | AsyncSession, obj):
    if isinstance(session, AsyncSession):
        await session.refresh(obj)
    else:
        session.refresh(obj)


_SENSITIVE_KEYWORDS = {
    "password", "jwt", "secret", "token", "auth", "key",
    "authorization", "cookie", "api_key", "bearer", "passwd", "credential"
}


def _sanitize_details(val: Any) -> Any:
    """Recursively sanitize dictionary keys and string values in audit details."""
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            k_str = str(k)
            k_lower = k_str.lower()
            if not isinstance(v, dict | list | tuple) and any(kw in k_lower for kw in _SENSITIVE_KEYWORDS):
                sanitized[k_str] = "[REDACTED]"
            else:
                sanitized[k_str] = _sanitize_details(v)
        return sanitized
    elif isinstance(val, list | tuple):
        return [_sanitize_details(item) for item in val]
    elif isinstance(val, str):
        # Strip control characters except newline and tab
        clean_str = "".join(ch for ch in val if ch in ("\n", "\t") or (32 <= ord(ch) <= 126) or ord(ch) > 127)
        if clean_str.lower().startswith("bearer ") or clean_str.lower().startswith("basic "):
            return "[REDACTED]"
        return clean_str
    return val


def _is_postgresql(session: Session | AsyncSession) -> bool:
    """Check if session is bound to a PostgreSQL database dialect."""
    try:
        bind = getattr(session, "bind", None)
        if bind is None and hasattr(session, "get_bind"):
            bind = session.get_bind()
        return bool(bind and hasattr(bind, "dialect") and getattr(bind.dialect, "name", "") == "postgresql")
    except Exception:
        return False


# ── Incident Service Implementation ───────────────────────────────────────────

class IncidentService:
    """Centralized Incident Management Service."""

    def build_summary(self, incident: Incident) -> IncidentAggregateSummary:
        """Derive aggregated analytical context from attached Alerts."""
        alerts = incident.alerts or []
        if not alerts:
            return IncidentAggregateSummary(
                alert_count=0,
                highest_severity=incident.severity,
                first_seen_at=incident.created_at,
                last_seen_at=incident.updated_at,
                affected_indicators=[],
                affected_domains=[],
                affected_ips=[],
            )

        highest_rank = _get_severity_rank(incident.severity)
        highest_sev = incident.severity

        indicators: set[str] = set()
        domains: set[str] = set()
        ips: set[str] = set()
        first_seen_list: list[datetime] = []
        last_seen_list: list[datetime] = []

        for alert in alerts:
            # Rank severity
            r = _get_severity_rank(alert.severity)
            if r > highest_rank:
                highest_rank = r
                highest_sev = alert.severity

            # Indicators
            val = alert.indicator_value.strip()
            indicators.add(val)

            # Timestamps
            if alert.first_seen_at:
                first_seen_list.append(alert.first_seen_at)
            if alert.last_seen_at:
                last_seen_list.append(alert.last_seen_at)

            # Domains & IPs
            if alert.indicator_type.upper() == "IP":
                ips.add(val)
            else:
                norm = normalize_canonical_domain(val)
                dom = norm.get("registered_domain") or norm.get("fqdn")
                if dom:
                    domains.add(dom)
                if norm.get("has_ip"):
                    ips.add(norm.get("host") or val)

        first_seen = min(first_seen_list) if first_seen_list else incident.created_at
        last_seen = max(last_seen_list) if last_seen_list else incident.updated_at

        return IncidentAggregateSummary(
            alert_count=len(alerts),
            highest_severity=highest_sev,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            affected_indicators=sorted(list(indicators)),
            affected_domains=sorted(list(domains)),
            affected_ips=sorted(list(ips)),
        )

    async def _audit(
        self,
        session: Session | AsyncSession,
        action: str,
        actor_user_id: int | None,
        target_resource: str,
        resource_id: str,
        details: dict,
        ip_address: str | None = None,
    ) -> None:
        """Create sanitized audit event record."""
        sanitized_details = _sanitize_details(details)

        audit = AuditEvent(
            action=action,
            actor_user_id=actor_user_id,
            target_resource=target_resource,
            resource_id=resource_id,
            details=sanitized_details,
            ip_address=ip_address,
            created_at=_utcnow(),
        )
        session.add(audit)

    async def create_incident(
        self,
        session: Session | AsyncSession,
        data: IncidentCreate,
        current_user: User | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """Create a new Incident and attach initial alerts if provided."""
        creator_id = current_user.id if current_user else None
        now = _utcnow()

        incident = Incident(
            title=data.title,
            description=data.description,
            severity=data.severity.value if isinstance(data.severity, EventSeverity) else str(data.severity),
            status=IncidentStatus.OPEN.value,
            assigned_to_user_id=data.assigned_to_user_id,
            created_by_user_id=creator_id,
            created_at=now,
            updated_at=now,
        )

        session.add(incident)
        try:
            await _commit(session)
            await _refresh(session, incident)
        except Exception as exc:
            await _rollback(session)
            logger.error("[INCIDENT_SERVICE] Failed to insert incident: %s", exc)
            raise IncidentServiceError("Database failure while creating incident.") from exc

        # Attach initial alerts if provided
        if data.alert_ids:
            try:
                await self.attach_alerts(
                    session=session,
                    incident_id_or_uuid=incident.id,
                    alert_ids=data.alert_ids,
                    current_user=current_user,
                    ip_address=ip_address,
                )
                await _refresh(session, incident)
            except Exception:
                # If attaching initial alerts fails, roll back entire incident creation if needed or let error bubble
                raise

        # Write audit log
        await self._audit(
            session=session,
            action="INCIDENT_CREATED",
            actor_user_id=creator_id,
            target_resource="Incident",
            resource_id=str(incident.id),
            details={
                "incident_uuid": incident.incident_uuid,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "alert_ids": data.alert_ids,
            },
            ip_address=ip_address,
        )
        await _commit(session)
        await _refresh(session, incident)

        logger.info(
            "[INCIDENT_SERVICE] Created Incident ID %d (UUID: %s) by user %s",
            incident.id,
            incident.incident_uuid,
            creator_id if creator_id is not None else "SYSTEM",
        )
        return incident

    async def get_incident(
        self,
        session: Session | AsyncSession,
        incident_id_or_uuid: int | str,
        current_user: User | None = None,
    ) -> Incident:
        """
        Retrieve an Incident by ID or UUID with strict multi-tenant authorization checks.

        Standard users can only access incidents where created_by_user_id == current_user.id.
        System incidents (created_by_user_id is None) require admin role.
        """
        stmt = select(Incident)

        # Parse identifier
        try:
            val_int = int(incident_id_or_uuid)
            stmt = stmt.where(Incident.id == val_int)
        except (ValueError, TypeError):
            # Attempt UUID validation
            val_str = str(incident_id_or_uuid).strip()
            try:
                uuid.UUID(val_str)
                stmt = stmt.where(Incident.incident_uuid == val_str)
            except ValueError:
                raise IncidentValidationError(f"Invalid incident identifier format: '{incident_id_or_uuid}'")

        # Apply PostgreSQL SELECT FOR UPDATE if applicable
        if not isinstance(session, AsyncSession) and session.bind and session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update()

        res = await _execute(session, stmt)
        incident = res.scalars().first()

        if not incident:
            raise IncidentNotFoundError(f"Incident '{incident_id_or_uuid}' not found.")

        # Ownership / Multi-tenancy Isolation Check
        if (
            current_user is not None
            and current_user.role != "admin"
            and (incident.created_by_user_id is None or incident.created_by_user_id != current_user.id)
        ):
            # Disguise unauthorized access as 404 Not Found to prevent incident existence probing
            raise IncidentNotFoundError(f"Incident '{incident_id_or_uuid}' not found.")

        return incident

    async def list_incidents(
        self,
        session: Session | AsyncSession,
        current_user: User | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        """
        List incidents with tenant isolation, status/severity filters, bounded pagination, and deterministic ordering.
        Returns tuple of (incidents_list, total_count).
        """
        bounded_limit = min(max(1, limit), 100)
        bounded_offset = max(0, offset)

        stmt = select(Incident)

        # Multi-tenant isolation filter
        if current_user is not None:
            if current_user.role != "admin":
                stmt = stmt.where(Incident.created_by_user_id == current_user.id)
        else:
            # Unauthenticated / System scope list returns system incidents only if specified
            stmt = stmt.where(Incident.created_by_user_id.is_(None))

        if status:
            stmt = stmt.where(Incident.status == status.upper())

        if severity:
            stmt = stmt.where(Incident.severity == severity.upper())

        # Count query
        from sqlalchemy import func
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_res = await _execute(session, count_stmt)
        total = count_res.scalar() or 0

        # Deterministic ordering
        stmt = stmt.order_by(Incident.created_at.desc(), Incident.id.desc())
        stmt = stmt.offset(bounded_offset).limit(bounded_limit)

        res = await _execute(session, stmt)
        incidents = list(res.scalars().all())

        return incidents, total

    async def update_incident(
        self,
        session: Session | AsyncSession,
        incident_id_or_uuid: int | str,
        update_data: IncidentUpdate,
        current_user: User | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """
        Controlled update of an Incident including state machine validation and severity escalation.
        """
        incident = await self.get_incident(session, incident_id_or_uuid, current_user)
        actor_id = current_user.id if current_user else None
        now = _utcnow()
        changes = {}

        # 1. Title
        if update_data.title is not None and update_data.title != incident.title:
            changes["title"] = {"old": incident.title, "new": update_data.title}
            incident.title = update_data.title

        # 2. Description
        if update_data.description is not None and update_data.description != incident.description:
            changes["description"] = "updated"
            incident.description = update_data.description

        # 3. Assigned user
        if update_data.assigned_to_user_id is not None and update_data.assigned_to_user_id != incident.assigned_to_user_id:
            changes["assigned_to_user_id"] = {
                "old": incident.assigned_to_user_id,
                "new": update_data.assigned_to_user_id,
            }
            incident.assigned_to_user_id = update_data.assigned_to_user_id

        # 4. Resolution notes
        if update_data.resolution_notes is not None and update_data.resolution_notes != incident.resolution_notes:
            changes["resolution_notes"] = "updated"
            incident.resolution_notes = update_data.resolution_notes

        # 5. Manual Severity Update
        if update_data.severity is not None:
            new_sev = update_data.severity.value if isinstance(update_data.severity, EventSeverity) else str(update_data.severity).upper()
            if new_sev != incident.severity:
                if (
                    _get_severity_rank(new_sev) < _get_severity_rank(incident.severity)
                    and current_user is not None
                    and current_user.role != "admin"
                ):
                    raise IncidentAccessDeniedError(
                        f"Unauthorized: Standard user '{current_user.id}' cannot manually downgrade incident severity from '{incident.severity}' to '{new_sev}'."
                    )
                changes["severity"] = {"old": incident.severity, "new": new_sev}
                incident.severity = new_sev

        # 6. Status Lifecycle Transition Validation
        if update_data.status is not None:
            new_status = update_data.status.value if isinstance(update_data.status, IncidentStatus) else str(update_data.status).upper()
            curr_status = incident.status.upper()

            if new_status != curr_status:
                try:
                    curr_enum = IncidentStatus(curr_status)
                    new_enum = IncidentStatus(new_status)
                except ValueError:
                    raise IncidentValidationError(f"Invalid status value: '{new_status}'")

                valid_allowed = INCIDENT_STATUS_TRANSITIONS.get(curr_enum, set())
                if new_enum not in valid_allowed:
                    raise IncidentValidationError(
                        f"Invalid status transition from '{curr_status}' to '{new_status}'. "
                        f"Allowed transitions from '{curr_status}': {[s.value for s in valid_allowed]}"
                    )

                changes["status"] = {"old": curr_status, "new": new_status}
                incident.status = new_status

                # Handle closed_at timestamp
                if new_enum in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
                    if incident.closed_at is None:
                        incident.closed_at = now
                elif curr_enum in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
                    # Reopened incident
                    incident.closed_at = None

        if changes:
            incident.updated_at = now
            try:
                await _commit(session)
                await _refresh(session, incident)
            except Exception as exc:
                await _rollback(session)
                logger.error("[INCIDENT_SERVICE] Update failed: %s", exc)
                raise IncidentServiceError("Database update failure.") from exc

            # Audit event
            await self._audit(
                session=session,
                action="INCIDENT_UPDATED",
                actor_user_id=actor_id,
                target_resource="Incident",
                resource_id=str(incident.id),
                details={"changes": changes, "incident_uuid": incident.incident_uuid},
                ip_address=ip_address,
            )
            await _commit(session)
            await _refresh(session, incident)

        return incident

    async def attach_alerts(
        self,
        session: Session | AsyncSession,
        incident_id_or_uuid: int | str,
        alert_ids: list[int],
        current_user: User | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """
        Attach a list of alerts to an incident safely.

        Checks:
        - Incident exists and belongs to current user/scope.
        - Each Alert exists.
        - Each Alert belongs to current user/scope (prevents cross-tenant attachment).
        - Each Alert is not already attached to a different Incident (no silent stealing, raises 409 Conflict).
        - Monotonic severity escalation (incident severity escalates if attached alert has higher severity).
        """
        if not alert_ids:
            return await self.get_incident(session, incident_id_or_uuid, current_user)

        incident = await self.get_incident(session, incident_id_or_uuid, current_user)
        actor_id = current_user.id if current_user else None

        # Fetch requested alerts
        stmt = select(Alert).where(Alert.id.in_(alert_ids))
        res = await _execute(session, stmt)
        alerts = list(res.scalars().all())

        found_ids = {a.id for a in alerts}
        missing_ids = set(alert_ids) - found_ids
        if missing_ids:
            raise IncidentNotFoundError(f"Alert IDs not found: {sorted(list(missing_ids))}")

        # Monotonic severity check over all attached and new alerts
        attached_count = 0
        new_severity = incident.severity
        for existing_alert in (incident.alerts or []):
            new_severity = _higher_severity(new_severity, existing_alert.severity)

        for alert in alerts:
            # Multi-tenant isolation check on Alert
            if (
                current_user is not None
                and current_user.role != "admin"
                and (alert.user_id is None or alert.user_id != current_user.id)
            ):
                raise IncidentAccessDeniedError(
                    f"Unauthorized: Alert ID {alert.id} does not belong to user {current_user.id}."
                )

            # Check if alert is already assigned to a DIFFERENT incident
            if alert.incident_id is not None and alert.incident_id != incident.id:
                raise IncidentConflictError(
                    f"Alert ID {alert.id} is already attached to Incident ID {alert.incident_id}. "
                    "Reassignment is rejected to maintain referential integrity."
                )

            # Assign if not already assigned
            if alert.incident_id != incident.id:
                alert.incident_id = incident.id
                attached_count += 1

            # Monotonic severity check
            new_severity = _higher_severity(new_severity, alert.severity)

        # Re-fetch all attached alert severities and latest incident severity from DB to prevent concurrent lost updates
        stmt_sevs = select(Alert.severity).where(Alert.incident_id == incident.id)
        res_sevs = await _execute(session, stmt_sevs)
        db_alert_sevs = list(res_sevs.scalars().all())

        stmt_inc_sev = select(Incident.severity).where(Incident.id == incident.id)
        res_inc_sev = await _execute(session, stmt_inc_sev)
        latest_inc_sev = res_inc_sev.scalar() or incident.severity

        new_severity = _higher_severity(new_severity, latest_inc_sev)
        for s in db_alert_sevs:
            new_severity = _higher_severity(new_severity, s)

        incident.severity = new_severity
        incident.updated_at = _utcnow()

        try:
            await _commit(session)
            await _refresh(session, incident)
        except Exception as exc:
            await _rollback(session)
            logger.error("[INCIDENT_SERVICE] Failed to attach alerts: %s", exc)
            raise IncidentServiceError("Database failure while attaching alerts.") from exc

        # Write audit event
        if attached_count > 0:
            await self._audit(
                session=session,
                action="ALERT_ATTACHED",
                actor_user_id=actor_id,
                target_resource="Incident",
                resource_id=str(incident.id),
                details={
                    "attached_alert_ids": alert_ids,
                    "incident_uuid": incident.incident_uuid,
                    "new_severity": incident.severity,
                },
                ip_address=ip_address,
            )
            await _commit(session)
            await _refresh(session, incident)

        logger.info(
            "[INCIDENT_SERVICE] Attached %d alerts to Incident ID %d (Severity: %s)",
            attached_count,
            incident.id,
            incident.severity,
        )
        return incident

    async def detach_alert(
        self,
        session: Session | AsyncSession,
        incident_id_or_uuid: int | str,
        alert_id: int,
        current_user: User | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """
        Detach a single alert from an Incident.
        Note: Monotonic severity is maintained (incident severity is NOT automatically downgraded).
        """
        incident = await self.get_incident(session, incident_id_or_uuid, current_user)
        actor_id = current_user.id if current_user else None

        stmt = select(Alert).where(Alert.id == alert_id, Alert.incident_id == incident.id)
        res = await _execute(session, stmt)
        alert = res.scalars().first()

        if not alert:
            raise IncidentNotFoundError(f"Alert ID {alert_id} is not attached to Incident ID {incident.id}.")

        # Multi-tenant isolation check
        if (
            current_user is not None
            and current_user.role != "admin"
            and (alert.user_id is None or alert.user_id != current_user.id)
        ):
            raise IncidentAccessDeniedError(f"Unauthorized access to Alert ID {alert_id}.")

        alert.incident_id = None
        incident.updated_at = _utcnow()

        try:
            await _commit(session)
            await _refresh(session, incident)
        except Exception as exc:
            await _rollback(session)
            logger.error("[INCIDENT_SERVICE] Failed to detach alert: %s", exc)
            raise IncidentServiceError("Database failure while detaching alert.") from exc

        # Audit
        await self._audit(
            session=session,
            action="ALERT_DETACHED",
            actor_user_id=actor_id,
            target_resource="Incident",
            resource_id=str(incident.id),
            details={"detached_alert_id": alert_id, "incident_uuid": incident.incident_uuid},
            ip_address=ip_address,
        )
        await _commit(session)
        await _refresh(session, incident)

        logger.info("[INCIDENT_SERVICE] Detached Alert ID %d from Incident ID %d", alert_id, incident.id)
        return incident


incident_service = IncidentService()
