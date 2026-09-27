"""
backend/services/containment_service.py
───────────────────────────────────────
Sprint 5 Phase 5F: Automated Threat Containment & Declarative SOAR-Lite Engine.

Features:
- Policy Gate: dedicated soc_containment_policies with default-safe disabled mode.
- Rule 0 Allowlist Fencing: unbreakable boundary using ThreatIntelAdapter (fail-closed).
- Declarative Typed Action Sequences: deterministic execution without arbitrary code/scripts.
- Global Per-Tenant Concurrency: max 5 concurrent playbook runs across pods.
- Stale Worker Fencing: fencing_token validation before destructive mutations.
- Exactly-Once Durable Action Identity: collision-safe database uniqueness constraints.
- Provenance-Safe Rollback: revert removes only entries created by the specific action.
- Target Quarantine: exact threshold evaluation (>= 3 distinct active alerts in 10m).
- Phase 5D & Phase 5E Integration: transactional outbox notifications & real-time SSE frames.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from backend.database.models import (
    Alert,
    AuditEvent,
    MonitoringTarget,
    SOCContainmentAction,
    SOCContainmentPolicy,
    SOCDynamicBlacklist,
    SOCEventStream,
    SOCPlaybookRun,
    User,
)
from backend.schemas.containment import (
    ContainmentActionStatus,
    ContainmentActionType,
    ContainmentPolicyUpdate,
    PlaybookRunStatus,
)
from backend.services.cache import cache_service
from backend.services.event_broadcaster import event_broadcaster
from backend.services.incident_service import incident_service
from backend.services.notification_service import notification_service
from backend.services.threat_intel import TRUSTED_DOMAINS, _is_legitimate_domain
from src.utils.logger import logger


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_str() -> str:
    return str(uuid.uuid4())


# ── SQLite Concurrency Synchronization Locks (CI Emulation) ──────────────────
_sqlite_playbook_thread_locks: dict[int, threading.Lock] = {}
_sqlite_playbook_thread_guard = threading.Lock()
_sqlite_playbook_semaphores: dict[tuple[int, int], asyncio.Semaphore] = {}


def _get_sqlite_playbook_thread_lock(tenant_id: int) -> threading.Lock:
    with _sqlite_playbook_thread_guard:
        if tenant_id not in _sqlite_playbook_thread_locks:
            _sqlite_playbook_thread_locks[tenant_id] = threading.Lock()
        return _sqlite_playbook_thread_locks[tenant_id]


def _get_sqlite_playbook_semaphore(tenant_id: int) -> asyncio.Semaphore:
    try:
        loop = asyncio.get_running_loop()
        key = (id(loop), tenant_id)
        if key not in _sqlite_playbook_semaphores:
            _sqlite_playbook_semaphores[key] = asyncio.Semaphore(5)
        return _sqlite_playbook_semaphores[key]
    except RuntimeError:
        return asyncio.Semaphore(5)


_sqlite_action_async_locks: dict[tuple[int, int], asyncio.Lock] = {}
_sqlite_action_thread_guard = threading.Lock()


def _get_sqlite_action_async_lock(tenant_id: int) -> asyncio.Lock:
    try:
        loop = asyncio.get_running_loop()
        key = (id(loop), tenant_id)
        with _sqlite_action_thread_guard:
            if key not in _sqlite_action_async_locks:
                _sqlite_action_async_locks[key] = asyncio.Lock()
            return _sqlite_action_async_locks[key]
    except RuntimeError:
        return asyncio.Lock()


# ── Session Execution Helpers ─────────────────────────────────────────────────

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


# ── Rule 0: Threat Intel Adapter (Protected File Adapter) ─────────────────────

class ThreatIntelAdapter:
    """
    Read-only adapter for trusted domain allowlist evaluation.
    Inspects TRUSTED_DOMAINS from backend.services.threat_intel without modifying it.
    Guarantees FAIL-CLOSED semantics on any error or parsing ambiguity.
    """

    @staticmethod
    def is_whitelisted(indicator: str) -> bool:
        if not indicator:
            return True  # Fail-closed
        try:
            parsed = urlparse(indicator)
            hostname = (parsed.hostname or indicator).lower().strip()
            return any(_is_legitimate_domain(hostname, trusted) for trusted in TRUSTED_DOMAINS)
        except Exception as exc:
            logger.warning("ThreatIntelAdapter: allowlist check error for %s: %s (failing closed)", indicator, exc)
            return True  # Fail-closed


# ── Core Containment Service ──────────────────────────────────────────────────

class ContainmentService:
    """Central orchestrator for automated and manual threat containment."""

    MAX_CONCURRENT_PLAYBOOKS_PER_TENANT = 5
    DEFAULT_BLACKLIST_TTL_SECONDS = 86400  # 24 hours

    # ── Policy Management ─────────────────────────────────────────────────────

    async def get_or_create_policy(
        self, session: Session | AsyncSession, tenant_id: int
    ) -> SOCContainmentPolicy:
        """Retrieve existing policy or synthesize a safe default policy row."""
        stmt = select(SOCContainmentPolicy).where(SOCContainmentPolicy.tenant_id == tenant_id)
        result = await _execute(session, stmt)
        policy = result.scalar_one_or_none()

        if policy is None:
            policy = SOCContainmentPolicy(
                tenant_id=tenant_id,
                auto_containment_enabled=False,
                auto_blacklist_enabled=False,
                auto_quarantine_enabled=False,
                auto_incident_binding_enabled=False,
                containment_min_severity="CRITICAL",
                blacklist_ttl_seconds=self.DEFAULT_BLACKLIST_TTL_SECONDS,
                policy_version=1,
            )
            session.add(policy)
            try:
                if isinstance(session, AsyncSession):
                    async with session.begin_nested():
                        await session.flush()
                else:
                    with session.begin_nested():
                        session.flush()
            except IntegrityError:
                result = await _execute(session, stmt)
                policy = result.scalar_one()

        return policy

    async def update_policy(
        self,
        session: Session | AsyncSession,
        tenant_id: int,
        update_data: ContainmentPolicyUpdate,
        user_id: int,
    ) -> SOCContainmentPolicy:
        """Optimistically update containment policy with version checking and audit logging."""
        policy = await self.get_or_create_policy(session, tenant_id)

        stmt_up = (
            update(SOCContainmentPolicy)
            .where(
                SOCContainmentPolicy.tenant_id == tenant_id,
                SOCContainmentPolicy.policy_version == update_data.policy_version,
            )
            .values(
                auto_containment_enabled=update_data.auto_containment_enabled,
                auto_blacklist_enabled=update_data.auto_blacklist_enabled,
                auto_quarantine_enabled=update_data.auto_quarantine_enabled,
                auto_incident_binding_enabled=update_data.auto_incident_binding_enabled,
                containment_min_severity=update_data.containment_min_severity,
                blacklist_ttl_seconds=update_data.blacklist_ttl_seconds,
                policy_version=SOCContainmentPolicy.policy_version + 1,
                updated_at=_utcnow(),
                updated_by=user_id,
            )
        )
        res_up = await _execute(session, stmt_up)
        if res_up.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Policy version conflict: current version is {policy.policy_version}, update submitted {update_data.policy_version}",
            )

        audit = AuditEvent(
            action="CONTAINMENT_POLICY_UPDATED",
            actor_user_id=user_id,
            target_resource="soc_containment_policies",
            resource_id=str(policy.id),
            details={
                "tenant_id": tenant_id,
                "policy_version": update_data.policy_version + 1,
                "auto_containment_enabled": update_data.auto_containment_enabled,
                "auto_blacklist_enabled": update_data.auto_blacklist_enabled,
                "auto_quarantine_enabled": update_data.auto_quarantine_enabled,
                "auto_incident_binding_enabled": update_data.auto_incident_binding_enabled,
                "containment_min_severity": update_data.containment_min_severity,
                "blacklist_ttl_seconds": update_data.blacklist_ttl_seconds,
            },
        )
        session.add(audit)
        await _commit(session)

        stmt_reload = select(SOCContainmentPolicy).where(SOCContainmentPolicy.tenant_id == tenant_id)
        res_reload = await _execute(session, stmt_reload)
        return res_reload.scalar_one()

    # ── Concurrency & Fencing Coordination ────────────────────────────────────

    async def _acquire_tenant_concurrency_lease(
        self, session: Session | AsyncSession, tenant_id: int
    ) -> str:
        """Acquire a distributed concurrency token (max 5 per tenant) with PostgreSQL fallback."""
        token = _uuid_str()

        # 1. Try Redis token semaphore if available
        redis = getattr(cache_service, "_client", None)
        if redis is not None:
            try:
                redis_key = f"soc:playbook:tenant_concurrency:{tenant_id}"
                now_ts = datetime.now(timezone.utc).timestamp()
                # Remove expired tokens older than 60s
                await redis.zremrangebyscore(redis_key, "-inf", now_ts - 60)
                count = await redis.zcard(redis_key)
                if count >= self.MAX_CONCURRENT_PLAYBOOKS_PER_TENANT:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Tenant playbook concurrency limit ({self.MAX_CONCURRENT_PLAYBOOKS_PER_TENANT}) reached",
                    )
                await redis.zadd(redis_key, {token: now_ts})
                await redis.expire(redis_key, 120)
                return token
            except HTTPException:
                raise
            except Exception as exc:
                logger.warning("Redis playbook concurrency lease failed: %s (falling back to DB)", exc)

        # 2. Authoritative PostgreSQL / DB Fallback
        # Ensure tenant policy anchor exists first (default-safe synthesis)
        await self.get_or_create_policy(session, tenant_id)

        # Authoritative PostgreSQL row-level lock on tenant policy anchor
        # Serializes concurrent lease acquisitions for the same tenant under READ COMMITTED
        lock_stmt = (
            select(SOCContainmentPolicy.id)
            .where(SOCContainmentPolicy.tenant_id == tenant_id)
            .with_for_update()
        )
        await _execute(session, lock_stmt)

        stmt = (
            select(func.count(SOCPlaybookRun.id))
            .where(
                SOCPlaybookRun.tenant_id == tenant_id,
                SOCPlaybookRun.status == PlaybookRunStatus.RUNNING.value,
            )
        )
        result = await _execute(session, stmt)
        running_count = result.scalar_one() or 0
        if running_count >= self.MAX_CONCURRENT_PLAYBOOKS_PER_TENANT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Tenant playbook concurrency limit ({self.MAX_CONCURRENT_PLAYBOOKS_PER_TENANT}) reached",
            )
        return token

    async def _release_tenant_concurrency_lease(self, tenant_id: int, token: str) -> None:
        """Safely release the distributed concurrency token."""
        redis = getattr(cache_service, "_client", None)
        if redis is not None:
            try:
                redis_key = f"soc:playbook:tenant_concurrency:{tenant_id}"
                await redis.zrem(redis_key, token)
            except Exception as exc:
                logger.debug("Failed to release Redis playbook concurrency token: %s", exc)

    # ── Quarantine Threshold Evaluation ───────────────────────────────────────

    async def evaluate_quarantine_eligibility(
        self, session: Session | AsyncSession, target: MonitoringTarget
    ) -> bool:
        """
        Quarantine occurs iff:
        - Target is currently active (is_active == True)
        - >= 3 distinct alerts (alert.id)
        - Belonging to same target (matching indicator or target URL)
        - Within rolling 10-minute window
        - Severity is HIGH or CRITICAL
        - Status is strictly OPEN or ACKNOWLEDGED (RESOLVED and DISMISSED do not count)
        """
        if not target.is_active:
            return False

        ten_mins_ago = _utcnow() - timedelta(minutes=10)
        stmt = (
            select(func.count(Alert.id))
            .where(
                Alert.user_id == target.user_id,
                Alert.status.in_(["OPEN", "ACKNOWLEDGED"]),
                Alert.severity.in_(["HIGH", "CRITICAL"]),
                Alert.first_seen_at >= ten_mins_ago,
                Alert.indicator_value.in_([target.url, target.normalized_domain]),
            )
        )
        result = await _execute(session, stmt)
        distinct_count = result.scalar_one() or 0
        return distinct_count >= 3

    # ── Action Execution Core ─────────────────────────────────────────────────

    async def execute_action(
        self,
        session: Session | AsyncSession,
        action_type: ContainmentActionType,
        target_identifier: str,
        tenant_id: int,
        trigger_source: str,
        alert_id: int | None = None,
        run_id: int | None = None,
        actor_user_id: int | None = None,
        reason: str = "Automated threat containment",
    ) -> SOCContainmentAction:
        """Execute a single declarative typed containment action with idempotency and Rule 0."""
        if isinstance(session, AsyncSession):
            bind = getattr(session, "bind", None)
            is_sqlite = not bind or getattr(getattr(bind, "dialect", None), "name", "") == "sqlite"
            if is_sqlite:
                async with _get_sqlite_action_async_lock(tenant_id):
                    return await self._do_execute_action(
                        session=session,
                        action_type=action_type,
                        target_identifier=target_identifier,
                        tenant_id=tenant_id,
                        trigger_source=trigger_source,
                        alert_id=alert_id,
                        run_id=run_id,
                        actor_user_id=actor_user_id,
                        reason=reason,
                    )
        return await self._do_execute_action(
            session=session,
            action_type=action_type,
            target_identifier=target_identifier,
            tenant_id=tenant_id,
            trigger_source=trigger_source,
            alert_id=alert_id,
            run_id=run_id,
            actor_user_id=actor_user_id,
            reason=reason,
        )

    async def _do_execute_action(
        self,
        session: Session | AsyncSession,
        action_type: ContainmentActionType,
        target_identifier: str,
        tenant_id: int,
        trigger_source: str,
        alert_id: int | None = None,
        run_id: int | None = None,
        actor_user_id: int | None = None,
        reason: str = "Automated threat containment",
    ) -> SOCContainmentAction:
        action_idempotency_key = (
            f"tenant:{tenant_id}:alert:{alert_id or 'none'}:action:{action_type.value}:{target_identifier}"
        )

        # Check existing action
        existing_stmt = select(SOCContainmentAction).where(
            SOCContainmentAction.action_idempotency_key == action_idempotency_key
        )
        result = await _execute(session, existing_stmt)
        existing_action = result.scalar_one_or_none()
        if existing_action:
            return existing_action

        action = SOCContainmentAction(
            action_uuid=_uuid_str(),
            run_id=run_id,
            tenant_id=tenant_id,
            alert_id=alert_id,
            target_identifier=target_identifier,
            action_type=action_type.value,
            status=ContainmentActionStatus.PENDING.value,
            actor_user_id=actor_user_id,
            trigger_source=trigger_source,
            action_idempotency_key=action_idempotency_key,
            created_at=_utcnow(),
            started_at=_utcnow(),
        )
        try:
            if isinstance(session, AsyncSession):
                async with session.begin_nested():
                    session.add(action)
                    await session.flush()
            else:
                with session.begin_nested():
                    session.add(action)
                    session.flush()
        except IntegrityError:
            for _ in range(20):
                await asyncio.sleep(0.05)
                result = await _execute(session, existing_stmt)
                existing = result.scalar_one_or_none()
                if existing:
                    return existing
            result = await _execute(session, existing_stmt)
            existing = result.scalar_one_or_none()
            if existing:
                return existing
            raise

        try:
            # 1. Rule 0 Allowlist Fencing (per action type)
            if action_type == ContainmentActionType.BLACKLIST_INDICATOR:
                if ThreatIntelAdapter.is_whitelisted(target_identifier):
                    action.status = ContainmentActionStatus.BLOCKED_BY_ALLOWLIST.value
                    action.error_message = f"Rule 0 Invariant: indicator '{target_identifier}' is allowlisted."
                    action.completed_at = _utcnow()
                    audit = AuditEvent(
                        action="CONTAINMENT_BLOCKED_BY_ALLOWLIST",
                        actor_user_id=actor_user_id,
                        target_resource="soc_dynamic_blacklist",
                        resource_id=target_identifier,
                        details={"tenant_id": tenant_id, "action_uuid": action.action_uuid, "alert_id": alert_id},
                    )
                    session.add(audit)
                    return action

            elif (
                action_type == ContainmentActionType.QUARANTINE_TARGET
                and ThreatIntelAdapter.is_whitelisted(target_identifier)
            ):
                action.status = ContainmentActionStatus.BLOCKED_BY_ALLOWLIST.value
                action.error_message = f"Rule 0 Invariant: target domain '{target_identifier}' is allowlisted."
                action.completed_at = _utcnow()
                audit = AuditEvent(
                    action="CONTAINMENT_BLOCKED_BY_ALLOWLIST",
                    actor_user_id=actor_user_id,
                    target_resource="monitoring_targets",
                    resource_id=target_identifier,
                    details={"tenant_id": tenant_id, "action_uuid": action.action_uuid, "alert_id": alert_id},
                )
                session.add(audit)
                return action

            # 2. Action Type Implementation
            if action_type == ContainmentActionType.BLACKLIST_INDICATOR:
                policy = await self.get_or_create_policy(session, tenant_id)
                expires_at = _utcnow() + timedelta(seconds=policy.blacklist_ttl_seconds)

                # Check if already blacklisted for this tenant
                bl_stmt = select(SOCDynamicBlacklist).where(
                    SOCDynamicBlacklist.tenant_id == tenant_id,
                    SOCDynamicBlacklist.indicator_value == target_identifier,
                    SOCDynamicBlacklist.is_active.is_(True),
                )
                bl_res = await _execute(session, bl_stmt)
                existing_bl = bl_res.scalar_one_or_none()

                if existing_bl:
                    # Extend expiry idempotently
                    existing_bl.expires_at = max(existing_bl.expires_at, expires_at)
                    existing_bl.updated_at = _utcnow()
                    action.result_metadata = {"blacklist_id": existing_bl.id, "action": "extended_ttl"}
                else:
                    ind_type = "url" if "://" in target_identifier else "domain"
                    bl_entry = SOCDynamicBlacklist(
                        indicator_type=ind_type,
                        indicator_value=target_identifier,
                        tenant_id=tenant_id,
                        containment_action_id=action.id,
                        reason=reason,
                        is_active=True,
                        expires_at=expires_at,
                    )
                    session.add(bl_entry)
                    await _flush(session)
                    action.result_metadata = {"blacklist_id": bl_entry.id, "action": "created"}

                action.rollback_metadata = {
                    "indicator_value": target_identifier,
                    "containment_action_id": action.id,
                }
                action.status = ContainmentActionStatus.EXECUTED.value
                action.completed_at = _utcnow()

            elif action_type == ContainmentActionType.INVALIDATE_CACHE:
                # Non-blocking Redis cache purge
                try:
                    redis = getattr(cache_service, "_client", None)
                    if redis is not None:
                        key = cache_service._make_key(target_identifier)
                        await redis.delete(key)
                    action.result_metadata = {"cache_invalidated": True}
                except Exception as exc:
                    logger.warning("Cache invalidation error during containment: %s", exc)
                    action.result_metadata = {"cache_invalidated": False, "error": str(exc)}
                action.status = ContainmentActionStatus.EXECUTED.value
                action.completed_at = _utcnow()

            elif action_type == ContainmentActionType.QUARANTINE_TARGET:
                # Target lookup by target_uuid or id
                target_stmt = select(MonitoringTarget).where(
                    MonitoringTarget.user_id == tenant_id,
                    (MonitoringTarget.target_uuid == target_identifier)
                    | (MonitoringTarget.url == target_identifier)
                    | (MonitoringTarget.normalized_domain == target_identifier),
                )
                t_res = await _execute(session, target_stmt)
                target = t_res.scalar_one_or_none()

                if not target:
                    action.status = ContainmentActionStatus.FAILED.value
                    action.error_message = f"Target '{target_identifier}' not found for tenant."
                    action.completed_at = _utcnow()
                    return action

                if not target.is_active:
                    # Idempotent no-op
                    action.status = ContainmentActionStatus.SKIPPED.value
                    action.result_metadata = {"reason": "target_already_inactive", "target_id": target.id}
                    action.completed_at = _utcnow()
                    return action

                target.is_active = False
                target.last_error_message = f"Auto-quarantined: action {action.action_uuid} ({reason})"
                action.rollback_metadata = {
                    "target_id": target.id,
                    "target_uuid": target.target_uuid,
                    "previous_is_active": True,
                    "action_uuid": action.action_uuid,
                }
                action.result_metadata = {"target_id": target.id, "quarantined": True}
                action.status = ContainmentActionStatus.EXECUTED.value
                action.completed_at = _utcnow()

            elif action_type == ContainmentActionType.CREATE_INCIDENT:
                # Check for existing open incident for target/tenant
                inc_id = None
                if alert_id:
                    alert_stmt = select(Alert).where(Alert.id == alert_id, Alert.user_id == tenant_id)
                    alert_res = await _execute(session, alert_stmt)
                    alert = alert_res.scalar_one_or_none()
                    if alert:
                        # Try to attach to existing incident or create new
                        if alert.incident_id:
                            inc_id = alert.incident_id
                        else:
                            # Create or bind incident via IncidentService
                            new_inc, _ = await incident_service.get_or_create_threat_incident(
                                session=session,
                                user_id=tenant_id,
                                normalized_domain=target_identifier,
                                severity=alert.severity or "CRITICAL",
                                title=f"Automated Containment Incident: {alert.title}",
                                description=f"Triggered by containment action on {target_identifier}. Reason: {reason}",
                                initial_alert_id=alert.id,
                            )
                            inc_id = new_inc.id
                action.incident_id = inc_id
                action.result_metadata = {"incident_id": inc_id}
                action.status = ContainmentActionStatus.EXECUTED.value
                action.completed_at = _utcnow()

            elif action_type == ContainmentActionType.EMIT_SOC_EVENT:
                # Insert transactional SOCEventStream row
                event_entry = SOCEventStream(
                    event_id=_uuid_str(),
                    tenant_id=tenant_id,
                    channel="soc",
                    event_type="containment_applied",
                    aggregate_id=str(alert_id or target_identifier),
                    payload_json={
                        "action_uuid": action.action_uuid,
                        "action_type": action_type.value,
                        "target_identifier": target_identifier,
                        "status": ContainmentActionStatus.EXECUTED.value,
                        "alert_id": alert_id,
                    },
                    created_at=_utcnow(),
                )
                session.add(event_entry)
                action.result_metadata = {"event_id": event_entry.event_id}
                action.status = ContainmentActionStatus.EXECUTED.value
                action.completed_at = _utcnow()

            elif action_type == ContainmentActionType.SEND_NOTIFICATION:
                # Enqueue Phase 5D outbox notification
                try:
                    await notification_service.create_in_app_notification(
                        session=session,
                        user_id=tenant_id,
                        title=f"SOC Containment Executed: {action_type.value}",
                        message=f"Action executed on {target_identifier}. Reason: {reason}",
                        severity="CRITICAL",
                    )
                    action.result_metadata = {"notification_enqueued": True}
                except Exception as exc:
                    logger.warning("Failed to create containment notification: %s", exc)
                    action.result_metadata = {"notification_enqueued": False, "error": str(exc)}
                action.status = ContainmentActionStatus.EXECUTED.value
                action.completed_at = _utcnow()

            # Record successful audit event
            audit = AuditEvent(
                action=f"CONTAINMENT_ACTION_{action.status}",
                actor_user_id=actor_user_id,
                target_resource="soc_containment_actions",
                resource_id=action.action_uuid,
                details={
                    "tenant_id": tenant_id,
                    "action_type": action_type.value,
                    "target_identifier": target_identifier,
                    "alert_id": alert_id,
                    "status": action.status,
                },
            )
            session.add(audit)

        except Exception as exc:
            action.status = ContainmentActionStatus.FAILED.value
            action.error_message = str(exc)
            action.completed_at = _utcnow()
            logger.error("Containment action %s failed: %s", action.action_uuid, exc)

        return action

    # ── Declarative Playbook Execution ────────────────────────────────────────

    async def execute_playbook(
        self,
        session: Session | AsyncSession,
        playbook_name: str,
        tenant_id: int,
        trigger_event: str,
        target_identifier: str,
        alert_id: int | None = None,
        target_id: int | None = None,
        actor_user_id: int | None = None,
        reason: str = "Automated playbook execution",
    ) -> SOCPlaybookRun:
        """
        Execute a declarative typed action sequence with concurrency limiting and stale worker fencing.
        """
        if isinstance(session, AsyncSession):
            bind = getattr(session, "bind", None)
            is_sqlite = not bind or getattr(getattr(bind, "dialect", None), "name", "") == "sqlite"
            if is_sqlite:
                async with _get_sqlite_action_async_lock(tenant_id):
                    return await self._do_execute_playbook(
                        session=session,
                        playbook_name=playbook_name,
                        tenant_id=tenant_id,
                        trigger_event=trigger_event,
                        target_identifier=target_identifier,
                        alert_id=alert_id,
                        target_id=target_id,
                        actor_user_id=actor_user_id,
                        reason=reason,
                    )
        return await self._do_execute_playbook(
            session=session,
            playbook_name=playbook_name,
            tenant_id=tenant_id,
            trigger_event=trigger_event,
            target_identifier=target_identifier,
            alert_id=alert_id,
            target_id=target_id,
            actor_user_id=actor_user_id,
            reason=reason,
        )

    async def _do_execute_playbook(
        self,
        session: Session | AsyncSession,
        playbook_name: str,
        tenant_id: int,
        trigger_event: str,
        target_identifier: str,
        alert_id: int | None = None,
        target_id: int | None = None,
        actor_user_id: int | None = None,
        reason: str = "Automated playbook execution",
    ) -> SOCPlaybookRun:
        idempotency_key = f"tenant:{tenant_id}:alert:{alert_id or 'none'}:playbook:{playbook_name}"

        # Check existing run
        existing_stmt = select(SOCPlaybookRun).where(SOCPlaybookRun.idempotency_key == idempotency_key)
        res = await _execute(session, existing_stmt)
        existing_run = res.scalar_one_or_none()
        if existing_run:
            return existing_run

        # Concurrency lease
        lease_token = await self._acquire_tenant_concurrency_lease(session, tenant_id)

        run = SOCPlaybookRun(
            run_uuid=_uuid_str(),
            playbook_name=playbook_name,
            playbook_version="1.0",
            tenant_id=tenant_id,
            trigger_event=trigger_event,
            alert_id=alert_id,
            target_id=target_id,
            status=PlaybookRunStatus.RUNNING.value,
            fencing_token=1,
            action_count=0,
            idempotency_key=idempotency_key,
            started_at=_utcnow(),
        )
        try:
            if isinstance(session, AsyncSession):
                async with session.begin_nested():
                    session.add(run)
                    await session.flush()
            else:
                with session.begin_nested():
                    session.add(run)
                    session.flush()
        except IntegrityError:
            await self._release_tenant_concurrency_lease(tenant_id, lease_token)
            for _ in range(20):
                await asyncio.sleep(0.05)
                res = await _execute(session, existing_stmt)
                existing = res.scalar_one_or_none()
                if existing:
                    return existing
            res = await _execute(session, existing_stmt)
            existing = res.scalar_one_or_none()
            if existing:
                return existing
            raise

        # Emit playbook_triggered event
        event_entry = SOCEventStream(
            event_id=_uuid_str(),
            tenant_id=tenant_id,
            channel="soc",
            event_type="playbook_triggered",
            aggregate_id=run.run_uuid,
            payload_json={
                "run_uuid": run.run_uuid,
                "playbook_name": playbook_name,
                "alert_id": alert_id,
                "target_identifier": target_identifier,
            },
            created_at=_utcnow(),
        )
        session.add(event_entry)

        # Define action sequence based on playbook name
        action_sequence: list[ContainmentActionType] = []
        if playbook_name == "CRITICAL_THREAT_AUTO_CONTAINMENT_V1":
            action_sequence = [
                ContainmentActionType.BLACKLIST_INDICATOR,
                ContainmentActionType.INVALIDATE_CACHE,
                ContainmentActionType.CREATE_INCIDENT,
                ContainmentActionType.EMIT_SOC_EVENT,
                ContainmentActionType.SEND_NOTIFICATION,
            ]
        elif playbook_name == "REPEATED_TARGET_COMPROMISE_QUARANTINE_V1":
            action_sequence = [
                ContainmentActionType.QUARANTINE_TARGET,
                ContainmentActionType.CREATE_INCIDENT,
                ContainmentActionType.EMIT_SOC_EVENT,
                ContainmentActionType.SEND_NOTIFICATION,
            ]
        elif playbook_name == "MANUAL_CONTAINMENT_V1":
            action_sequence = [ContainmentActionType.BLACKLIST_INDICATOR]
        else:
            run.status = PlaybookRunStatus.FAILED.value
            run.error_message = f"Unknown playbook: {playbook_name}"
            run.completed_at = _utcnow()
            await _commit(session)
            await self._release_tenant_concurrency_lease(tenant_id, lease_token)
            return run

        # Execute actions sequentially
        has_failure = False
        completed_actions = 0

        for action_type in action_sequence:
            # Fencing check before destructive actions
            if action_type in (ContainmentActionType.BLACKLIST_INDICATOR, ContainmentActionType.QUARANTINE_TARGET):
                # Verify run is still running and owned
                fence_stmt = select(SOCPlaybookRun).where(
                    SOCPlaybookRun.id == run.id,
                    SOCPlaybookRun.fencing_token == run.fencing_token,
                    SOCPlaybookRun.status == PlaybookRunStatus.RUNNING.value,
                )
                fence_res = await _execute(session, fence_stmt)
                if not fence_res.scalar_one_or_none():
                    run.status = PlaybookRunStatus.FAILED.value
                    run.error_message = "Stale worker fenced: lost execution authority."
                    run.completed_at = _utcnow()
                    await _commit(session)
                    await self._release_tenant_concurrency_lease(tenant_id, lease_token)
                    return run

            act = await self._do_execute_action(
                session=session,
                action_type=action_type,
                target_identifier=target_identifier,
                tenant_id=tenant_id,
                trigger_source=f"playbook:{playbook_name}",
                alert_id=alert_id,
                run_id=run.id,
                actor_user_id=actor_user_id,
                reason=reason,
            )
            completed_actions += 1

            if act.status == ContainmentActionStatus.FAILED.value:
                has_failure = True
                run.error_message = f"Action {action_type.value} failed: {act.error_message}"
                break

        run.action_count = completed_actions
        run.completed_at = _utcnow()
        if has_failure:
            run.status = PlaybookRunStatus.FAILED.value
        else:
            run.status = PlaybookRunStatus.COMPLETED.value

        # Emit completion/failure event
        comp_event = SOCEventStream(
            event_id=_uuid_str(),
            tenant_id=tenant_id,
            channel="soc",
            event_type="playbook_completed" if not has_failure else "playbook_failed",
            aggregate_id=run.run_uuid,
            payload_json={
                "run_uuid": run.run_uuid,
                "status": run.status,
                "action_count": run.action_count,
            },
            created_at=_utcnow(),
        )
        session.add(comp_event)

        await _flush(session)
        cursor_id = comp_event.cursor_id or 0
        await _commit(session)
        await self._release_tenant_concurrency_lease(tenant_id, lease_token)

        # Broadcast SSE post-commit
        event_broadcaster.publish_event_nowait(
            cursor_id=cursor_id,
            event_id=comp_event.event_id,
            tenant_id=tenant_id,
            channel="soc",
            event_type=comp_event.event_type,
            aggregate_id=run.run_uuid,
            payload=comp_event.payload_json,
        )

        return run

    # ── Alert Evaluation Hook ─────────────────────────────────────────────────

    async def evaluate_alert_containment(
        self, session: Session | AsyncSession, alert: Alert
    ) -> SOCPlaybookRun | None:
        """
        Post-commit alert evaluation hook:
        1. Checks tenant policy: auto_containment_enabled.
        2. Evaluates severity threshold (CRITICAL or HIGH).
        3. Evaluates Rule 0 allowlist.
        4. Triggers appropriate declarative playbook.
        """
        if not alert.user_id:
            return None

        policy = await self.get_or_create_policy(session, alert.user_id)
        if not policy.auto_containment_enabled:
            return None

        # Check minimum severity
        alert_sev = (alert.severity or "MEDIUM").upper()
        min_sev = policy.containment_min_severity.upper()
        if min_sev == "CRITICAL" and alert_sev != "CRITICAL":
            return None
        if min_sev == "HIGH" and alert_sev not in ("HIGH", "CRITICAL"):
            return None

        # Check target quarantine eligibility if auto_quarantine_enabled
        if policy.auto_quarantine_enabled:
            target_stmt = select(MonitoringTarget).where(
                MonitoringTarget.user_id == alert.user_id,
                (MonitoringTarget.url == alert.indicator_value)
                | (MonitoringTarget.normalized_domain == alert.indicator_value),
            )
            t_res = await _execute(session, target_stmt)
            target = t_res.scalar_one_or_none()
            if target and await self.evaluate_quarantine_eligibility(session, target):
                return await self.execute_playbook(
                    session=session,
                    playbook_name="REPEATED_TARGET_COMPROMISE_QUARANTINE_V1",
                    tenant_id=alert.user_id,
                    trigger_event="alert_quarantine_threshold_met",
                    target_identifier=target.target_uuid,
                    alert_id=alert.id,
                    target_id=target.id,
                    reason="Auto-quarantined: >= 3 active high-severity alerts in 10 minutes",
                )

        # Execute automated indicator containment if auto_blacklist_enabled
        if policy.auto_blacklist_enabled:
            return await self.execute_playbook(
                session=session,
                playbook_name="CRITICAL_THREAT_AUTO_CONTAINMENT_V1",
                tenant_id=alert.user_id,
                trigger_event="critical_alert_auto_containment",
                target_identifier=alert.indicator_value,
                alert_id=alert.id,
                reason=f"Automated containment for alert {alert.id} ({alert.title})",
            )

        return None

    # ── Provenance-Safe Rollback ───────────────────────────────────────────────

    async def revert_action(
        self,
        session: Session | AsyncSession,
        action_uuid: str,
        current_user: User,
    ) -> SOCContainmentAction:
        """
        Idempotently rollback an executed containment action.
        Only reverts entries owned by this specific containment action.
        """
        stmt = select(SOCContainmentAction).where(SOCContainmentAction.action_uuid == action_uuid)
        res = await _execute(session, stmt)
        action = res.scalar_one_or_none()

        if not action:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Containment action not found")

        # Strict tenant isolation
        if action.tenant_id != current_user.id and current_user.role != "admin":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Containment action not found")

        # Idempotent return if already reverted
        if action.status == ContainmentActionStatus.REVERTED.value:
            return action

        if action.status != ContainmentActionStatus.EXECUTED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot revert action in status '{action.status}' (must be 'EXECUTED')",
            )

        # 1. Action-specific Rollback
        if action.action_type == ContainmentActionType.BLACKLIST_INDICATOR.value:
            # Deactivate only rows created by this exact action
            bl_stmt = select(SOCDynamicBlacklist).where(
                SOCDynamicBlacklist.containment_action_id == action.id,
                SOCDynamicBlacklist.is_active.is_(True),
            )
            bl_res = await _execute(session, bl_stmt)
            bl_rows = bl_res.scalars().all()
            for row in bl_rows:
                row.is_active = False
                row.updated_at = _utcnow()

        elif action.action_type == ContainmentActionType.QUARANTINE_TARGET.value:
            # Reactivate target ONLY if this action owns the quarantine
            meta = action.rollback_metadata or {}
            target_id = meta.get("target_id")
            if target_id:
                t_stmt = select(MonitoringTarget).where(
                    MonitoringTarget.id == target_id,
                    MonitoringTarget.user_id == action.tenant_id,
                )
                t_res = await _execute(session, t_stmt)
                target = t_res.scalar_one_or_none()
                if target and target.last_error_message and action.action_uuid in target.last_error_message:
                    target.is_active = True
                    target.last_error_message = None

        elif action.action_type == ContainmentActionType.CREATE_INCIDENT.value:
            # Irreversible incident — mark action as reverted and emit compensatory audit event
            pass

        elif action.action_type in (
            ContainmentActionType.INVALIDATE_CACHE.value,
            ContainmentActionType.EMIT_SOC_EVENT.value,
            ContainmentActionType.SEND_NOTIFICATION.value,
        ):
            # Irreversible side effects — mark reverted and emit compensatory event
            pass

        action.status = ContainmentActionStatus.REVERTED.value
        action.reverted_at = _utcnow()
        action.reverted_by_user_id = current_user.id

        # Emit compensatory SSE event
        rev_event = SOCEventStream(
            event_id=_uuid_str(),
            tenant_id=action.tenant_id,
            channel="soc",
            event_type="containment_reverted",
            aggregate_id=action.action_uuid,
            payload_json={
                "action_uuid": action.action_uuid,
                "action_type": action.action_type,
                "reverted_by": current_user.id,
            },
            created_at=_utcnow(),
        )
        session.add(rev_event)

        audit = AuditEvent(
            action="CONTAINMENT_ACTION_REVERTED",
            actor_user_id=current_user.id,
            target_resource="soc_containment_actions",
            resource_id=action.action_uuid,
            details={"tenant_id": action.tenant_id, "action_type": action.action_type},
        )
        session.add(audit)

        await _flush(session)
        cursor_id = rev_event.cursor_id or 0
        await _commit(session)

        # Broadcast SSE
        event_broadcaster.publish_event_nowait(
            cursor_id=cursor_id,
            event_id=rev_event.event_id,
            tenant_id=action.tenant_id,
            channel="soc",
            event_type="containment_reverted",
            aggregate_id=action.action_uuid,
            payload=rev_event.payload_json,
        )

        return action


containment_service = ContainmentService()
