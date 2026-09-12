"""
backend/services/monitoring_service.py
───────────────────────────────────────
Sprint 5 Phase 5A: Monitoring Target Management Service.

Provides async service layer for monitoring target CRUD:
  - Target registration with SSRF pre-validation
  - Owner-scoped retrieval and pagination
  - Interval and activation updates
  - Per-user target limit enforcement
  - Soft-deactivation delete
  - Audit event creation

Strict multi-tenancy: every query includes `user_id = current_user.id` scope.
Sequential integer IDs are never exposed in API responses; target_uuid is used.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.security_network import (
    SSRFSecurityError,
    resolve_and_validate_host,
    validate_target_url,
)
from backend.database.models import AuditEvent, MonitoringTarget, User
from backend.schemas.alerts import (
    CheckNowResponse,
    MonitoringStatsResponse,
    MonitoringTargetDiagnosticsResponse,
)
from backend.schemas.monitor import (
    MonitoringTargetCreate,
    MonitoringTargetListResponse,
    MonitoringTargetResponse,
    MonitoringTargetUpdate,
)
from backend.utils.domain import normalize_canonical_domain
from src.utils.logger import logger

MAX_TARGETS_STANDARD_USER: int = int(os.getenv("MAX_TARGETS_STANDARD_USER", "20"))
MAX_TARGETS_ADMIN: int = int(os.getenv("MAX_TARGETS_ADMIN", "500"))
MAX_TARGETS_PER_USER: int = MAX_TARGETS_STANDARD_USER

# SQLite development / testing concurrency lock per user
# (PostgreSQL uses authoritative database-level SELECT ... FOR UPDATE)
_sqlite_user_locks: dict[tuple[int, int], asyncio.Lock] = {}
_sqlite_target_locks: dict[tuple[int, int], asyncio.Lock] = {}


def _get_sqlite_user_lock(user_id: int) -> asyncio.Lock:
    """Return an asyncio.Lock bound to the currently running event loop for user_id."""
    loop = asyncio.get_running_loop()
    key = (id(loop), user_id)
    if key not in _sqlite_user_locks:
        _sqlite_user_locks[key] = asyncio.Lock()
    return _sqlite_user_locks[key]


def _get_sqlite_target_lock(target_id: int) -> asyncio.Lock:
    """Return an asyncio.Lock bound to the currently running event loop for target_id."""
    loop = asyncio.get_running_loop()
    key = (id(loop), target_id)
    if key not in _sqlite_target_locks:
        _sqlite_target_locks[key] = asyncio.Lock()
    return _sqlite_target_locks[key]


def get_user_target_quota(user: User) -> int:
    """Return the active monitoring target quota based on authenticated user role."""
    if user.role == "admin":
        return MAX_TARGETS_ADMIN
    return MAX_TARGETS_STANDARD_USER


# ── Domain Exceptions ──────────────────────────────────────────────────────────

class MonitorServiceError(Exception):
    """Base exception for monitoring service operations."""


class MonitorNotFoundError(MonitorServiceError):
    """Raised when a target is not found or not accessible under tenant scope."""


class MonitorAccessDeniedError(MonitorServiceError):
    """Raised when a user attempts an unauthorized operation."""


class MonitorLimitExceededError(MonitorServiceError):
    """Raised when a user exceeds the per-user target limit."""


class MonitorSSRFError(MonitorServiceError):
    """Raised when the target URL fails SSRF pre-validation."""


class MonitorValidationError(MonitorServiceError):
    """Raised for invalid input that passes Pydantic but fails business logic."""


class MonitorTargetSuspendedError(MonitorServiceError):
    """Raised when an operation (e.g. resume) is rejected because the target is auto-suspended."""


class MonitorLeaseConflictError(MonitorServiceError):
    """Raised when check-now is requested while target has an active unexpired execution lease."""


# ── Service ────────────────────────────────────────────────────────────────────

class MonitoringService:
    """Async CRUD service for MonitoringTarget entities."""

    @asynccontextmanager
    async def _acquire_user_quota_lock(self, session: AsyncSession, user_id: int):
        """
        Acquire a per-user concurrency lock to serialize quota-check and target creation.

        PostgreSQL (Production Authoritative):
          Executes `SELECT id FROM users WHERE id = :user_id FOR UPDATE`, which acquires
          an authoritative row-level lock on the User record across all pods and workers.
        SQLite (Dev / Test Environment):
          SQLite does not support row-level FOR UPDATE. We serialize concurrent creations
          per user within the process using an asyncio mutex to emulate PostgreSQL row locking.
        """
        dialect = session.get_bind().dialect.name
        if dialect == "postgresql":
            await session.execute(
                select(User.id).where(User.id == user_id).with_for_update()
            )
            yield
        else:
            lock = _get_sqlite_user_lock(user_id)
            async with lock:
                yield

    # ── Registration ───────────────────────────────────────────────────────────

    async def register_target(
        self,
        session: AsyncSession,
        data: MonitoringTargetCreate,
        current_user: User,
        ip_address: str | None = None,
    ) -> MonitoringTarget:
        """
        Register a new monitoring target within a single atomic transaction.

        Security gates (in order, fail-closed):
          1. SSRF pre-validation (scheme, host resolution, private IP rejection).
          2. Concurrency-safe per-user quota lock and check:
             - Standard user: 20 active targets
             - Admin user: 500 active targets
             - PostgreSQL: Database-level row lock (SELECT ... FOR UPDATE on User)
             - SQLite: Per-user async lock emulation for local dev/testing
          3. Atomic insertion of MonitoringTarget + AuditEvent in ONE commit.

        Returns the newly created MonitoringTarget ORM object.
        """
        # Gate 1: SSRF pre-validation (fail-closed before acquiring locks)
        await self._ssrf_validate(data.url)

        quota_limit = get_user_target_quota(current_user)

        async with self._acquire_user_quota_lock(session, current_user.id):
            # Gate 2: Concurrency-safe quota limit check
            count_result = await session.execute(
                select(func.count()).where(
                    MonitoringTarget.user_id == current_user.id,
                    MonitoringTarget.is_active.is_(True),
                )
            )
            active_count: int = count_result.scalar_one()
            if active_count >= quota_limit:
                raise MonitorLimitExceededError(
                    f"Monitoring target limit of {quota_limit} reached for {current_user.role} user. "
                    "Deactivate an existing target before registering a new one."
                )

            # Normalize domain for indexing
            norm = normalize_canonical_domain(data.url)
            normalized_domain = (
                norm.get("registered_domain")
                or norm.get("fqdn")
                or norm.get("ip")
                or urlparse(data.url).hostname
                or data.url[:255]
            )

            target_uuid = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            target = MonitoringTarget(
                target_uuid=target_uuid,
                url=data.url,
                normalized_domain=normalized_domain[:255],
                check_interval_minutes=data.check_interval_minutes,
                is_active=True,
                next_check_at=now,
                consecutive_failures=0,
                user_id=current_user.id,
                created_at=now,
            )
            session.add(target)

            # Single atomic commit: audit event references stable target_uuid directly
            audit = AuditEvent(
                event_uuid=str(uuid.uuid4()),
                action="MONITORING_TARGET_CREATED",
                actor_user_id=current_user.id,
                target_resource="monitoring_targets",
                resource_id=target_uuid,
                details={
                    "target_uuid": target_uuid,
                    "url": data.url,
                    "normalized_domain": normalized_domain,
                    "check_interval_minutes": data.check_interval_minutes,
                },
                ip_address=ip_address,
                created_at=now,
            )
            session.add(audit)

            await session.commit()
            await session.refresh(target)

            logger.info(
                "[MONITOR_SVC] Registered target %s (%s) for user %d",
                target.target_uuid, normalized_domain, current_user.id,
            )
            return target

    # ── Retrieval ──────────────────────────────────────────────────────────────

    async def list_targets(
        self,
        session: AsyncSession,
        current_user: User,
        page: int = 1,
        page_size: int = 20,
        include_inactive: bool = False,
    ) -> MonitoringTargetListResponse:
        """List monitoring targets owned by the current user (or all if admin), paginated."""
        stmt = select(MonitoringTarget)
        if current_user.role != "admin":
            stmt = stmt.where(MonitoringTarget.user_id == current_user.id)
        if not include_inactive:
            stmt = stmt.where(MonitoringTarget.is_active.is_(True))
        stmt = stmt.order_by(MonitoringTarget.created_at.desc())

        # Total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total: int = (await session.execute(count_stmt)).scalar_one()

        # Paginated page
        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)
        rows = (await session.execute(stmt)).scalars().all()

        items = [MonitoringTargetResponse.model_validate(t) for t in rows]
        return MonitoringTargetListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            has_more=(offset + len(items)) < total,
        )

    async def get_target_by_uuid(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
    ) -> MonitoringTarget:
        """Retrieve a specific target by UUID, scoped to the owning user or admin."""
        stmt = select(MonitoringTarget).where(
            MonitoringTarget.target_uuid == target_uuid
        )
        if current_user.role != "admin":
            stmt = stmt.where(MonitoringTarget.user_id == current_user.id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()
        if target is None:
            raise MonitorNotFoundError(
                f"Monitoring target '{target_uuid}' not found or not accessible."
            )
        return target

    # ── Update ─────────────────────────────────────────────────────────────────

    async def update_target(
        self,
        session: AsyncSession,
        target_uuid: str,
        data: MonitoringTargetUpdate,
        current_user: User,
        ip_address: str | None = None,
    ) -> MonitoringTarget:
        """Update interval or activation state for a monitoring target."""
        target = await self.get_target_by_uuid(session, target_uuid, current_user)

        changed: dict[str, object] = {}
        if data.check_interval_minutes is not None:
            target.check_interval_minutes = data.check_interval_minutes
            changed["check_interval_minutes"] = data.check_interval_minutes

        if data.is_active is not None:
            # Reactivation semantics: when transitioning from False -> True,
            # explicitly reset next_check_at to current UTC time so scheduling starts fresh.
            if not target.is_active and data.is_active:
                now = datetime.now(timezone.utc)
                target.next_check_at = now
                changed["next_check_at"] = now.isoformat()
            target.is_active = data.is_active
            changed["is_active"] = data.is_active

        if not changed:
            return target  # No-op: nothing to update

        audit = AuditEvent(
            event_uuid=str(uuid.uuid4()),
            action="MONITORING_TARGET_UPDATED",
            actor_user_id=current_user.id,
            target_resource="monitoring_targets",
            resource_id=target.target_uuid,
            details={"changes": changed, "target_uuid": target_uuid},
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc),
        )
        session.add(audit)
        await session.commit()
        await session.refresh(target)

        logger.info(
            "[MONITOR_SVC] Updated target %s for user %d: %s",
            target_uuid, current_user.id, changed,
        )
        return target

    # ── Delete (Soft Deactivation) ─────────────────────────────────────────────

    async def delete_target(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
        ip_address: str | None = None,
    ) -> None:
        """
        Soft-delete a monitoring target by deactivating it.

        The row is preserved for audit/history; only `is_active` is set False.
        """
        target = await self.get_target_by_uuid(session, target_uuid, current_user)
        target.is_active = False

        audit = AuditEvent(
            event_uuid=str(uuid.uuid4()),
            action="MONITORING_TARGET_DELETED",
            actor_user_id=current_user.id,
            target_resource="monitoring_targets",
            resource_id=target.target_uuid,
            details={"target_uuid": target_uuid, "url": target.url},
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc),
        )
        session.add(audit)
        await session.commit()

        logger.info(
            "[MONITOR_SVC] Soft-deleted target %s for user %d",
            target_uuid, current_user.id,
        )

    # ── Operational Controls (Sprint 5 Phase 5C) ──────────────────────────────

    async def pause_target(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
        ip_address: str | None = None,
    ) -> MonitoringTarget:
        """
        Pause an active monitoring target.

        Preserves consecutive_failures history and emits TARGET_PAUSED audit event.

        Raises MonitorTargetSuspendedError if the target is already auto-suspended
        (consecutive_failures >= 5), preventing silent reinterpretation of SUSPENDED
        state as PAUSED.  Use reactivate() to recover a suspended target.
        """
        target = await self.get_target_by_uuid(session, target_uuid, current_user)

        # Guard: do not reinterpret an auto-suspended target (consecutive_failures >= 5)
        # as PAUSED — the caller must use reactivate() for suspended targets.
        if target.consecutive_failures >= 5 and not target.is_active:
            raise MonitorTargetSuspendedError(
                "Target is automatically suspended due to excessive failures; "
                "use reactivate to reset failures and restore the target."
            )

        target.is_active = False
        # consecutive_failures is intentionally NOT reset — pause preserves failure history.

        audit = AuditEvent(
            event_uuid=str(uuid.uuid4()),
            action="TARGET_PAUSED",
            actor_user_id=current_user.id,
            target_resource="monitoring_targets",
            resource_id=target.target_uuid,
            details={
                "target_uuid": target_uuid,
                "url": target.url,
                "consecutive_failures": target.consecutive_failures,
            },
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc),
        )
        session.add(audit)
        await session.commit()
        await session.refresh(target)

        logger.info(
            "[MONITOR_SVC] Paused target %s for user %d (failures=%d)",
            target_uuid, current_user.id, target.consecutive_failures,
        )
        return target

    async def resume_target(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
        ip_address: str | None = None,
    ) -> MonitoringTarget:
        """
        Resume a paused monitoring target.

        Rejects auto-suspended targets (consecutive_failures >= 5) with MonitorTargetSuspendedError.
        Emits TARGET_RESUMED audit event.
        """
        target = await self.get_target_by_uuid(session, target_uuid, current_user)
        if target.consecutive_failures >= 5:
            raise MonitorTargetSuspendedError(
                "Target is automatically suspended due to excessive failures; use reactivate to reset failures."
            )

        now = datetime.now(timezone.utc)
        target.is_active = True
        target.next_check_at = now

        audit = AuditEvent(
            event_uuid=str(uuid.uuid4()),
            action="TARGET_RESUMED",
            actor_user_id=current_user.id,
            target_resource="monitoring_targets",
            resource_id=target.target_uuid,
            details={
                "target_uuid": target_uuid,
                "url": target.url,
                "consecutive_failures": target.consecutive_failures,
            },
            ip_address=ip_address,
            created_at=now,
        )
        session.add(audit)
        await session.commit()
        await session.refresh(target)

        logger.info(
            "[MONITOR_SVC] Resumed target %s for user %d",
            target_uuid, current_user.id,
        )
        return target

    async def reactivate_target(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
        ip_address: str | None = None,
    ) -> MonitoringTarget:
        """
        Recover and reactivate an auto-suspended or paused monitoring target.

        Resets consecutive_failures to 0, sets is_active to True, schedules immediate check,
        and emits TARGET_REACTIVATED audit event.
        """
        target = await self.get_target_by_uuid(session, target_uuid, current_user)
        now = datetime.now(timezone.utc)
        target.consecutive_failures = 0
        target.is_active = True
        target.next_check_at = now

        audit = AuditEvent(
            event_uuid=str(uuid.uuid4()),
            action="TARGET_REACTIVATED",
            actor_user_id=current_user.id,
            target_resource="monitoring_targets",
            resource_id=target.target_uuid,
            details={
                "target_uuid": target_uuid,
                "url": target.url,
                "consecutive_failures": 0,
            },
            ip_address=ip_address,
            created_at=now,
        )
        session.add(audit)
        await session.commit()
        await session.refresh(target)

        logger.info(
            "[MONITOR_SVC] Reactivated target %s for user %d (failures reset to 0)",
            target_uuid, current_user.id,
        )
        return target

    async def trigger_check_now(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
        ip_address: str | None = None,
    ) -> CheckNowResponse:
        """
        Trigger an on-demand check for an active target using authoritative execution lease.

        Rejects inactive targets (paused or suspended).
        Atomically claims execution lease; rejects active in-flight lease with MonitorLeaseConflictError.
        Dispatches ClaimedTarget to MonitoringWorkerPool.
        """
        from backend.services.monitoring_worker import monitoring_worker_pool
        from backend.services.scheduler_service import WORKER_LEASE_SECONDS, ClaimedTarget

        target = await self.get_target_by_uuid(session, target_uuid, current_user)
        if not target.is_active:
            if target.consecutive_failures >= 5:
                raise MonitorTargetSuspendedError(
                    "Target is automatically suspended due to excessive failures; use reactivate to reset failures."
                )
            raise MonitorValidationError(
                "Target is paused; resume the target before requesting check-now."
            )

        now = datetime.now(timezone.utc)
        token = str(uuid.uuid4())
        dialect = session.get_bind().dialect.name

        # Read current epoch from scheduler_state
        epoch = 1
        try:
            epoch_res = await session.execute(
                text("SELECT current_epoch FROM scheduler_state WHERE id = 1")
            )
            epoch_row = epoch_res.fetchone()
            if epoch_row and epoch_row[0] is not None:
                epoch = int(epoch_row[0])
        except Exception:
            epoch = 1

        if dialect == "postgresql":
            # Atomic PostgreSQL lease claim
            result = await session.execute(
                text(
                    "UPDATE monitoring_targets "
                    "SET execution_token = :token, "
                    "    execution_epoch = :epoch, "
                    "    execution_expires_at = NOW() + INTERVAL ':sec seconds' "
                    "WHERE target_uuid = :target_uuid "
                    "  AND is_active = TRUE "
                    "  AND (execution_token IS NULL OR execution_expires_at < NOW()) "
                    "RETURNING id"
                ).bindparams(
                    token=token,
                    epoch=epoch,
                    sec=WORKER_LEASE_SECONDS,
                    target_uuid=target_uuid,
                )
            )
            row = result.fetchone()
            if not row:
                raise MonitorLeaseConflictError(
                    "Target check is already in progress with an active execution lease."
                )
            target.execution_token = token
            target.execution_epoch = epoch
            target.execution_expires_at = now + timedelta(seconds=WORKER_LEASE_SECONDS)

            audit = AuditEvent(
                event_uuid=str(uuid.uuid4()),
                action="TARGET_CHECK_NOW_REQUESTED",
                actor_user_id=current_user.id,
                target_resource="monitoring_targets",
                resource_id=target.target_uuid,
                details={
                    "target_uuid": target_uuid,
                    "url": target.url,
                    "execution_token": token,
                    "execution_epoch": epoch,
                },
                ip_address=ip_address,
                created_at=now,
            )
            session.add(audit)
            await session.commit()
        else:
            # SQLite safe lease claim with target mutex
            now_sqlite = now.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
            expires_sqlite = (
                now.replace(tzinfo=None) + timedelta(seconds=WORKER_LEASE_SECONDS)
            ).strftime("%Y-%m-%d %H:%M:%S.%f")

            lock = _get_sqlite_target_lock(target.id)
            async with lock:
                cur_res = await session.execute(
                    select(
                        MonitoringTarget.execution_token,
                        MonitoringTarget.execution_expires_at,
                    ).where(MonitoringTarget.id == target.id)
                )
                cur_token, cur_expires = cur_res.one()
                if cur_token is not None and cur_expires is not None:
                    cur_exp_dt = (
                        cur_expires
                        if cur_expires.tzinfo
                        else cur_expires.replace(tzinfo=timezone.utc)
                    )
                    if cur_exp_dt > now:
                        raise MonitorLeaseConflictError(
                            "Target check is already in progress with an active execution lease."
                        )

                upd_res = await session.execute(
                    text(
                        "UPDATE monitoring_targets "
                        "SET execution_token = :token, "
                        "    execution_epoch = :epoch, "
                        "    execution_expires_at = :expires "
                        "WHERE id = :target_id "
                        "  AND is_active = 1 "
                        "  AND (execution_token IS NULL OR execution_expires_at < :now)"
                    ),
                    {
                        "token": token,
                        "epoch": epoch,
                        "expires": expires_sqlite,
                        "target_id": target.id,
                        "now": now_sqlite,
                    },
                )
                if upd_res.rowcount == 0:
                    raise MonitorLeaseConflictError(
                        "Target check is already in progress with an active execution lease."
                    )

                target.execution_token = token
                target.execution_epoch = epoch
                target.execution_expires_at = now + timedelta(seconds=WORKER_LEASE_SECONDS)

                audit = AuditEvent(
                    event_uuid=str(uuid.uuid4()),
                    action="TARGET_CHECK_NOW_REQUESTED",
                    actor_user_id=current_user.id,
                    target_resource="monitoring_targets",
                    resource_id=target.target_uuid,
                    details={
                        "target_uuid": target_uuid,
                        "url": target.url,
                        "execution_token": token,
                        "execution_epoch": epoch,
                    },
                    ip_address=ip_address,
                    created_at=now,
                )
                session.add(audit)
                await session.commit()

        claimed = ClaimedTarget(
            target_id=target.id,
            url=target.url,
            normalized_domain=target.normalized_domain,
            check_interval_minutes=target.check_interval_minutes,
            execution_token=token,
            execution_epoch=epoch,
            user_id=target.user_id,
        )

        # Submit target to existing authoritative worker pool
        await monitoring_worker_pool.submit_target(claimed)

        logger.info(
            "[MONITOR_SVC] check-now dispatched for target %s (token=%s, epoch=%d)",
            target_uuid, token[:8], epoch,
        )
        return CheckNowResponse(
            target_uuid=target.target_uuid,
            execution_token=token,
            dispatched_at=now,
            message="Target check successfully dispatched to worker pool.",
        )

    async def get_target_diagnostics(
        self,
        session: AsyncSession,
        target_uuid: str,
        current_user: User,
    ) -> MonitoringTargetDiagnosticsResponse:
        """
        Retrieve diagnostic metadata from the last execution of a target.

        Reads target fields with fallback to latest check AuditEvent details.
        """
        target = await self.get_target_by_uuid(session, target_uuid, current_user)
        last_status = target.last_status_code
        last_lat = target.last_response_time_ms
        last_err = target.last_error_message

        if last_status is None or last_lat is None or last_err is None:
            audit_res = await session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.resource_id == target.target_uuid,
                    AuditEvent.action.in_([
                        "MONITORING_CHECK_EXECUTED",
                        "TARGET_AUTO_SUSPENDED",
                        "TARGET_SSRF_ABORTED",
                    ]),
                )
                .order_by(AuditEvent.created_at.desc())
                .limit(1)
            )
            latest_audit = audit_res.scalar_one_or_none()
            if latest_audit and latest_audit.details:
                details = latest_audit.details
                if last_status is None and "status_code" in details:
                    last_status = details.get("status_code")
                if last_lat is None and "latency_ms" in details:
                    last_lat = details.get("latency_ms")
                if last_err is None:
                    if latest_audit.action == "TARGET_SSRF_ABORTED":
                        last_err = "SSRF outbound probe blocked"
                    elif details.get("failure_category"):
                        last_err = str(details.get("failure_category"))
                    elif details.get("event_subtype") == "MONITORING_TARGET_UNREACHABLE":
                        last_err = "Probe network failure: target unreachable"

        return MonitoringTargetDiagnosticsResponse(
            target_uuid=target.target_uuid,
            url=target.url,
            is_active=target.is_active,
            consecutive_failures=target.consecutive_failures,
            last_checked_at=target.last_checked_at,
            last_status_code=last_status,
            last_response_time_ms=last_lat,
            last_error_message=last_err,
            last_prediction=target.last_prediction,
            last_confidence=target.last_confidence,
        )

    async def get_monitoring_stats(
        self,
        session: AsyncSession,
        current_user: User,
    ) -> MonitoringStatsResponse:
        """
        Compute aggregated target health distribution and scheduler telemetry.
        """
        from backend.services.monitoring_worker import monitoring_worker_pool

        is_admin = current_user.role == "admin"
        base_cond = []
        if not is_admin:
            base_cond.append(MonitoringTarget.user_id == current_user.id)

        # total_targets
        total = (
            await session.execute(
                select(func.count(MonitoringTarget.id)).where(*base_cond)
            )
        ).scalar_one() or 0

        # active_targets
        active = (
            await session.execute(
                select(func.count(MonitoringTarget.id)).where(
                    *base_cond,
                    MonitoringTarget.is_active.is_(True),
                    MonitoringTarget.consecutive_failures < 5,
                )
            )
        ).scalar_one() or 0

        # paused_targets
        paused = (
            await session.execute(
                select(func.count(MonitoringTarget.id)).where(
                    *base_cond,
                    MonitoringTarget.is_active.is_(False),
                    MonitoringTarget.consecutive_failures < 5,
                )
            )
        ).scalar_one() or 0

        # suspended_targets
        suspended = (
            await session.execute(
                select(func.count(MonitoringTarget.id)).where(
                    *base_cond,
                    MonitoringTarget.is_active.is_(False),
                    MonitoringTarget.consecutive_failures >= 5,
                )
            )
        ).scalar_one() or 0

        # failing_targets
        failing = (
            await session.execute(
                select(func.count(MonitoringTarget.id)).where(
                    *base_cond,
                    MonitoringTarget.is_active.is_(True),
                    MonitoringTarget.consecutive_failures > 0,
                )
            )
        ).scalar_one() or 0

        # Scheduler health
        leader_pod: str | None = None
        epoch: int = 0
        try:
            sched_res = await session.execute(
                text("SELECT leader_pod_id, current_epoch FROM scheduler_state WHERE id = 1")
            )
            sched_row = sched_res.fetchone()
            if sched_row:
                leader_pod = sched_row[0]
                epoch = int(sched_row[1]) if sched_row[1] is not None else 0
        except Exception:
            pass

        active_workers = len(monitoring_worker_pool._active_tasks)
        pool_capacity = monitoring_worker_pool.global_max_workers

        return MonitoringStatsResponse(
            total_targets=total,
            active_targets=active,
            paused_targets=paused,
            suspended_targets=suspended,
            failing_targets=failing,
            scheduler_leader=leader_pod,
            scheduler_epoch=epoch,
            active_workers=active_workers,
            pool_capacity=pool_capacity,
        )

    # ── SSRF Helper ────────────────────────────────────────────────────────────

    @staticmethod
    async def _ssrf_validate(url: str) -> None:
        """
        SSRF pre-validation at registration time (fail-closed).

        Raises MonitorSSRFError if the URL fails any security check.
        Never raises for purely syntactic issues (those are caught by Pydantic).
        """
        try:
            # validate_target_url checks scheme, hostname presence, and IP literals
            _scheme, hostname, _port, _path = validate_target_url(url)
        except SSRFSecurityError as exc:
            raise MonitorSSRFError(f"URL failed SSRF scheme/syntax validation: {exc}") from exc

        try:
            await resolve_and_validate_host(hostname)
        except SSRFSecurityError as exc:
            raise MonitorSSRFError(f"URL failed SSRF host validation: {exc}") from exc
        except Exception as exc:
            raise MonitorSSRFError(f"URL host resolution failed: {exc}") from exc


# ── Singleton Instance ─────────────────────────────────────────────────────────
monitoring_service = MonitoringService()
