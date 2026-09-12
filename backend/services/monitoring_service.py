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
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.security_network import (
    SSRFSecurityError,
    resolve_and_validate_host,
    validate_target_url,
)
from backend.database.models import AuditEvent, MonitoringTarget, User
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


def _get_sqlite_user_lock(user_id: int) -> asyncio.Lock:
    """Return an asyncio.Lock bound to the currently running event loop for user_id."""
    loop = asyncio.get_running_loop()
    key = (id(loop), user_id)
    if key not in _sqlite_user_locks:
        _sqlite_user_locks[key] = asyncio.Lock()
    return _sqlite_user_locks[key]


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
        """List monitoring targets owned by the current user, paginated."""
        stmt = select(MonitoringTarget).where(
            MonitoringTarget.user_id == current_user.id
        )
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
        """Retrieve a specific target by UUID, scoped to the owning user."""
        result = await session.execute(
            select(MonitoringTarget).where(
                MonitoringTarget.target_uuid == target_uuid,
                MonitoringTarget.user_id == current_user.id,
            )
        )
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
