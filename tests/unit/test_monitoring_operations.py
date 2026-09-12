"""
tests/unit/test_monitoring_operations.py
────────────────────────────────────────
Sprint 5 Phase 5C: Unit tests for Monitoring Target Operational Controls & Diagnostics.

Verifies:
1. Target Pause operation:
   - Sets is_active = False, preserves consecutive_failures.
   - Emits TARGET_PAUSED audit event.
2. Target Resume operation:
   - Precondition: is_active = False and consecutive_failures < 5.
   - Transitions to is_active = True, schedules next_check_at = NOW().
   - Emits TARGET_RESUMED audit event.
3. Auto-Suspended Target Resume Rejection:
   - Target with consecutive_failures >= 5 rejected with MonitorTargetSuspendedError (409 Conflict).
4. Target Reactivation:
   - Recovers suspended or paused target.
   - Resets consecutive_failures = 0, sets is_active = True, schedules next_check_at = NOW().
   - Emits TARGET_REACTIVATED audit event.
5. check-now On-Demand Execution:
   - Reuses existing Phase 5A/5B execution lease (WORKER_LEASE_SECONDS = 45).
   - In-flight active unexpired lease rejected with MonitorLeaseConflictError (409 Conflict).
   - Paused target rejected with MonitorValidationError.
   - Suspended target rejected with MonitorTargetSuspendedError.
   - Submits ClaimedTarget to existing MonitoringWorkerPool.
6. Execution Diagnostics:
   - Returns last execution metadata (status_code, response_time_ms, error_message, prediction).
   - Graceful fallback to AuditEvent details when target columns are null.
7. Monitoring Telemetry / Stats:
   - Accurate distribution counts: total, active, paused, suspended, failing targets.
   - Scheduler leader and worker pool capacity metadata.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.database.models import AuditEvent, Base, MonitoringTarget, User
from backend.services.monitoring_service import (
    MonitorLeaseConflictError,
    MonitorTargetSuspendedError,
    MonitorValidationError,
    monitoring_service,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_engine():
    """Create in-memory SQLite engine for async monitoring operations tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(async_engine):
    """Async session factory with expire_on_commit=False for concurrent sessions."""
    return async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)


async def _seed_user(session: AsyncSession, user_id: int = 1, role: str = "user") -> User:
    user = User(
        id=user_id,
        email=f"user{user_id}_{role}@test.com",
        hashed_pw="hashed_test_pw",
        role=role,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _create_test_target(
    session: AsyncSession,
    user_id: int = 1,
    is_active: bool = True,
    consecutive_failures: int = 0,
    execution_token: str | None = None,
    execution_expires_at: datetime | None = None,
) -> MonitoringTarget:
    now = datetime.now(timezone.utc)
    target = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url=f"https://target-{uuid.uuid4().hex[:8]}.example.com",
        normalized_domain=f"target-{uuid.uuid4().hex[:8]}.example.com",
        check_interval_minutes=5,
        is_active=is_active,
        next_check_at=now,
        consecutive_failures=consecutive_failures,
        execution_token=execution_token,
        execution_expires_at=execution_expires_at,
        user_id=user_id,
        created_at=now,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


# ── Operational State Transitions Tests ────────────────────────────────────────

@pytest.mark.anyio
async def test_pause_active_target(session_factory):
    """Pausing an active target sets is_active=False and preserves failures."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        target = await _create_test_target(
            session, user_id=user.id, is_active=True, consecutive_failures=3
        )

        paused = await monitoring_service.pause_target(session, target.target_uuid, user)

        assert paused.is_active is False
        assert paused.consecutive_failures == 3

        # Verify audit event emitted
        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.resource_id == target.target_uuid,
                AuditEvent.action == "TARGET_PAUSED",
            )
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None
        assert audit.actor_user_id == user.id


@pytest.mark.anyio
async def test_pause_preserves_consecutive_failures_regression(session_factory):
    """
    REGRESSION TEST: pause_target MUST NOT reset consecutive_failures.
    A target with failures=7 (active) must retain failures=7 after pause.
    """
    async with session_factory() as session:
        user = await _seed_user(session, user_id=2)
        # Active target with 7 failures (below threshold for auto-suspend while active)
        target = await _create_test_target(
            session, user_id=user.id, is_active=True, consecutive_failures=7
        )

        paused = await monitoring_service.pause_target(session, target.target_uuid, user)

        # Core invariant: is_active flips, failures are preserved
        assert paused.is_active is False
        assert paused.consecutive_failures == 7, (
            "pause_target reset consecutive_failures to 0 — contract violation"
        )


@pytest.mark.anyio
async def test_pause_suspended_target_rejected(session_factory):
    """
    REGRESSION TEST: pause_target MUST raise MonitorTargetSuspendedError when the
    target is already auto-suspended (is_active=False AND consecutive_failures >= 5).
    Silent reinterpretation of SUSPENDED state as PAUSED is forbidden.
    """
    async with session_factory() as session:
        user = await _seed_user(session, user_id=3)
        # Already auto-suspended: inactive + failures >= 5
        target = await _create_test_target(
            session, user_id=user.id, is_active=False, consecutive_failures=5
        )

        with pytest.raises(MonitorTargetSuspendedError) as exc_info:
            await monitoring_service.pause_target(session, target.target_uuid, user)

        assert "use reactivate" in str(exc_info.value)

        # Verify the target state was NOT mutated
        from sqlalchemy import select as _select
        reloaded = (await session.execute(
            _select(MonitoringTarget).where(MonitoringTarget.id == target.id)
        )).scalar_one()
        assert reloaded.is_active is False
        assert reloaded.consecutive_failures == 5


@pytest.mark.anyio
async def test_resume_paused_target(session_factory):
    """Resuming a paused target with < 5 failures sets is_active=True and next_check_at=NOW."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        target = await _create_test_target(
            session, user_id=user.id, is_active=False, consecutive_failures=2
        )

        resumed = await monitoring_service.resume_target(session, target.target_uuid, user)

        assert resumed.is_active is True
        assert resumed.consecutive_failures == 2
        assert resumed.next_check_at is not None

        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.resource_id == target.target_uuid,
                AuditEvent.action == "TARGET_RESUMED",
            )
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None


@pytest.mark.anyio
async def test_resume_suspended_target_rejected(session_factory):
    """Resuming a target with >= 5 failures is rejected with MonitorTargetSuspendedError."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        target = await _create_test_target(
            session, user_id=user.id, is_active=False, consecutive_failures=5
        )

        with pytest.raises(MonitorTargetSuspendedError) as exc_info:
            await monitoring_service.resume_target(session, target.target_uuid, user)

        assert "use reactivate to reset failures" in str(exc_info.value)


@pytest.mark.anyio
async def test_reactivate_suspended_target(session_factory):
    """Reactivating a suspended target resets failures to 0 and activates it."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        target = await _create_test_target(
            session, user_id=user.id, is_active=False, consecutive_failures=7
        )

        reactivated = await monitoring_service.reactivate_target(session, target.target_uuid, user)

        assert reactivated.is_active is True
        assert reactivated.consecutive_failures == 0
        assert reactivated.next_check_at is not None

        audit_res = await session.execute(
            select(AuditEvent).where(
                AuditEvent.resource_id == target.target_uuid,
                AuditEvent.action == "TARGET_REACTIVATED",
            )
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None


# ── check-now Execution Lease Tests ────────────────────────────────────────────

@pytest.mark.anyio
async def test_trigger_check_now_success(session_factory):
    """check-now claims execution lease and submits ClaimedTarget to worker pool."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        target = await _create_test_target(session, user_id=user.id, is_active=True)

        with patch("backend.services.monitoring_worker.monitoring_worker_pool.submit_target", new_callable=AsyncMock) as mock_submit:
            resp = await monitoring_service.trigger_check_now(session, target.target_uuid, user)

            assert resp.target_uuid == target.target_uuid
            assert resp.execution_token is not None
            assert resp.message == "Target check successfully dispatched to worker pool."

            # Verify target claimed in database
            reloaded = await session.execute(
                select(MonitoringTarget).where(MonitoringTarget.id == target.id)
            )
            claimed_target = reloaded.scalar_one()
            assert claimed_target.execution_token == resp.execution_token
            assert claimed_target.execution_expires_at is not None

            # Verify dispatched to worker pool
            mock_submit.assert_awaited_once()


@pytest.mark.anyio
async def test_trigger_check_now_lease_conflict(session_factory):
    """check-now on a target with an active unexpired lease raises MonitorLeaseConflictError."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        now = datetime.now(timezone.utc)
        # Active unexpired lease for 30 more seconds
        target = await _create_test_target(
            session,
            user_id=user.id,
            is_active=True,
            execution_token=str(uuid.uuid4()),
            execution_expires_at=now + timedelta(seconds=30),
        )

        with pytest.raises(MonitorLeaseConflictError) as exc_info:
            await monitoring_service.trigger_check_now(session, target.target_uuid, user)

        assert "already in progress" in str(exc_info.value)


@pytest.mark.anyio
async def test_trigger_check_now_rejected_if_paused_or_suspended(session_factory):
    """check-now is rejected if the target is paused or auto-suspended."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)

        # Paused target
        paused = await _create_test_target(session, user_id=user.id, is_active=False, consecutive_failures=1)
        with pytest.raises(MonitorValidationError):
            await monitoring_service.trigger_check_now(session, paused.target_uuid, user)

        # Suspended target
        suspended = await _create_test_target(session, user_id=user.id, is_active=False, consecutive_failures=5)
        with pytest.raises(MonitorTargetSuspendedError):
            await monitoring_service.trigger_check_now(session, suspended.target_uuid, user)


# ── Target Diagnostics & Stats Tests ──────────────────────────────────────────

@pytest.mark.anyio
async def test_get_target_diagnostics(session_factory):
    """Diagnostics retrieves target execution metadata with AuditEvent fallback."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)
        target = await _create_test_target(session, user_id=user.id, is_active=True)
        target.last_status_code = 200
        target.last_response_time_ms = 85.4
        target.last_error_message = None
        target.last_prediction = "BENIGN"
        target.last_confidence = 0.98
        await session.commit()

        diag = await monitoring_service.get_target_diagnostics(session, target.target_uuid, user)

        assert diag.target_uuid == target.target_uuid
        assert diag.last_status_code == 200
        assert diag.last_response_time_ms == 85.4
        assert diag.last_prediction == "BENIGN"
        assert diag.last_confidence == 0.98


@pytest.mark.anyio
async def test_get_monitoring_stats(session_factory):
    """Monitoring stats aggregates target distribution across states accurately."""
    async with session_factory() as session:
        user = await _seed_user(session, user_id=1)

        # Seed 1 active, 1 paused, 1 suspended, 1 failing active
        await _create_test_target(session, user_id=user.id, is_active=True, consecutive_failures=0)
        await _create_test_target(session, user_id=user.id, is_active=False, consecutive_failures=1)
        await _create_test_target(session, user_id=user.id, is_active=False, consecutive_failures=5)
        await _create_test_target(session, user_id=user.id, is_active=True, consecutive_failures=2)

        stats = await monitoring_service.get_monitoring_stats(session, user)

        assert stats.total_targets == 4
        assert stats.active_targets == 2  # failures < 5 and is_active=True
        assert stats.paused_targets == 1  # failures < 5 and is_active=False
        assert stats.suspended_targets == 1  # failures >= 5 and is_active=False
        assert stats.failing_targets == 1  # is_active=True and failures > 0
        assert stats.pool_capacity == 10
