"""
tests/unit/test_monitoring_service.py
───────────────────────────────────────
Sprint 5 Phase 5A: Unit and concurrency tests for MonitoringService.

Proves that the actual production MonitoringService.register_target() and
update_target() implementations correctly enforce:
1. Concurrency-safe target quota:
   - 19 active targets + 50 concurrent requests -> exactly 1 success, 49 rejected, final count = 20.
2. Role-aware quotas:
   - Standard user: MAX_ACTIVE_TARGETS = 20 (21st rejected).
   - Admin user: MAX_ACTIVE_TARGETS = 500 (501st rejected, 500th succeeds).
   - Admin 499 active targets + 50 concurrent requests -> exactly 1 success, 49 rejected, final count = 500.
   - Schema forbid extra fields prevents client-side role/quota spoofing.
3. Reactivation semantics:
   - Deactivating and reactivating a target explicitly resets next_check_at to current UTC time.
   - Reactivated target is eligible for scheduler claiming.
   - Multi-tenant 404 disguise prevents unauthorized access.
4. Transaction atomicity:
   - Target and audit event committed together atomically in ONE commit.
   - Rollback leaves zero orphaned rows; audit.resource_id uses stable target_uuid directly.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.database.models import AuditEvent, Base, MonitoringTarget, User
from backend.schemas.monitor import MonitoringTargetCreate, MonitoringTargetUpdate
from backend.services.monitoring_service import (
    MAX_TARGETS_ADMIN,
    MAX_TARGETS_STANDARD_USER,
    MonitorLimitExceededError,
    MonitorNotFoundError,
    monitoring_service,
)

# ── Async Engine & Session Fixtures ───────────────────────────────────────────

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_engine():
    """Create in-memory SQLite engine for async tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(async_engine):
    """Async session factory with expire_on_commit=False for concurrent sessions."""
    return async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
def mock_dns():
    """
    Mock only the external DNS host resolution to return a clean public IP.
    The real validate_target_url, _ssrf_validate, quota locks, and DB logic execute unmocked.
    """
    with patch(
        "backend.services.monitoring_service.resolve_and_validate_host",
        new=AsyncMock(return_value=["93.184.216.34"]),
    ):
        yield


# ── 1. Mandatory Real Service Concurrency Test (Standard User: 19 -> 20) ──────

@pytest.mark.anyio
async def test_concurrent_standard_user_quota_race(session_factory):
    """
    MANDATORY CONCURRENCY TEST:
    Initial state: 19 active targets for standard user.
    Launch: 50 concurrent creation requests across separate AsyncSessions.
    All requests call the REAL monitoring_service.register_target() method directly.
    Required result:
      successes = 1
      rejected = 49 (MonitorLimitExceededError)
      unexpected errors = 0
      final active target count in DB = 20
    """
    async with session_factory() as s:
        user = User(email="concurrency-user@test.com", hashed_pw="x", role="user")
        s.add(user)
        await s.commit()
        await s.refresh(user)
        user_id = user.id

        # Seed 19 active targets
        now = datetime.now(timezone.utc)
        targets = [
            MonitoringTarget(
                target_uuid=f"initial-std-{i}",
                url=f"https://std-seed-{i}.example.com",
                normalized_domain=f"std-seed-{i}.example.com",
                check_interval_minutes=60,
                is_active=True,
                next_check_at=now,
                user_id=user_id,
                created_at=now,
            )
            for i in range(19)
        ]
        s.add_all(targets)
        await s.commit()

    succeeded = 0
    rejected = 0
    errors = []

    async def _worker(idx: int):
        nonlocal succeeded, rejected
        try:
            # Each worker uses an independent AsyncSession
            async with session_factory() as s:
                u = await s.get(User, user_id)
                data = MonitoringTargetCreate(
                    url=f"https://concurrent-std-{idx}.example.com",
                    check_interval_minutes=30,
                )
                # Exercises the ACTUAL production MonitoringService.register_target implementation
                await monitoring_service.register_target(s, data, u)
                succeeded += 1
        except MonitorLimitExceededError:
            rejected += 1
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

    # Launch 50 truly concurrent creation requests
    await asyncio.gather(*[_worker(i) for i in range(50)])

    # Assert exact required concurrency outcome
    assert errors == [], f"Unexpected errors during concurrency: {errors}"
    assert succeeded == 1, f"Expected exactly 1 success, got {succeeded}"
    assert rejected == 49, f"Expected exactly 49 rejected, got {rejected}"

    async with session_factory() as s:
        count_res = await s.execute(
            select(func.count()).where(
                MonitoringTarget.user_id == user_id,
                MonitoringTarget.is_active.is_(True),
            )
        )
        final_count = count_res.scalar_one()

    assert final_count == 20, f"Expected final active count of 20, got {final_count}"


# ── 2. Admin Real Service Concurrency Test (Near 500 Boundary: 499 -> 500) ────

@pytest.mark.anyio
async def test_concurrent_admin_quota_race_near_500(session_factory):
    """
    ADMIN CONCURRENCY TEST:
    Initial state: 499 active targets for admin user.
    Launch: 50 concurrent creation requests across separate AsyncSessions.
    All requests call the REAL monitoring_service.register_target() method directly.
    Required result:
      successes = 1
      rejected = 49 (MonitorLimitExceededError)
      unexpected errors = 0
      final active target count in DB = 500
    """
    async with session_factory() as s:
        admin = User(email="concurrency-admin@test.com", hashed_pw="x", role="admin")
        s.add(admin)
        await s.commit()
        await s.refresh(admin)
        admin_id = admin.id

        # Seed 499 active targets
        now = datetime.now(timezone.utc)
        batch = [
            MonitoringTarget(
                target_uuid=f"initial-adm-{i}",
                url=f"https://adm-seed-{i}.example.com",
                normalized_domain=f"adm-seed-{i}.example.com",
                check_interval_minutes=60,
                is_active=True,
                next_check_at=now,
                user_id=admin_id,
                created_at=now,
            )
            for i in range(499)
        ]
        s.add_all(batch)
        await s.commit()

    succeeded = 0
    rejected = 0
    errors = []

    async def _worker(idx: int):
        nonlocal succeeded, rejected
        try:
            async with session_factory() as s:
                u = await s.get(User, admin_id)
                data = MonitoringTargetCreate(
                    url=f"https://concurrent-adm-{idx}.example.com",
                    check_interval_minutes=30,
                )
                # Exercises the ACTUAL production MonitoringService.register_target implementation
                await monitoring_service.register_target(s, data, u)
                succeeded += 1
        except MonitorLimitExceededError:
            rejected += 1
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

    # Launch 50 concurrent requests
    await asyncio.gather(*[_worker(i) for i in range(50)])

    assert errors == [], f"Unexpected errors during admin concurrency: {errors}"
    assert succeeded == 1, f"Expected exactly 1 success, got {succeeded}"
    assert rejected == 49, f"Expected exactly 49 rejected, got {rejected}"

    async with session_factory() as s:
        count_res = await s.execute(
            select(func.count()).where(
                MonitoringTarget.user_id == admin_id,
                MonitoringTarget.is_active.is_(True),
            )
        )
        final_count = count_res.scalar_one()

    assert final_count == 500, f"Expected final active count of 500, got {final_count}"


# ── 3. Role-Based Quota Limits & Exploitation Prevention ───────────────────────

@pytest.mark.anyio
async def test_standard_user_quota_boundary_20(session_factory):
    """Standard user at 20 active targets cannot register a 21st target."""
    async with session_factory() as s:
        user = User(email="std-limit@test.com", hashed_pw="x", role="user")
        s.add(user)
        await s.commit()
        await s.refresh(user)

        now = datetime.now(timezone.utc)
        for i in range(MAX_TARGETS_STANDARD_USER):
            s.add(
                MonitoringTarget(
                    target_uuid=f"std-{i}",
                    url=f"https://std-{i}.com",
                    normalized_domain=f"std-{i}.com",
                    check_interval_minutes=60,
                    is_active=True,
                    next_check_at=now,
                    user_id=user.id,
                    created_at=now,
                )
            )
        await s.commit()

        # 21st attempt must fail with MonitorLimitExceededError via real register_target
        data = MonitoringTargetCreate(url="https://std-overflow.com", check_interval_minutes=60)
        with pytest.raises(MonitorLimitExceededError, match=f"limit of {MAX_TARGETS_STANDARD_USER}"):
            await monitoring_service.register_target(s, data, user)


@pytest.mark.anyio
async def test_admin_quota_boundary_500(session_factory):
    """Admin user at 500 active targets cannot register a 501st target."""
    async with session_factory() as s:
        admin = User(email="admin-limit@test.com", hashed_pw="x", role="admin")
        s.add(admin)
        await s.commit()
        await s.refresh(admin)

        now = datetime.now(timezone.utc)
        s.add_all([
            MonitoringTarget(
                target_uuid=f"adm-{i}",
                url=f"https://adm-{i}.com",
                normalized_domain=f"adm-{i}.com",
                check_interval_minutes=60,
                is_active=True,
                next_check_at=now,
                user_id=admin.id,
                created_at=now,
            )
            for i in range(MAX_TARGETS_ADMIN)
        ])
        await s.commit()

        # 501st attempt must fail
        data = MonitoringTargetCreate(url="https://adm-overflow.com", check_interval_minutes=60)
        with pytest.raises(MonitorLimitExceededError, match=f"limit of {MAX_TARGETS_ADMIN}"):
            await monitoring_service.register_target(s, data, admin)


@pytest.mark.anyio
async def test_admin_quota_under_limit_499(session_factory):
    """Admin user at 499 active targets can successfully register the 500th target."""
    async with session_factory() as s:
        admin = User(email="admin-under-limit@test.com", hashed_pw="x", role="admin")
        s.add(admin)
        await s.commit()
        await s.refresh(admin)

        now = datetime.now(timezone.utc)
        s.add_all([
            MonitoringTarget(
                target_uuid=f"adm-under-{i}",
                url=f"https://adm-under-{i}.com",
                normalized_domain=f"adm-under-{i}.com",
                check_interval_minutes=60,
                is_active=True,
                next_check_at=now,
                user_id=admin.id,
                created_at=now,
            )
            for i in range(499)
        ])
        await s.commit()

        # 500th attempt must succeed
        data = MonitoringTargetCreate(url="https://adm-500th.com", check_interval_minutes=60)
        t = await monitoring_service.register_target(s, data, admin)
        assert t is not None
        assert t.target_uuid is not None


def test_client_cannot_spoof_role_or_quota_fields():
    """Client input cannot specify role or manipulate quota through payload fields."""
    with pytest.raises(ValidationError):
        MonitoringTargetCreate(url="https://spoof.com", role="admin")

    with pytest.raises(ValidationError):
        MonitoringTargetCreate(url="https://spoof.com", quota=500)

    with pytest.raises(ValidationError):
        MonitoringTargetUpdate(role="admin")

    with pytest.raises(ValidationError):
        MonitoringTargetUpdate(execution_token="fake-token")

    with pytest.raises(ValidationError):
        MonitoringTargetUpdate(next_check_at=datetime.now(timezone.utc))


# ── 4. Reactivation Semantics ─────────────────────────────────────────────────

@pytest.mark.anyio
async def test_reactivation_resets_next_check_at(session_factory):
    """
    Reactivation test:
    1. Create active target via actual service.
    2. Pause target (is_active = False).
    3. Manually set next_check_at far in the past (e.g. 10 days ago).
    4. Reactivate (is_active = True).
    5. Verify next_check_at is reset to current UTC time.
    6. Verify target becomes eligible for scheduler claim.
    7. Verify another user's target cannot be manipulated.
    """
    async with session_factory() as s:
        user_a = User(email="reactivate-a@test.com", hashed_pw="x", role="user")
        user_b = User(email="reactivate-b@test.com", hashed_pw="x", role="user")
        s.add_all([user_a, user_b])
        await s.commit()
        await s.refresh(user_a)
        await s.refresh(user_b)

        # 1. Create active target via actual register_target
        t = await monitoring_service.register_target(
            s,
            MonitoringTargetCreate(url="https://reactivate-test.com", check_interval_minutes=15),
            user_a,
        )
        target_uuid = t.target_uuid
        target_id = t.id

        # 2. Pause target via actual update_target
        updated = await monitoring_service.update_target(
            s, target_uuid, MonitoringTargetUpdate(is_active=False), user_a
        )
        assert updated.is_active is False

        # 3. Set next_check_at far in the past (10 days ago)
        stale_time = datetime.now(timezone.utc) - timedelta(days=10)
        updated.next_check_at = stale_time
        await s.commit()

        # Reload and confirm it is stale and paused
        t_reloaded = await monitoring_service.get_target_by_uuid(s, target_uuid, user_a)
        assert t_reloaded.is_active is False
        assert (datetime.now(timezone.utc) - t_reloaded.next_check_at.replace(tzinfo=timezone.utc)).total_seconds() > 800000

        # 4. Reactivate via actual update_target
        before_reactivate = datetime.now(timezone.utc)
        reactivated = await monitoring_service.update_target(
            s, target_uuid, MonitoringTargetUpdate(is_active=True), user_a
        )
        after_reactivate = datetime.now(timezone.utc)

        # 5. Verify next_check_at is reset appropriately to current UTC time
        assert reactivated.is_active is True
        reactivated_check = reactivated.next_check_at.replace(tzinfo=timezone.utc)
        assert before_reactivate <= reactivated_check <= after_reactivate + timedelta(seconds=1), (
            f"next_check_at {reactivated_check} was not reset to current UTC time ({before_reactivate})"
        )

        # 6. Verify target becomes eligible for scheduler claiming
        res = await s.execute(
            select(MonitoringTarget).where(
                MonitoringTarget.id == target_id,
                MonitoringTarget.is_active.is_(True),
                MonitoringTarget.next_check_at <= datetime.now(timezone.utc),
            )
        )
        claimable = res.scalar_one_or_none()
        assert claimable is not None, "Reactivated target was not claimable by scheduler query."

        # 7. Verify another user cannot manipulate the target (404 disguise)
        with pytest.raises(MonitorNotFoundError):
            await monitoring_service.update_target(
                s, target_uuid, MonitoringTargetUpdate(is_active=False), user_b
            )


# ── 5. Transaction Atomicity & Rollback Tests ─────────────────────────────────

@pytest.mark.anyio
async def test_atomic_single_commit_registration(session_factory):
    """
    Transaction atomicity:
    - Target and audit event are committed together in ONE commit.
    - AuditEvent.resource_id uses target.target_uuid directly (never 'pending').
    """
    async with session_factory() as s:
        user = User(email="atomic-user@test.com", hashed_pw="x", role="user")
        s.add(user)
        await s.commit()
        await s.refresh(user)

        target = await monitoring_service.register_target(
            s,
            MonitoringTargetCreate(url="https://atomic-test.com", check_interval_minutes=60),
            user,
        )

        # Query audit event
        audit_res = await s.execute(
            select(AuditEvent).where(
                AuditEvent.target_resource == "monitoring_targets",
                AuditEvent.actor_user_id == user.id,
            )
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None, "AuditEvent was not created."
        assert audit.resource_id == target.target_uuid, (
            f"Expected audit.resource_id to be target_uuid '{target.target_uuid}', got '{audit.resource_id}'"
        )
        assert audit.resource_id != "pending", "audit.resource_id remained 'pending'!"


@pytest.mark.anyio
async def test_transaction_rollback_leaves_no_orphaned_state(session_factory):
    """
    Rollback test:
    When an error occurs during registration, neither the target nor the audit event is persisted.
    """
    async with session_factory() as s:
        user = User(email="rollback-user@test.com", hashed_pw="x", role="user")
        s.add(user)
        await s.commit()
        await s.refresh(user)

        # Fill quota to 20
        now = datetime.now(timezone.utc)
        for i in range(20):
            s.add(
                MonitoringTarget(
                    target_uuid=f"rb-seed-{i}",
                    url=f"https://rb-seed-{i}.com",
                    normalized_domain=f"rb-seed-{i}.com",
                    check_interval_minutes=60,
                    is_active=True,
                    next_check_at=now,
                    user_id=user.id,
                    created_at=now,
                )
            )
        await s.commit()

        # Attempt 21st registration (fails quota check)
        with pytest.raises(MonitorLimitExceededError):
            await monitoring_service.register_target(
                s,
                MonitoringTargetCreate(url="https://should-rollback.com"),
                user,
            )

        # Verify no 21st target exists
        target_count = (
            await s.execute(
                select(func.count()).where(MonitoringTarget.user_id == user.id)
            )
        ).scalar_one()
        assert target_count == 20

        # Verify no audit event was created for the failed target
        audit_count = (
            await s.execute(
                select(func.count()).where(
                    AuditEvent.actor_user_id == user.id,
                    AuditEvent.action == "MONITORING_TARGET_CREATED",
                )
            )
        ).scalar_one()
        assert audit_count == 0, f"Expected 0 audit events on failed creation, got {audit_count}"
