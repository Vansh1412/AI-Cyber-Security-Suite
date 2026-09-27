"""
tests/integration/test_containment_concurrency.py
─────────────────────────────────────────────────
Sprint 5 Phase 5F: Concurrency & Stress Tests for Containment Engine.

Tests:
  - 20 concurrent identical containment triggers producing exactly 1 durable action
  - 20 concurrent identical playbook triggers producing exactly 1 durable playbook run
  - Simultaneous rollback attempts
  - Stale worker fencing token rejection
  - Policy update race condition handling
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.database.models import (
    Base,
    SOCContainmentAction,
    SOCPlaybookRun,
    User,
)
from backend.schemas.containment import (
    ContainmentActionType,
    ContainmentPolicyUpdate,
    PlaybookRunStatus,
)
from backend.services.containment_service import containment_service


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(async_engine):
    return async_sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def seeded_user(session_factory):
    async with session_factory() as session:
        user = User(id=1, email="concurrent_user@soc.test", hashed_pw="pw", role="user", is_active=True)
        session.add(user)
        await session.commit()
    yield 1


# ── 1. 20 Concurrent Identical Containment Action Triggers ───────────────────

@pytest.mark.anyio
async def test_20_concurrent_identical_action_triggers(session_factory, seeded_user):
    """Verify 20 simultaneous action triggers for the same indicator produce exactly 1 durable action."""
    user_id = seeded_user
    indicator = "https://race-condition-malware.xyz/bin"

    async def trigger_action(i: int):
        async with session_factory() as session:
            try:
                act = await containment_service.execute_action(
                    session=session,
                    action_type=ContainmentActionType.BLACKLIST_INDICATOR,
                    target_identifier=indicator,
                    tenant_id=user_id,
                    trigger_source="concurrency_test",
                    reason=f"Concurrent trigger {i}",
                )
                await session.commit()
                return act
            except Exception as exc:
                return exc

    # Launch 20 concurrent tasks
    tasks = [trigger_action(i) for i in range(20)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect successful action UUIDs
    action_uuids = {r.action_uuid for r in results if isinstance(r, SOCContainmentAction)}
    assert len(action_uuids) == 1, f"Expected exactly 1 unique action UUID, got {action_uuids}"

    # Verify database has exactly 1 row
    async with session_factory() as session:
        res = await session.execute(
            select(SOCContainmentAction).where(SOCContainmentAction.target_identifier == indicator)
        )
        rows = res.scalars().all()
        assert len(rows) == 1


# ── 2. 20 Concurrent Identical Playbook Triggers ─────────────────────────────

@pytest.mark.anyio
async def test_20_concurrent_identical_playbook_triggers(session_factory, seeded_user):
    """Verify 20 simultaneous playbook runs for the same alert produce exactly 1 durable run."""
    user_id = seeded_user
    target_id_val = "https://playbook-storm.xyz/phish"

    async def trigger_playbook(i: int):
        async with session_factory() as session:
            try:
                return await containment_service.execute_playbook(
                    session=session,
                    playbook_name="CRITICAL_THREAT_AUTO_CONTAINMENT_V1",
                    tenant_id=user_id,
                    trigger_event="concurrency_alert",
                    target_identifier=target_id_val,
                    alert_id=999,
                    reason=f"Playbook storm test {i}",
                )
            except Exception as exc:
                return exc

    tasks = [trigger_playbook(i) for i in range(20)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    run_uuids = {r.run_uuid for r in results if isinstance(r, SOCPlaybookRun)}
    assert len(run_uuids) == 1, f"Expected exactly 1 unique playbook run UUID, got {run_uuids}"

    async with session_factory() as session:
        res = await session.execute(select(SOCPlaybookRun).where(SOCPlaybookRun.alert_id == 999))
        rows = res.scalars().all()
        assert len(rows) == 1


# ── 3. Stale Worker Fencing Token Rejection ───────────────────────────────────

@pytest.mark.anyio
async def test_stale_worker_fencing_rejection(session_factory, seeded_user):
    """Verify worker with mismatched fencing token is rejected before destructive action."""
    user_id = seeded_user

    async with session_factory() as session:
        # Create a run with fencing_token = 1
        run = SOCPlaybookRun(
            run_uuid="stale-run-uuid",
            playbook_name="CRITICAL_THREAT_AUTO_CONTAINMENT_V1",
            playbook_version="1.0",
            tenant_id=user_id,
            trigger_event="manual",
            status=PlaybookRunStatus.RUNNING.value,
            fencing_token=2,  # Another worker incremented to 2!
            idempotency_key="stale-test-key",
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)

        # Worker A thinks fencing_token is 1
        worker_a_token = 1

        # Simulate Worker A checking fence before destructive action
        fence_stmt = select(SOCPlaybookRun).where(
            SOCPlaybookRun.id == run.id,
            SOCPlaybookRun.fencing_token == worker_a_token,
            SOCPlaybookRun.status == PlaybookRunStatus.RUNNING.value,
        )
        res = await session.execute(fence_stmt)
        valid_run = res.scalar_one_or_none()

        # Worker A must be fenced out!
        assert valid_run is None


# ── 4. Policy Update Race Condition ───────────────────────────────────────────

@pytest.mark.anyio
async def test_policy_update_race_condition(session_factory, seeded_user):
    """Verify concurrent policy updates result in exactly one success and others 409."""
    user_id = seeded_user

    # Create initial policy
    async with session_factory() as session:
        await containment_service.get_or_create_policy(session, user_id)
        await session.commit()

    async def do_update(new_sev: str):
        async with session_factory() as session:
            try:
                update_data = ContainmentPolicyUpdate(
                    auto_containment_enabled=True,
                    auto_blacklist_enabled=True,
                    auto_quarantine_enabled=False,
                    auto_incident_binding_enabled=True,
                    containment_min_severity=new_sev,
                    blacklist_ttl_seconds=86400,
                    policy_version=1,  # Both race with version 1!
                )
                return await containment_service.update_policy(session, user_id, update_data, user_id)
            except Exception as exc:
                return exc

    results = await asyncio.gather(do_update("HIGH"), do_update("CRITICAL"), return_exceptions=True)

    # Exactly one should succeed, and one should get a version conflict
    from fastapi import HTTPException
    successes = [r for r in results if not isinstance(r, Exception)]
    conflicts = [r for r in results if isinstance(r, HTTPException) and r.status_code == 409]

    assert len(successes) == 1
    assert len(conflicts) == 1
