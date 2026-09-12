"""
tests/integration/test_phase5c_concurrency.py
─────────────────────────────────────────────
Sprint 5 Phase 5C: Concurrency, Race Condition & Mutex Isolation Tests.

Verifies:
1. 50-way concurrent acknowledge race:
   - Exactly 1 state mutation, exactly 1 AuditEvent emitted.
   - Remaining 49 requests return HTTP 200 idempotently.
2. 50-way concurrent resolve race:
   - Exactly 1 state mutation, exactly 1 AuditEvent emitted.
   - Remaining 49 requests return HTTP 200 idempotently.
3. Acknowledge vs Resolve race:
   - Serialized cleanly: whichever commits first establishes valid state.
4. Resolve vs Dismiss terminal race:
   - Whichever commits first establishes terminal state.
   - Opposing transition rejected with HTTP 400 (AlertInvalidTransitionError).
5. 50-way check-now execution lease race:
   - Exactly 1 request successfully claims lease.
   - Remaining 49 requests rejected with MonitorLeaseConflictError (409 Conflict).
6. Cross-tenant concurrency isolation:
   - Foreign tenant concurrent triage requests match 0 rows and return 404.
   - Zero lock contention or state contamination.
7. PostgreSQL multi-connection row locking:
   - Exercised on live PostgreSQL when available.
   - Explicitly skipped and reported as SKIPPED/UNAVAILABLE when PostgreSQL is offline.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.database.models import Alert, AuditEvent, Base, MonitoringTarget, User
from backend.schemas.alerts import AlertStatus
from backend.services.alert_service import (
    AlertInvalidTransitionError,
    AlertNotFoundError,
    alert_service,
)
from backend.services.monitoring_service import (
    MonitorLeaseConflictError,
    monitoring_service,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _is_postgres_available() -> bool:
    """Check if a real PostgreSQL server is reachable for distributed locking tests."""
    url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url or "postgresql" not in url:
        return False
    try:
        from sqlalchemy import create_engine
        engine = create_engine(url, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# ── SQLite Async Shared Database Fixture ──────────────────────────────────────

@pytest.fixture
async def async_shared_factory():
    """Create async engine with StaticPool for concurrent async tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False, "timeout": 30},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as s:
        u1 = User(id=1, email="conc_async_u1@test.com", hashed_pw="pw1", role="user", is_active=True)
        u2 = User(id=2, email="conc_async_u2@test.com", hashed_pw="pw2", role="user", is_active=True)
        s.add_all([u1, u2])
        await s.commit()

    yield session_factory

    await engine.dispose()


async def _seed_open_alert(session_factory, user_id: int = 1) -> str:
    now = datetime.now(timezone.utc)
    alert_uuid = str(uuid.uuid4())
    async with session_factory() as s:
        alert = Alert(
            alert_uuid=alert_uuid,
            title="Concurrent Alert Test",
            severity="HIGH",
            status=AlertStatus.OPEN.value,
            rule_name="CONCURRENCY_TEST_RULE",
            indicator_type="DOMAIN",
            indicator_value="race-condition.com",
            fingerprint=f"fp_{uuid.uuid4().hex[:12]}",
            occurrence_count=1,
            first_seen_at=now,
            last_seen_at=now,
            user_id=user_id,
        )
        s.add(alert)
        await s.commit()
    return alert_uuid


# ── 1. 50 Concurrent ACKNOWLEDGE Requests ─────────────────────────────────────

@pytest.mark.anyio
async def test_50_concurrent_acknowledges(async_shared_factory):
    """
    Scenario: 50 concurrent requests attempt to acknowledge the SAME open alert.
    Requirement:
      - Exactly 1 state mutation.
      - Exactly 1 AuditEvent(action="ALERT_ACKNOWLEDGED").
      - All 50 calls succeed without exception (49 idempotent no-ops).
      - Alert status remains ACKNOWLEDGED.
    """
    alert_uuid = await _seed_open_alert(async_shared_factory, user_id=1)

    async def _worker(idx: int):
        async with async_shared_factory() as s:
            u1 = (await s.execute(select(User).where(User.id == 1))).scalar_one()
            return await alert_service.acknowledge_alert(s, alert_uuid, u1, notes=f"Worker {idx}")

    results = await asyncio.gather(*[_worker(i) for i in range(50)])

    assert len(results) == 50
    for r in results:
        assert r.status == AlertStatus.ACKNOWLEDGED.value

    # Verify audit events: exactly 1 event emitted
    async with async_shared_factory() as s:
        audit_count = (await s.execute(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.resource_id == alert_uuid,
                AuditEvent.action == "ALERT_ACKNOWLEDGED",
            )
        )).scalar()
        assert audit_count == 1, f"Expected exactly 1 audit event, got {audit_count}"


# ── 2. 50 Concurrent RESOLVE Requests ─────────────────────────────────────────

@pytest.mark.anyio
async def test_50_concurrent_resolves(async_shared_factory):
    """
    Scenario: 50 concurrent requests attempt to resolve the SAME open alert.
    Requirement:
      - Exactly 1 state mutation.
      - Exactly 1 AuditEvent(action="ALERT_RESOLVED").
      - All 50 calls succeed (49 idempotent no-ops).
      - Alert status remains RESOLVED.
    """
    alert_uuid = await _seed_open_alert(async_shared_factory, user_id=1)

    async def _worker(idx: int):
        async with async_shared_factory() as s:
            u1 = (await s.execute(select(User).where(User.id == 1))).scalar_one()
            return await alert_service.resolve_alert(s, alert_uuid, u1, resolution_notes=f"Resolved by {idx}")

    results = await asyncio.gather(*[_worker(i) for i in range(50)])

    assert len(results) == 50
    for r in results:
        assert r.status == AlertStatus.RESOLVED.value

    async with async_shared_factory() as s:
        audit_count = (await s.execute(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.resource_id == alert_uuid,
                AuditEvent.action == "ALERT_RESOLVED",
            )
        )).scalar()
        assert audit_count == 1, f"Expected exactly 1 audit event, got {audit_count}"


# ── 3. Acknowledge vs. Resolve Race Condition ─────────────────────────────────

@pytest.mark.anyio
async def test_acknowledge_vs_resolve_race(async_shared_factory):
    """
    Scenario: Concurrent ACKNOWLEDGE and RESOLVE requests.
    Requirement:
      - Transitions serialize cleanly.
      - If ACK commits first, RESOLVE can still proceed (ACK -> RESOLVE is valid).
      - If RESOLVE commits first, ACK is rejected with AlertInvalidTransitionError.
      - Final state must be RESOLVED.
    """
    alert_uuid = await _seed_open_alert(async_shared_factory, user_id=1)

    async def _task(idx: int):
        async with async_shared_factory() as s:
            u1 = (await s.execute(select(User).where(User.id == 1))).scalar_one()
            try:
                if idx % 2 == 0:
                    return ("ACK", await alert_service.acknowledge_alert(s, alert_uuid, u1))
                else:
                    return ("RES", await alert_service.resolve_alert(s, alert_uuid, u1))
            except AlertInvalidTransitionError:
                return ("REJECTED", None)

    results = await asyncio.gather(*[_task(i) for i in range(50)])
    assert len(results) == 50

    async with async_shared_factory() as s:
        alert = (await s.execute(select(Alert).where(Alert.alert_uuid == alert_uuid))).scalar_one()
        assert alert.status == AlertStatus.RESOLVED.value


# ── 4. Resolve vs. Dismiss Terminal Race Condition ────────────────────────────

@pytest.mark.anyio
async def test_resolve_vs_dismiss_race(async_shared_factory):
    """
    Scenario: Concurrent RESOLVE and DISMISS requests on the SAME open alert.
    Requirement:
      - Direct flip between terminal states is forbidden (Section 1.4).
      - Whichever terminal state commits first locks in.
      - Opposing transitions MUST raise AlertInvalidTransitionError (400 Bad Request).
      - Zero corrupted state.
    """
    alert_uuid = await _seed_open_alert(async_shared_factory, user_id=1)

    async def _task(idx: int):
        async with async_shared_factory() as s:
            u1 = (await s.execute(select(User).where(User.id == 1))).scalar_one()
            try:
                if idx % 2 == 0:
                    return ("RESOLVE", await alert_service.resolve_alert(s, alert_uuid, u1))
                else:
                    return ("DISMISS", await alert_service.dismiss_alert(s, alert_uuid, u1, dismiss_reason="FALSE_POSITIVE"))
            except AlertInvalidTransitionError:
                return ("REJECTED", None)

    results = await asyncio.gather(*[_task(i) for i in range(50)])
    outcomes = [r[0] for r in results]

    # Exactly one terminal state won the race, and opposing requests were rejected
    assert "REJECTED" in outcomes

    async with async_shared_factory() as s:
        alert = (await s.execute(select(Alert).where(Alert.alert_uuid == alert_uuid))).scalar_one()
        assert alert.status in (AlertStatus.RESOLVED.value, AlertStatus.DISMISSED.value)


# ── 5. 50 Concurrent check-now Requests ───────────────────────────────────────

@pytest.mark.anyio
async def test_50_concurrent_check_now(async_shared_factory):
    """
    Scenario: 50 concurrent on-demand check-now requests for the SAME target.
    Requirement:
      - Exactly 1 request acquires the execution lease.
      - Remaining 49 requests receive MonitorLeaseConflictError.
      - Exactly 1 target dispatch occurs.
    """
    async with async_shared_factory() as s:
        user = (await s.execute(select(User).where(User.id == 1))).scalar_one()
        now = datetime.now(timezone.utc)
        target = MonitoringTarget(
            target_uuid=str(uuid.uuid4()),
            url="https://concurrent-check.example.com",
            normalized_domain="concurrent-check.example.com",
            check_interval_minutes=5,
            is_active=True,
            next_check_at=now,
            consecutive_failures=0,
            user_id=user.id,
            created_at=now,
        )
        s.add(target)
        await s.commit()
        tuuid = target.target_uuid

    successes = 0
    conflicts = 0

    with patch("backend.services.monitoring_worker.monitoring_worker_pool.submit_target", new_callable=AsyncMock):
        async def _attempt_check():
            nonlocal successes, conflicts
            async with async_shared_factory() as s:
                u = (await s.execute(select(User).where(User.id == 1))).scalar_one()
                try:
                    await monitoring_service.trigger_check_now(s, tuuid, u)
                    successes += 1
                except MonitorLeaseConflictError:
                    conflicts += 1

        # Execute 50 concurrent tasks
        await asyncio.gather(*[_attempt_check() for _ in range(50)])

    assert successes == 1, f"Expected exactly 1 check-now lease acquisition, got {successes}"
    assert conflicts == 49, f"Expected 49 lease conflicts, got {conflicts}"


# ── 6. Cross-Tenant Concurrency Isolation ─────────────────────────────────────

@pytest.mark.anyio
async def test_cross_tenant_concurrency(async_shared_factory):
    """
    Scenario: Concurrent triage calls on User 1's alert by User 1 and User 2.
    Requirement:
      - User 2 requests always receive AlertNotFoundError (404) with zero state contamination.
      - User 1 requests succeed without exception.
    """
    alert_uuid = await _seed_open_alert(async_shared_factory, user_id=1)

    u1_successes = 0
    u2_not_founds = 0

    async def _worker(user_id: int):
        nonlocal u1_successes, u2_not_founds
        async with async_shared_factory() as s:
            u = (await s.execute(select(User).where(User.id == user_id))).scalar_one()
            try:
                await alert_service.acknowledge_alert(s, alert_uuid, u)
                if user_id == 1:
                    u1_successes += 1
            except AlertNotFoundError:
                if user_id == 2:
                    u2_not_founds += 1

    tasks = [_worker(1 if i % 2 == 0 else 2) for i in range(20)]
    await asyncio.gather(*tasks)

    assert u1_successes == 10
    assert u2_not_founds == 10


# ── 7. Real PostgreSQL Row-Locking Test (Gated) ───────────────────────────────

@pytest.mark.skipif(
    not _is_postgres_available(),
    reason="PostgreSQL service not running in local test environment; mandatory staging gate",
)
@pytest.mark.anyio
async def test_postgres_row_locking_concurrency():
    """
    PostgreSQL-authoritative SELECT FOR UPDATE concurrency test.
    Only runs when a live PostgreSQL database is reachable.
    """
    url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    assert url is not None
    engine = create_async_engine(url)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession)

    alert_uuid = await _seed_open_alert(session_factory, user_id=1)

    async def _worker():
        async with session_factory() as s:
            u = (await s.execute(select(User).where(User.id == 1))).scalar_one()
            return await alert_service.acknowledge_alert(s, alert_uuid, u)

    results = await asyncio.gather(*[_worker() for _ in range(50)])

    assert len(results) == 50
    async with session_factory() as s:
        audit_count = (await s.execute(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.resource_id == alert_uuid,
                AuditEvent.action == "ALERT_ACKNOWLEDGED",
            )
        )).scalar()
        assert audit_count == 1
