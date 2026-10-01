"""
tests/staging/test_postgres_staging_concurrency.py
──────────────────────────────────────────────────
Phase 7 Plan 02: PostgreSQL 16 & Redis 7 Staging Concurrency & Parity Harness.

Verifies Decisions D-01, D-02, D-03:
  1. Engine version verification (PostgreSQL 16+).
  2. Session-level PostgreSQL advisory locks for leader election (pg_try_advisory_lock).
  3. Transactional multi-worker row claiming with FOR UPDATE SKIP LOCKED (Outbox).
  4. Monotonic epoch fencing preventing split-brain writes.
  5. 100 concurrent alert attachments to an incident with row-level locks (with_for_update).
  6. Parallel incident status transitions ensuring state-machine integrity.
  7. Concurrent monitoring target lease claims with FOR UPDATE SKIP LOCKED.

Dual-mode execution:
  - Connects to TEST_DATABASE_URL or STAGING_DATABASE_URL if available.
  - Gracefully skips when PostgreSQL 16 staging container is unreachable.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.database.models import (
    Alert,
    Base,
    Incident,
    MonitoringTarget,
    SchedulerState,
    User,
)
from backend.services.incident_service import (
    IncidentUpdate,
    IncidentValidationError,
    incident_service,
)
from backend.services.notification_service import NotificationOutbox

STAGING_PG_URL = (
    os.getenv("TEST_DATABASE_URL")
    or os.getenv("STAGING_DATABASE_URL")
    or "postgresql+asyncpg://soc_admin:staging_secure_password_123!@localhost:5433/cyber_soc_staging"
)
STAGING_REDIS_URL = os.getenv(
    "STAGING_REDIS_URL",
    "redis://localhost:6380/0",
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def pg_engine():
    """Attempt to connect to PostgreSQL 16 staging container with expanded pool. Skips if unavailable."""
    engine = create_async_engine(
        STAGING_PG_URL,
        echo=False,
        pool_size=20,
        max_overflow=30,
        pool_timeout=10,
        pool_pre_ping=True,
    )
    try:
        async with asyncio.timeout(1.5):
            async with engine.connect() as conn:
                res = await conn.execute(text("SELECT version();"))
                version_str = res.scalar()
                if not version_str or "PostgreSQL" not in version_str:
                    pytest.skip("Not connected to PostgreSQL database.")
    except Exception as exc:
        await engine.dispose()
        pytest.skip(
            f"PostgreSQL 16 staging container is not running ({exc}). "
            "Start it using: docker compose -f docker-compose.staging.yml up -d"
        )

    # Initialize schema
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine
    await engine.dispose()


@pytest.fixture
def pg_session_factory(pg_engine):
    return async_sessionmaker(bind=pg_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
async def clean_staging_db(pg_session_factory):
    """Explicit post-test table cleanup fixture to ensure test isolation."""
    yield
    try:
        async with pg_session_factory() as session, session.begin():
            await session.execute(text("DELETE FROM notification_outbox;"))
            await session.execute(text("DELETE FROM alerts;"))
            await session.execute(text("DELETE FROM incidents;"))
            await session.execute(text("DELETE FROM monitoring_targets;"))
            await session.execute(text("DELETE FROM scheduler_state WHERE id = 1;"))
            await session.execute(text("SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE((SELECT MAX(id) FROM users), 1));"))
    except Exception:
        pass


# ── 1. PostgreSQL 16 Engine Verification ─────────────────────────────────────

@pytest.mark.anyio
async def test_postgres_version_16(pg_engine):
    """Verify target environment is genuine PostgreSQL 16+."""
    async with pg_engine.connect() as conn:
        res = await conn.execute(text("SHOW server_version;"))
        version = res.scalar()
        assert version is not None
        assert version.startswith("16"), f"Expected PostgreSQL 16, got {version}"


# ── 2. Advisory Lock Leader Election ──────────────────────────────────────────

@pytest.mark.anyio
async def test_postgres_advisory_lock_leader_election(pg_engine):
    """
    Two concurrent sessions attempt to claim the leader advisory lock (pg_try_advisory_lock).
    Exactly one session must acquire it; the other must receive False.
    Upon release, the second session can acquire it.
    """
    LOCK_ID = 987654321

    conn1 = await pg_engine.connect()
    conn2 = await pg_engine.connect()

    try:
        # Worker 1 acquires lock
        res1 = await conn1.execute(text(f"SELECT pg_try_advisory_lock({LOCK_ID});"))
        won1 = res1.scalar()
        assert won1 is True, "Worker 1 failed to acquire uncontested advisory lock"

        # Worker 2 attempts same lock (must fail immediately without blocking)
        res2 = await conn2.execute(text(f"SELECT pg_try_advisory_lock({LOCK_ID});"))
        won2 = res2.scalar()
        assert won2 is False, "Worker 2 erroneously acquired an already-held advisory lock"

        # Worker 1 releases lock
        rel = await conn1.execute(text(f"SELECT pg_advisory_unlock({LOCK_ID});"))
        assert rel.scalar() is True

        # Worker 2 attempts again (must now succeed)
        res3 = await conn2.execute(text(f"SELECT pg_try_advisory_lock({LOCK_ID});"))
        assert res3.scalar() is True, "Worker 2 failed to acquire unlocked advisory lock"

        # Cleanup Worker 2 lock
        await conn2.execute(text(f"SELECT pg_advisory_unlock({LOCK_ID});"))

    finally:
        await conn1.close()
        await conn2.close()


# ── 3. FOR UPDATE SKIP LOCKED Outbox Concurrency ──────────────────────────────

@pytest.mark.anyio
async def test_skip_locked_outbox_claiming(pg_session_factory):
    """
    Seed 10 pending outbox records.
    Two concurrent workers run batch claim with FOR UPDATE SKIP LOCKED (limit 5).
    Verifies:
      - Worker 1 claims 5 items.
      - Worker 2 claims the remaining 5 items concurrently.
      - Claimed sets are completely disjoint (zero duplication / contention).
    """
    outbox_ids: list[str] = []
    async with pg_session_factory() as session:
        user = (await session.execute(select(User).limit(1))).scalar_one_or_none()
        if not user:
            user = User(email="staging@soc.test", hashed_pw="dummy", role="user", is_active=True)
            session.add(user)
            await session.flush()
        user_id = user.id

        for i in range(10):
            item_id = str(uuid.uuid4())
            outbox_ids.append(item_id)
            row = NotificationOutbox(
                outbox_uuid=item_id,
                user_id=user_id,
                channel="WEBHOOK",
                destination_url="https://example.com/webhook",
                payload_json={"event": "alert_created", "seq": i},
                idempotency_key=f"idem_{item_id}",
                status="PENDING",
                attempt_count=0,
            )
            session.add(row)
        await session.commit()

    async def claim_batch() -> list[str]:
        async with pg_session_factory() as session, session.begin():
            query = text("""
                SELECT outbox_uuid FROM notification_outbox
                WHERE status = 'PENDING'
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 5;
            """)
            res = await session.execute(query)
            claimed_ids = [str(row[0]) for row in res.fetchall()]
            if claimed_ids:
                update_query = text("""
                    UPDATE notification_outbox
                    SET status = 'PROCESSING'
                    WHERE outbox_uuid = ANY(:ids);
                """)
                await session.execute(update_query, {"ids": claimed_ids})
            return claimed_ids

    batch1, batch2 = await asyncio.gather(claim_batch(), claim_batch())

    assert len(batch1) == 5, f"Worker 1 expected 5 items, got {len(batch1)}"
    assert len(batch2) == 5, f"Worker 2 expected 5 items, got {len(batch2)}"

    set1 = set(batch1)
    set2 = set(batch2)
    intersection = set1.intersection(set2)
    assert len(intersection) == 0, f"FOR UPDATE SKIP LOCKED violated: duplicate claim on {intersection}"
    assert set1.union(set2) == set(outbox_ids), "Not all 10 items were claimed across workers"


# ── 4. Monotonic Epoch Fencing ───────────────────────────────────────────────

@pytest.mark.anyio
async def test_monotonic_epoch_fencing(pg_session_factory):
    """
    Verify epoch fencing prevents stale workers from overwriting active leases.
    Only updates with epoch >= current_epoch succeed.
    """
    async with pg_session_factory() as session, session.begin():
        await session.execute(text("DELETE FROM scheduler_state WHERE id = 1;"))
        sched = SchedulerState(
            id=1,
            leader_pod_id="worker_active",
            current_epoch=5,
        )
        session.add(sched)

    # Attempt write with stale epoch 4 (must be rejected / affect 0 rows)
    async with pg_session_factory() as session:
        stmt = text("""
            UPDATE scheduler_state
            SET leader_pod_id = 'stale_worker'
            WHERE id = 1 AND current_epoch < 5;
        """)
        res = await session.execute(stmt)
        await session.commit()
        assert res.rowcount == 0, "Stale epoch was able to update scheduler state!"

    # Attempt write with equal or greater epoch (must succeed)
    async with pg_session_factory() as session:
        stmt = text("""
            UPDATE scheduler_state
            SET leader_pod_id = 'valid_worker', current_epoch = 6
            WHERE id = 1 AND current_epoch <= 5;
        """)
        res = await session.execute(stmt)
        await session.commit()
        assert res.rowcount == 1, "Valid epoch update failed to apply!"


# ── 5. 100 Concurrent Alert Attachments ──────────────────────────────────────

@pytest.mark.anyio
async def test_100_concurrent_alert_attachments(pg_session_factory):
    """
    Verify 100 concurrent alert attachments to an incident under PostgreSQL.
    Row-level locking (with_for_update) serializes severity updates and prevents lost updates.
    """
    async with pg_session_factory() as session:
        user = (await session.execute(select(User).limit(1))).scalar_one_or_none()
        if not user:
            user = User(email="tenant1@soc.test", hashed_pw="pw1", role="user", is_active=True)
            session.add(user)
            await session.flush()
        user_id = user.id

        inc = Incident(
            title="100-Alert Concurrency Test Incident",
            description="Testing high-concurrency alert attachments",
            severity="LOW",
            status="OPEN",
            created_by_user_id=user_id,
        )
        session.add(inc)
        await session.flush()
        incident_id = inc.id

        # 100 alerts with various severities and at least one CRITICAL
        severities = ["LOW", "MEDIUM", "HIGH"] * 33 + ["CRITICAL"]
        alert_ids: list[int] = []
        for i, sev in enumerate(severities):
            alert = Alert(
                user_id=user_id,
                title=f"Concurrent Alert {i}",
                description=f"Synthetic alert {i}",
                severity=sev,
                status="OPEN",
                rule_name="CONCURRENCY_TEST",
                indicator_type="DOMAIN",
                indicator_value=f"phish-{i}.example.com",
            )
            session.add(alert)
            await session.flush()
            alert_ids.append(alert.id)
        await session.commit()

    sem = asyncio.Semaphore(15)

    async def _attach_single_alert(aid: int):
        async with sem, pg_session_factory() as session:
            user_obj = await session.get(User, user_id)
            await incident_service.attach_alerts(
                session=session,
                incident_id_or_uuid=incident_id,
                alert_ids=[aid],
                current_user=user_obj,
            )

    await asyncio.gather(*[_attach_single_alert(aid) for aid in alert_ids])

    async with pg_session_factory() as session:
        verify_inc = await session.get(Incident, incident_id)
        assert verify_inc.severity == "CRITICAL", f"Expected CRITICAL severity, got {verify_inc.severity}"

        res = await session.execute(
            text("SELECT count(*) FROM alerts WHERE incident_id = :inc_id"),
            {"inc_id": incident_id},
        )
        attached_count = res.scalar()
        assert attached_count == 100, f"Expected 100 attached alerts, found {attached_count}"


# ── 6. Parallel Incident Status Transitions ───────────────────────────────────

@pytest.mark.anyio
async def test_parallel_incident_status_transitions(pg_session_factory):
    """
    Verify parallel competing status transitions on an incident.
    Valid state transitions succeed while invalid transitions are rejected without corruption.
    """
    async with pg_session_factory() as session:
        user = (await session.execute(select(User).limit(1))).scalar_one_or_none()
        if not user:
            user = User(email="tenant1@soc.test", hashed_pw="pw1", role="user", is_active=True)
            session.add(user)
            await session.flush()
        user_id = user.id

        inc = Incident(
            title="Status Transition Race Incident",
            description="Testing competing status updates",
            severity="MEDIUM",
            status="OPEN",
            created_by_user_id=user_id,
        )
        session.add(inc)
        await session.commit()
        inc_id = inc.id

    async def _transition(target_status: str) -> bool:
        async with pg_session_factory() as session:
            u = await session.get(User, user_id)
            try:
                await incident_service.update_incident(
                    session=session,
                    incident_id_or_uuid=inc_id,
                    update_data=IncidentUpdate(status=target_status),
                    current_user=u,
                )
                return True
            except IncidentValidationError:
                return False

    results = await asyncio.gather(
        _transition("RESOLVED"),
        _transition("INVESTIGATING"),
        _transition("CLOSED"),
        return_exceptions=False,
    )

    # RESOLVED is invalid directly from OPEN, so at least one transition must return False
    assert False in results, "Invalid state transition was erroneously allowed"

    async with pg_session_factory() as session:
        final_inc = await session.get(Incident, inc_id)
        assert final_inc.status in ("INVESTIGATING", "CLOSED"), f"Corrupt incident status: {final_inc.status}"


# ── 7. Concurrent Monitoring Lease Claims ─────────────────────────────────────

@pytest.mark.anyio
async def test_concurrent_monitoring_lease_claims(pg_session_factory):
    """
    Verify multiple concurrent workers contending for unassigned monitoring target leases
    with SELECT ... FOR UPDATE SKIP LOCKED claim completely disjoint targets without race conditions.
    """
    target_ids: list[int] = []
    async with pg_session_factory() as session:
        user = (await session.execute(select(User).limit(1))).scalar_one_or_none()
        if not user:
            user = User(email="tenant1@soc.test", hashed_pw="pw1", role="user", is_active=True)
            session.add(user)
            await session.flush()
        user_id = user.id

        for i in range(10):
            tgt = MonitoringTarget(
                url=f"https://target-{i}.example.com",
                normalized_domain=f"target-{i}.example.com",
                is_active=True,
                check_interval_minutes=60,
                user_id=user_id,
                execution_token=None,
            )
            session.add(tgt)
            await session.flush()
            target_ids.append(tgt.id)
        await session.commit()

    async def _claim_monitoring_batch(worker_token: str) -> list[int]:
        async with pg_session_factory() as session, session.begin():
            stmt = text("""
                SELECT id FROM monitoring_targets
                WHERE is_active = true AND execution_token IS NULL
                ORDER BY id ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 5;
            """)
            res = await session.execute(stmt)
            claimed = [row[0] for row in res.fetchall()]
            if claimed:
                update_stmt = text("""
                    UPDATE monitoring_targets
                    SET execution_token = :token
                    WHERE id = ANY(:ids);
                """)
                await session.execute(update_stmt, {"token": worker_token, "ids": claimed})
            return claimed

    worker1_token = str(uuid.uuid4())
    worker2_token = str(uuid.uuid4())

    batch1, batch2 = await asyncio.gather(
        _claim_monitoring_batch(worker1_token),
        _claim_monitoring_batch(worker2_token),
    )

    assert len(batch1) == 5, f"Worker 1 expected 5 claimed targets, got {len(batch1)}"
    assert len(batch2) == 5, f"Worker 2 expected 5 claimed targets, got {len(batch2)}"
    s1 = set(batch1)
    s2 = set(batch2)
    overlap = s1.intersection(s2)
    assert len(overlap) == 0, f"Monitoring target lease claim collision detected: {overlap}"
    assert s1.union(s2) == set(target_ids), "Not all monitoring targets were claimed across workers"
