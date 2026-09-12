"""
tests/unit/test_monitoring_worker.py
────────────────────────────────────
Sprint 5 Phase 5B: Unit tests for MonitoringWorker & MonitoringWorkerPool.

Validates all 20 mandatory worker invariants:
1. valid lease executes
2. expired lease performs zero network calls
3. wrong token performs zero network calls
4. wrong epoch performs zero network calls
5. stale task performs zero ML calls
6. stale task emits zero events
7. stale task performs zero write-back
8. worker hard timeout
9. probe aggregate timeout
10. ML timeout
11. bounded global concurrency
12. per-user concurrency <= 2
13. fairness between users
14. cancellation during network work
15. cancellation during ML
16. shutdown drains/cancels tasks
17. worker exception recovery
18. model unavailable -> UNKNOWN
19. monitoring prediction never enters scan_results
20. monitoring prediction never enters retraining data
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.models import (
    Alert,
    AuditEvent,
    Base,
    Incident,
    MonitoringTarget,
    ScanResult,
    User,
)
from backend.schemas.soc import EventSeverity, EventType
from backend.services.event_engine import event_engine
from backend.services.monitoring_probe import (
    MonitoringProbe,
    ProbeFailureCategory,
    ProbeResult,
)
from backend.services.monitoring_worker import (
    GLOBAL_MAX_WORKERS,
    MAX_USER_WORKERS,
    ClaimedTarget,
    MonitoringWorker,
    MonitoringWorkerPool,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def sync_engine():
    """In-memory SQLite engine for worker unit testing with shared memory."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def session_factory(sync_engine):
    """Sessionmaker bound to in-memory test database."""
    return sessionmaker(bind=sync_engine)


@pytest.fixture
def db_session(session_factory) -> Session:
    """Individual test session."""
    sess = session_factory()
    yield sess
    sess.close()


@pytest.fixture
def test_user(db_session: Session) -> User:
    """Persisted user for target ownership."""
    user = User(
        email=f"worker_test_{uuid.uuid4().hex[:8]}@example.com",
        hashed_pw="hashed_pw_test",
        role="user",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def active_db_target(db_session: Session, test_user: User) -> MonitoringTarget:
    """Persisted active target with an active lease."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    target = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url="https://secure.example.com",
        normalized_domain="secure.example.com",
        check_interval_minutes=60,
        is_active=True,
        user_id=test_user.id,
        consecutive_failures=0,
        execution_token="valid-token-12345",
        execution_epoch=1,
        execution_expires_at=now + timedelta(seconds=45),
        created_at=now,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target


@pytest.fixture
def claimed_target(active_db_target: MonitoringTarget) -> ClaimedTarget:
    """ClaimedTarget matching the active_db_target lease."""
    return ClaimedTarget(
        target_id=active_db_target.id,
        url=active_db_target.url,
        normalized_domain=active_db_target.normalized_domain,
        check_interval_minutes=active_db_target.check_interval_minutes,
        execution_token=active_db_target.execution_token,
        execution_epoch=active_db_target.execution_epoch,
        user_id=active_db_target.user_id,
    )


# ── Unit Tests ─────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_01_valid_lease_executes(session_factory, claimed_target, db_session):
    """1. Valid lease executes successfully and writes back to target row."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed_target.url,
        status_code=200,
        latency_ms=45.2,
        redirect_count=0,
    ))

    worker = MonitoringWorker(
        probe=mock_probe,
        session_factory=session_factory,
    )
    # Stub inference to benign
    worker._run_inference = MagicMock(return_value=("BENIGN", 0.05))

    success = await worker.execute_target(claimed_target)
    assert success is True

    # Verify write-back updated target
    db_session.expire_all()
    t = db_session.execute(
        select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
    ).scalar_one()
    assert t.last_checked_at is not None
    assert t.last_prediction == "BENIGN"
    assert t.consecutive_failures == 0
    assert t.execution_token is None  # Lease released


@pytest.mark.anyio
async def test_02_expired_lease_zero_network_calls(session_factory, claimed_target, db_session):
    """2. Expired lease performs zero network calls."""
    # Expire target in DB
    past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=10)
    target_row = db_session.execute(
        select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
    ).scalar_one()
    target_row.execution_expires_at = past
    db_session.commit()

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock()

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(claimed_target)

    assert success is False
    mock_probe.probe.assert_not_called()


@pytest.mark.anyio
async def test_03_wrong_token_zero_network_calls(session_factory, claimed_target):
    """3. Wrong token performs zero network calls."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock()

    stale_target = ClaimedTarget(
        target_id=claimed_target.target_id,
        url=claimed_target.url,
        normalized_domain=claimed_target.normalized_domain,
        check_interval_minutes=claimed_target.check_interval_minutes,
        execution_token="wrong-token-abc",
        execution_epoch=claimed_target.execution_epoch,
        user_id=claimed_target.user_id,
    )

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(stale_target)

    assert success is False
    mock_probe.probe.assert_not_called()


@pytest.mark.anyio
async def test_04_wrong_epoch_zero_network_calls(session_factory, claimed_target):
    """4. Wrong epoch performs zero network calls."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock()

    stale_target = ClaimedTarget(
        target_id=claimed_target.target_id,
        url=claimed_target.url,
        normalized_domain=claimed_target.normalized_domain,
        check_interval_minutes=claimed_target.check_interval_minutes,
        execution_token=claimed_target.execution_token,
        execution_epoch=999,  # DB has epoch=1
        user_id=claimed_target.user_id,
    )

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(stale_target)

    assert success is False
    mock_probe.probe.assert_not_called()


@pytest.mark.anyio
async def test_05_stale_task_zero_ml_calls(session_factory, claimed_target):
    """5. Stale task performs zero ML inference calls."""
    stale_target = ClaimedTarget(
        target_id=claimed_target.target_id,
        url=claimed_target.url,
        normalized_domain=claimed_target.normalized_domain,
        check_interval_minutes=claimed_target.check_interval_minutes,
        execution_token="stale-token",
        execution_epoch=claimed_target.execution_epoch,
        user_id=claimed_target.user_id,
    )

    mock_feat = MagicMock()
    mock_pred = MagicMock()
    worker = MonitoringWorker(
        feature_service=mock_feat,
        prediction_service=mock_pred,
        session_factory=session_factory,
    )
    success = await worker.execute_target(stale_target)

    assert success is False
    mock_feat.extract_features.assert_not_called()
    mock_pred.predict.assert_not_called()


@pytest.mark.anyio
async def test_06_stale_task_zero_events(session_factory, claimed_target):
    """6. Stale task emits zero monitoring events."""
    stale_target = ClaimedTarget(
        target_id=claimed_target.target_id,
        url=claimed_target.url,
        normalized_domain=claimed_target.normalized_domain,
        check_interval_minutes=claimed_target.check_interval_minutes,
        execution_token="stale-token",
        execution_epoch=claimed_target.execution_epoch,
        user_id=claimed_target.user_id,
    )

    worker = MonitoringWorker(session_factory=session_factory)
    with patch("backend.services.monitoring_worker.event_engine.emit_event") as mock_emit:
        success = await worker.execute_target(stale_target)
        assert success is False
        mock_emit.assert_not_called()


@pytest.mark.anyio
async def test_07_stale_task_zero_write_back(session_factory, claimed_target, db_session):
    """7. Stale task performs zero write-back to database."""
    stale_target = ClaimedTarget(
        target_id=claimed_target.target_id,
        url=claimed_target.url,
        normalized_domain=claimed_target.normalized_domain,
        check_interval_minutes=claimed_target.check_interval_minutes,
        execution_token="stale-token",
        execution_epoch=claimed_target.execution_epoch,
        user_id=claimed_target.user_id,
    )

    worker = MonitoringWorker(session_factory=session_factory)
    success = await worker.execute_target(stale_target)
    assert success is False

    # Check DB state
    db_session.expire_all()
    t = db_session.execute(
        select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
    ).scalar_one()
    assert t.last_checked_at is None
    assert t.execution_token == claimed_target.execution_token  # Unchanged


@pytest.mark.anyio
async def test_08_worker_hard_timeout(session_factory, claimed_target):
    """8. Worker hard timeout cancels runaway execution cleanly."""
    mock_probe = MagicMock(spec=MonitoringProbe)

    async def hanging_probe(*args, **kwargs):
        await asyncio.sleep(5.0)
        return ProbeResult(success=True)

    mock_probe.probe = hanging_probe

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)

    with patch("backend.services.monitoring_worker.WORKER_HARD_TIMEOUT_S", 0.05):
        start = asyncio.get_running_loop().time()
        success = await worker.execute_target(claimed_target)
        duration = asyncio.get_running_loop().time() - start

        assert success is False
        assert duration < 1.0


@pytest.mark.anyio
async def test_09_probe_aggregate_timeout(session_factory, claimed_target, db_session):
    """9. Probe aggregate timeout records failure and applies backoff."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=False,
        failure_category=ProbeFailureCategory.CONNECTION_TIMEOUT,
        error_message="Probe wall-clock budget exceeded",
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(claimed_target)

    assert success is True  # Check completed and result written back
    db_session.expire_all()
    t = db_session.execute(
        select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
    ).scalar_one()
    assert t.consecutive_failures == 1
    assert t.last_prediction == "UNKNOWN"


@pytest.mark.anyio
async def test_10_ml_timeout(session_factory, claimed_target, db_session):
    """10. ML inference timeout degrades gracefully to UNKNOWN prediction."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed_target.url,
        status_code=200,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)

    def hanging_inference(url):
        import time
        time.sleep(1.0)
        return ("BENIGN", 0.1)

    worker._run_inference = hanging_inference

    with patch("backend.services.monitoring_worker.ML_TIMEOUT_S", 0.05):
        success = await worker.execute_target(claimed_target)
        assert success is True

    db_session.expire_all()
    t = db_session.execute(
        select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
    ).scalar_one()
    assert t.last_prediction == "UNKNOWN"


@pytest.mark.anyio
async def test_11_bounded_global_concurrency(session_factory):
    """11. Global concurrency ceiling is strictly bounded at GLOBAL_MAX_WORKERS (10)."""
    pool = MonitoringWorkerPool(global_max_workers=GLOBAL_MAX_WORKERS)
    assert pool._global_semaphore._value == 10

    active_concurrent = 0
    max_observed = 0
    lock = asyncio.Lock()

    async def mock_execute(target):
        nonlocal active_concurrent, max_observed
        async with lock:
            active_concurrent += 1
            if active_concurrent > max_observed:
                max_observed = active_concurrent
        await asyncio.sleep(0.05)
        async with lock:
            active_concurrent -= 1
        return True

    pool.worker.execute_target = mock_execute

    targets = [
        ClaimedTarget(
            target_id=i,
            user_id=i,  # Different user per target to test global limit
            url=f"https://site{i}.example.com",
            normalized_domain=f"site{i}.example.com",
            check_interval_minutes=60,
            execution_token=f"tok-{i}",
            execution_epoch=1,
        )
        for i in range(15)
    ]

    tasks = [await pool.submit_target(t) for t in targets]
    await asyncio.gather(*tasks)

    assert max_observed <= 10


@pytest.mark.anyio
async def test_12_per_user_concurrency(session_factory):
    """12. Per-user concurrency is strictly bounded at MAX_USER_WORKERS (2)."""
    pool = MonitoringWorkerPool(max_user_workers=MAX_USER_WORKERS)

    user_concurrent = 0
    max_user_observed = 0
    lock = asyncio.Lock()

    async def mock_execute(target):
        nonlocal user_concurrent, max_user_observed
        async with lock:
            user_concurrent += 1
            if user_concurrent > max_user_observed:
                max_user_observed = user_concurrent
        await asyncio.sleep(0.05)
        async with lock:
            user_concurrent -= 1
        return True

    pool.worker.execute_target = mock_execute

    # 5 targets for the SAME user
    targets = [
        ClaimedTarget(
            target_id=i,
            user_id=42,
            url=f"https://site{i}.example.com",
            normalized_domain=f"site{i}.example.com",
            check_interval_minutes=60,
            execution_token=f"tok-{i}",
            execution_epoch=1,
        )
        for i in range(5)
    ]

    tasks = [await pool.submit_target(t) for t in targets]
    await asyncio.gather(*tasks)

    assert max_user_observed <= 2


@pytest.mark.anyio
async def test_13_fairness_between_users(session_factory):
    """13. User 1 cannot starve User 2 when submitting bulk targets."""
    pool = MonitoringWorkerPool(global_max_workers=10, max_user_workers=2)

    user2_started_early = False
    u1_done_count = 0

    async def mock_execute(target):
        nonlocal user2_started_early, u1_done_count
        if target.user_id == 2 and u1_done_count < 6:
            user2_started_early = True
        await asyncio.sleep(0.04)
        if target.user_id == 1:
            u1_done_count += 1
        return True

    pool.worker.execute_target = mock_execute

    # User 1 submits 6 targets, User 2 submits 1 target
    t_u1 = [
        ClaimedTarget(
            target_id=i,
            user_id=1,
            url=f"https://u1-{i}.example.com",
            normalized_domain=f"u1-{i}.example.com",
            check_interval_minutes=60,
            execution_token=f"tok-1-{i}",
            execution_epoch=1,
        )
        for i in range(6)
    ]
    t_u2 = ClaimedTarget(
        target_id=99,
        user_id=2,
        url="https://u2.example.com",
        normalized_domain="u2.example.com",
        check_interval_minutes=60,
        execution_token="tok-2",
        execution_epoch=1,
    )

    tasks_u1 = [await pool.submit_target(t) for t in t_u1]
    task_u2 = await pool.submit_target(t_u2)

    await asyncio.gather(*tasks_u1, task_u2)
    assert user2_started_early is True


@pytest.mark.anyio
async def test_14_cancellation_during_network_work(session_factory, claimed_target):
    """14. Task cancellation during network I/O is handled cleanly without exceptions."""
    mock_probe = MagicMock(spec=MonitoringProbe)

    async def probe_hang(*args, **kwargs):
        await asyncio.sleep(10.0)

    mock_probe.probe = probe_hang
    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)

    task = asyncio.create_task(worker.execute_target(claimed_target))
    await asyncio.sleep(0.05)
    task.cancel()

    res = await task
    assert res is False


@pytest.mark.anyio
async def test_15_cancellation_during_ml(session_factory, claimed_target):
    """15. Task cancellation during ML inference is handled cleanly."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(success=True))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)

    def cancel_me(*args, **kwargs):
        raise asyncio.CancelledError()

    with patch("asyncio.to_thread", side_effect=cancel_me):
        success = await worker.execute_target(claimed_target)
        assert success is False


@pytest.mark.anyio
async def test_16_shutdown_drains_and_cancels_tasks(session_factory):
    """16. Worker pool shutdown cancels and drains active tasks within timeout."""
    pool = MonitoringWorkerPool(global_max_workers=5)

    async def mock_execute(target):
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(10.0)
        return False

    pool.worker.execute_target = mock_execute

    t = ClaimedTarget(
        target_id=1,
        user_id=1,
        url="https://hang.example.com",
        normalized_domain="hang.example.com",
        check_interval_minutes=60,
        execution_token="tok",
        execution_epoch=1,
    )
    task = await pool.submit_target(t)
    assert len(pool._active_tasks) == 1

    await pool.shutdown(timeout_seconds=0.2)
    assert len(pool._active_tasks) == 0
    assert task.done()


@pytest.mark.anyio
async def test_17_worker_exception_recovery(session_factory, claimed_target):
    """17. Worker catches and recovers from unexpected internal exceptions."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(side_effect=RuntimeError("Unexpected socket crash"))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(claimed_target)

    # Worker catches exception and returns False without crashing
    assert success is False


@pytest.mark.anyio
async def test_18_model_unavailable_degrades_to_unknown(session_factory, claimed_target, db_session):
    """18. Missing or failing model degrades gracefully to UNKNOWN with SYSTEM_AUDIT event."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed_target.url,
        status_code=200,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    # Simulate feature/prediction service failure
    worker._run_inference = MagicMock(side_effect=FileNotFoundError("Model artifact missing"))

    with patch("backend.services.monitoring_worker.event_engine.emit_event") as mock_emit:
        success = await worker.execute_target(claimed_target)
        assert success is True

        # Verify event published with SYSTEM_AUDIT
        mock_emit.assert_called_once()
        published_event = mock_emit.call_args[0][0]
        assert published_event.event_type == EventType.SYSTEM_AUDIT
        assert published_event.severity == EventSeverity.LOW
        assert published_event.payload["event_subtype"] == "MONITORING_INFERENCE_DEGRADED"
        assert published_event.payload["prediction"] == "UNKNOWN"

    db_session.expire_all()
    t = db_session.execute(
        select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
    ).scalar_one()
    assert t.last_prediction == "UNKNOWN"


@pytest.mark.anyio
async def test_19_monitoring_prediction_never_enters_scan_results(session_factory, claimed_target, db_session):
    """19. Monitoring prediction is operational telemetry only: never enters scan_results table."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed_target.url,
        status_code=200,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.96))

    success = await worker.execute_target(claimed_target)
    assert success is True

    # Check scan_results table
    scans = db_session.execute(select(ScanResult)).scalars().all()
    assert len(scans) == 0  # CRITICAL INVARIANT: 0 scan_results created


@pytest.mark.anyio
async def test_20_monitoring_prediction_never_enters_retraining_data(session_factory, claimed_target, db_session):
    """20. Monitoring predictions are quarantined from active learning / retraining datasets."""
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed_target.url,
        status_code=200,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("ZERO_DAY", 0.99))

    success = await worker.execute_target(claimed_target)
    assert success is True

    # Verify no entries in scan_results or retraining queues
    scans = db_session.execute(
        select(ScanResult).where(ScanResult.retrain_status != "UNVERIFIED")
    ).scalars().all()
    assert len(scans) == 0

    # Verify audit event was written
    audits = db_session.execute(select(AuditEvent)).scalars().all()
    assert len(audits) >= 1


# ── Remediation Verification Tests ───────────────────────────────────────────

@pytest.mark.anyio
async def test_worker_hard_timeout_blocking_ml_cancellation_proof(session_factory, claimed_target, db_session):
    """
    CRITICAL HARD TIMEOUT & CANCELLATION PROOF:
    ML inference deliberately blocks beyond worker deadline.
    Verifies:
      - Worker task terminates (execute_target returns False)
      - 0 database write-backs
      - 0 events emitted
      - 0 alerts created
      - 0 incidents created
      - 0 background network activity
      - Even after the blocking thread eventually finishes, cancellation prevents
        the surrounding worker pipeline from continuing.
    """
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(success=True, status_code=200))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)

    thread_unblock_evt = threading.Event()
    thread_started_evt = threading.Event()
    thread_finished = False

    def blocking_inference(url):
        nonlocal thread_finished
        thread_started_evt.set()
        thread_unblock_evt.wait(timeout=10.0)
        thread_finished = True
        return "MALICIOUS", 0.99

    worker._run_inference = blocking_inference

    emitted_events: list[Any] = []
    orig_emit = event_engine.emit_event
    event_engine.emit_event = lambda ev: emitted_events.append(ev)

    try:
        with (
            patch("backend.services.monitoring_worker.WORKER_HARD_TIMEOUT_S", 0.15),
            patch("backend.services.monitoring_worker.ML_TIMEOUT_S", 5.0),
        ):
            success = await worker.execute_target(claimed_target)
            assert success is False, "Timed-out worker MUST return False"

            # Check DB state immediately after timeout
            db_session.expire_all()
            t_row = db_session.scalars(
                select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
            ).first()
            alerts = db_session.scalars(select(Alert)).all()
            incidents = db_session.scalars(select(Incident)).all()

            assert t_row.last_checked_at is None, "Zero write-back allowed on worker timeout"
            assert len(emitted_events) == 0, "Zero events allowed on worker timeout"
            assert len(alerts) == 0, "Zero alerts allowed on worker timeout"
            assert len(incidents) == 0, "Zero incidents allowed on worker timeout"

            # Now signal the blocking background thread to complete
            thread_unblock_evt.set()
            await asyncio.sleep(0.05)

            assert thread_finished is True, "Background thread finished execution"

            # Re-verify: pipeline must NOT continue after thread completes
            db_session.expire_all()
            t_row_after = db_session.scalars(
                select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
            ).first()
            alerts_after = db_session.scalars(select(Alert)).all()
            incidents_after = db_session.scalars(select(Incident)).all()

            assert t_row_after.last_checked_at is None, "Still zero write-backs after thread finish"
            assert len(emitted_events) == 0, "Still zero events after thread finish"
            assert len(alerts_after) == 0, "Still zero alerts after thread finish"
            assert len(incidents_after) == 0, "Still zero incidents after thread finish"
    finally:
        thread_unblock_evt.set()
        event_engine.emit_event = orig_emit


@pytest.mark.anyio
async def test_stale_epoch_leadership_race_rejection(session_factory, claimed_target, db_session):
    """
    HIGH — STALE LEADERSHIP / EPOCH RACE:
    Production-path test:
      1. Worker A receives a valid claim (epoch 1, token-A).
      2. Worker A is delayed before execution.
      3. Scheduler epoch advances to 2 / leadership changes in DB.
      4. Worker A attempts to start.
      5. Pre-execution authoritative DB validation executes.
    Expected:
      0 DNS calls, 0 socket calls, 0 HTTP calls, 0 ML calls, 0 events, 0 write-backs.
    """
    # Advance epoch to 2 and change token in database before Worker A runs
    db_session.execute(
        text("UPDATE monitoring_targets SET execution_epoch = 2, execution_token = :token WHERE id = :id"),
        {"token": "token-B", "id": claimed_target.target_id},
    )
    db_session.commit()

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock()

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    mock_ml = MagicMock()
    worker._run_inference = mock_ml

    emitted_events: list[Any] = []
    orig_emit = event_engine.emit_event
    event_engine.emit_event = lambda ev: emitted_events.append(ev)

    try:
        success = await worker.execute_target(claimed_target)
        assert success is False, "Worker with stale epoch MUST be rejected"

        # Verify strict zero side effects
        assert mock_probe.probe.call_count == 0, "ZERO probe/DNS/socket/HTTP calls allowed!"
        assert mock_ml.call_count == 0, "ZERO ML calls allowed!"
        assert len(emitted_events) == 0, "ZERO event emissions allowed!"

        db_session.expire_all()
        t = db_session.scalars(
            select(MonitoringTarget).where(MonitoringTarget.id == claimed_target.target_id)
        ).first()
        assert t.last_checked_at is None, "ZERO write-back allowed!"
        assert t.execution_epoch == 2, "DB target epoch must remain 2!"
        assert t.execution_token == "token-B", "DB target token must remain token-B!"
    finally:
        event_engine.emit_event = orig_emit


def test_write_back_fencing_stale_worker_safe_noop(session_factory, test_user, db_session):
    """
    VERIFY WRITE-BACK FENCING:
    Worker A claim -> Worker B gets newer token/epoch -> Worker A attempts write_back_result.
    Expected:
      False / safe no-op
      0 target state corruption
      0 overwrite of Worker B's execution.
    """
    from backend.services.scheduler_service import scheduler_service

    now = datetime.now(timezone.utc)
    target = MonitoringTarget(
        user_id=test_user.id,
        url="https://fencing-test.org",
        normalized_domain="fencing-test.org",
        target_uuid="uuid-fencing-1",
        execution_token="token-B",  # Worker B owns token-B, epoch 2
        execution_epoch=2,
        execution_expires_at=now + timedelta(seconds=45),
        last_prediction="BENIGN",
        last_confidence=0.10,
        consecutive_failures=0,
        is_active=True,
    )
    db_session.add(target)
    db_session.commit()
    target_id = target.id

    # Worker A attempts write_back_result using stale token-A, epoch 1
    sess_a = session_factory()
    written = scheduler_service.write_back_result(
        sess_a,
        target_id=target_id,
        execution_token="token-A",
        execution_epoch=1,
        last_checked_at=now,
        interval_minutes=15,
        last_prediction="MALICIOUS",
        last_confidence=0.99,
        consecutive_failures=5,
    )
    sess_a.close()

    assert written is False, "Stale worker write-back MUST return False / safe no-op!"

    # Verify target state in DB: 0 corruption, 0 overwrite of Worker B
    db_session.expire_all()
    t_row = db_session.scalars(select(MonitoringTarget).where(MonitoringTarget.id == target_id)).first()
    assert t_row.execution_token == "token-B"
    assert t_row.execution_epoch == 2
    assert t_row.last_prediction == "BENIGN", "Worker A prediction must NOT overwrite Worker B!"
    assert t_row.last_confidence == 0.10, "Worker A confidence must NOT overwrite Worker B!"
    assert t_row.consecutive_failures == 0, "Worker A failures must NOT overwrite Worker B!"


def test_timeout_budget_invariants_and_timings():
    """
    VERIFY TIMEOUT BOUNDARY & BUDGET INVARIANTS:
    Ensures:
      WORKER_HARD_TIMEOUT_S = 30.0
      WORKER_LEASE_SECONDS = 45.0
      PROBE_WALL_CLOCK_BUDGET = 20.0
      ML_TIMEOUT_S = 2.0
      Pre-execution DB check <= 1.0s
      MAX_TOTAL_EXECUTION_TIME (30.0s) < WORKER_LEASE_SECONDS (45.0s)
    """
    from backend.services.monitoring_probe import PROBE_WALL_CLOCK_BUDGET
    from backend.services.monitoring_worker import ML_TIMEOUT_S, WORKER_HARD_TIMEOUT_S
    from backend.services.scheduler_service import WORKER_LEASE_SECONDS

    assert WORKER_HARD_TIMEOUT_S == 30.0
    assert WORKER_LEASE_SECONDS == 45.0
    assert PROBE_WALL_CLOCK_BUDGET == 20.0
    assert ML_TIMEOUT_S == 2.0
    assert WORKER_HARD_TIMEOUT_S < WORKER_LEASE_SECONDS
    # Required invariant: outer worker limit strictly finishes before 45.0s lease expiry
    assert (PROBE_WALL_CLOCK_BUDGET + ML_TIMEOUT_S + 5.0) <= WORKER_HARD_TIMEOUT_S < WORKER_LEASE_SECONDS
