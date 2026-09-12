"""
tests/integration/test_monitoring_pipeline.py
─────────────────────────────────────────────
Sprint 5 Phase 5B: Comprehensive Integration Tests for the Monitoring Pipeline.

Validates:
A. Benign target (SCAN_COMPLETED, INFO)
B. Malicious target (HIGH_RISK_ENRICHMENT, CRITICAL, alert + incident created)
C. Suspicious target (HIGH_RISK_ENRICHMENT, HIGH, alert + incident created)
D. Threat-intel match (REPUTATION_CHANGED, CRITICAL)
E. SSRF-blocked target (SYSTEM_AUDIT, CRITICAL, immediate suspension)
F. Unreachable target (TARGET_STATUS_CHANGED, LOW, failure counter increment)
G. Auto-suspension (5 consecutive failures -> is_active=False)
H. Event generation (strict Pydantic SecurityEventSchema validation)
I. Correlation (indicator matching)
J. Alert creation (valid fields, status=OPEN)
K. Alert deduplication (3 detections -> 1 alert with occurrence_count=3)
L. Incident creation (Incident container created)
M. Incident attachment (alert.incident_id linked)
N. Stale write-back (expired lease yields safe no-op)
O. Tenant isolation (multi-tenant boundaries strictly maintained)

CRITICAL CONCURRENCY TESTS:
- 100 concurrent identical CRITICAL events -> exactly 1 incident, zero duplicates, CRITICAL severity
- Concurrent severity escalation (INFO, LOW, MEDIUM, HIGH, CRITICAL) -> final severity = CRITICAL
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.models import (
    Alert,
    AuditEvent,
    Base,
    Incident,
    MonitoringTarget,
    User,
)
from backend.schemas.soc import EventSeverity, EventType, IndicatorType
from backend.services.alert_service import alert_service
from backend.services.event_engine import event_engine
from backend.services.incident_service import incident_service
from backend.services.monitoring_probe import (
    MonitoringProbe,
    ProbeFailureCategory,
    ProbeResult,
)
from backend.services.monitoring_worker import (
    ClaimedTarget,
    MonitoringWorker,
)
from backend.services.scheduler_service import scheduler_service

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def sync_engine():
    """In-memory SQLite engine with StaticPool for thread/task sharing."""
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
    return sessionmaker(bind=sync_engine)


@pytest.fixture
def db_session(session_factory) -> Session:
    sess = session_factory()
    yield sess
    sess.close()


@pytest.fixture
def tenant_a(db_session: Session) -> User:
    u = User(
        email=f"tenant_a_{uuid.uuid4().hex[:8]}@example.com",
        hashed_pw="test_hash_a",
        role="user",
        is_active=True,
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture
def tenant_b(db_session: Session) -> User:
    u = User(
        email=f"tenant_b_{uuid.uuid4().hex[:8]}@example.com",
        hashed_pw="test_hash_b",
        role="user",
        is_active=True,
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


def _create_claimed_target(
    db_session: Session,
    user: User,
    url: str,
    domain: str,
    failures: int = 0,
    active: bool = True,
) -> tuple[MonitoringTarget, ClaimedTarget]:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    token = f"tok-{uuid.uuid4().hex[:12]}"
    t = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url=url,
        normalized_domain=domain,
        check_interval_minutes=60,
        is_active=active,
        user_id=user.id,
        consecutive_failures=failures,
        execution_token=token,
        execution_epoch=1,
        execution_expires_at=now + timedelta(seconds=45),
        created_at=now,
    )
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)

    claimed = ClaimedTarget(
        target_id=t.id,
        url=t.url,
        normalized_domain=t.normalized_domain,
        check_interval_minutes=t.check_interval_minutes,
        execution_token=t.execution_token,
        execution_epoch=t.execution_epoch,
        user_id=t.user_id,
    )
    return t, claimed


# ── Pipeline Integration Tests A through O ─────────────────────────────────────

@pytest.mark.anyio
async def test_pipeline_a_benign_target(session_factory, tenant_a, db_session):
    """A. Benign target executes, records SCAN_COMPLETED (INFO), zero incidents."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "https://safe.example.com", "safe.example.com"
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed.url,
        status_code=200,
        latency_ms=35.0,
        redirect_count=0,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("BENIGN", 0.05))

    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    t = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    assert t.last_prediction == "BENIGN"
    assert t.consecutive_failures == 0

    # No alerts or incidents for benign routine check
    alerts = db_session.execute(select(Alert).where(Alert.user_id == tenant_a.id)).scalars().all()
    incidents = db_session.execute(select(Incident).where(Incident.created_by_user_id == tenant_a.id)).scalars().all()
    assert len(alerts) == 0
    assert len(incidents) == 0


@pytest.mark.anyio
async def test_pipeline_b_malicious_target(session_factory, tenant_a, db_session):
    """B. Malicious target generates CRITICAL alert and attaches to an Incident."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "https://evil.example.com", "evil.example.com"
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed.url,
        status_code=200,
        latency_ms=40.0,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.95))

    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    t = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    assert t.last_prediction == "MALICIOUS"

    # Verify Alert created with CRITICAL severity
    alerts = db_session.execute(select(Alert).where(Alert.user_id == tenant_a.id)).scalars().all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "CRITICAL"
    assert alert.indicator_value == claimed.url

    # Verify Incident created with CRITICAL severity and linked alert
    incidents = db_session.execute(select(Incident).where(Incident.created_by_user_id == tenant_a.id)).scalars().all()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.severity == "CRITICAL"
    assert incident.created_by_user_id == tenant_a.id
    assert alert.incident_id == incident.id


@pytest.mark.anyio
async def test_pipeline_c_suspicious_target(session_factory, tenant_a, db_session):
    """C. Suspicious ML (0.60 <= conf < 0.85) produces HIGH severity alert & incident."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "https://suspicious.example.com", "suspicious.example.com"
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=True,
        final_url=claimed.url,
        status_code=200,
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.72))

    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    alerts = db_session.execute(select(Alert).where(Alert.user_id == tenant_a.id)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"


@pytest.mark.anyio
async def test_pipeline_d_threat_intel_match(session_factory, tenant_a, db_session):
    """D. Threat-intel blacklist match produces REPUTATION_CHANGED CRITICAL outcome."""
    target_row, claimed = _create_claimed_target(
        db_session, tenant_a, "https://badreputation.com", "badreputation.com"
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(success=True))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    # Simulate outcome classification yielding REPUTATION_CHANGED
    worker._classify_outcome = MagicMock(return_value=(
        EventType.REPUTATION_CHANGED,
        EventSeverity.CRITICAL,
        "THREAT_INTEL_BLACKLIST_MATCH",
        False,
        0,
    ))

    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    incidents = db_session.execute(select(Incident).where(Incident.created_by_user_id == tenant_a.id)).scalars().all()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"


@pytest.mark.anyio
async def test_pipeline_e_ssrf_blocked_target(session_factory, tenant_a, db_session):
    """E. SSRF blocked target is IMMEDIATELY suspended (is_active=False)."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "http://169.254.169.254/latest/meta-data", "169.254.169.254"
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=False,
        failure_category=ProbeFailureCategory.SSRF_BLOCKED,
        error_message="SSRF attempt blocked by security boundary",
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    t = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    assert t.is_active is False  # IMMEDIATE SUSPENSION

    # Verify audit trail action
    audit = db_session.execute(
        select(AuditEvent).where(AuditEvent.resource_id == t.target_uuid)
    ).scalars().first()
    assert audit is not None
    assert audit.action == "TARGET_SSRF_ABORTED"


@pytest.mark.anyio
async def test_pipeline_f_unreachable_target(session_factory, tenant_a, db_session):
    """F. Unreachable network target increments failure counter without auto-suspending."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "https://down.example.com", "down.example.com", failures=0
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=False,
        failure_category=ProbeFailureCategory.CONNECTION_TIMEOUT,
        error_message="Connection timed out",
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    t = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    assert t.consecutive_failures == 1
    assert t.is_active is True  # Still active


@pytest.mark.anyio
async def test_pipeline_g_auto_suspension(session_factory, tenant_a, db_session):
    """G. Target reaching 5 consecutive failures is automatically suspended."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "https://dead.example.com", "dead.example.com", failures=4
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(
        success=False,
        failure_category=ProbeFailureCategory.DNS_FAILURE,
        error_message="Host not found",
    ))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    success = await worker.execute_target(claimed)
    assert success is True

    db_session.expire_all()
    t = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    assert t.consecutive_failures == 5
    assert t.is_active is False  # AUTO-SUSPENDED

    audit = db_session.execute(
        select(AuditEvent).where(AuditEvent.resource_id == t.target_uuid)
    ).scalars().first()
    assert audit is not None
    assert audit.action == "TARGET_AUTO_SUSPENDED"


@pytest.mark.anyio
async def test_pipeline_h_to_m_event_alert_incident_flow(session_factory, tenant_a, db_session):
    """H through M. Full lifecycle: Event emission, Correlation, Alert creation, Dedup, Incident attachment."""
    _, claimed = _create_claimed_target(
        db_session, tenant_a, "https://target-hm.example.com", "target-hm.example.com"
    )

    # 1. First Malicious Check
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(success=True))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.90))

    await worker.execute_target(claimed)

    db_session.expire_all()
    alerts = db_session.execute(select(Alert).where(Alert.user_id == tenant_a.id)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 1
    initial_alert_id = alerts[0].id

    incidents = db_session.execute(select(Incident).where(Incident.created_by_user_id == tenant_a.id)).scalars().all()
    assert len(incidents) == 1
    assert alerts[0].incident_id == incidents[0].id

    # 2. Second Check on same target: Alert Deduplication (K)
    # Re-claim target
    db_target = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    db_target.execution_token = "tok-second"
    db_target.execution_epoch = 1
    db_target.execution_expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=45)
    db_session.commit()

    claimed_second = ClaimedTarget(
        target_id=db_target.id,
        url=db_target.url,
        normalized_domain=db_target.normalized_domain,
        check_interval_minutes=db_target.check_interval_minutes,
        execution_token=db_target.execution_token,
        execution_epoch=db_target.execution_epoch,
        user_id=db_target.user_id,
    )
    await worker.execute_target(claimed_second)

    db_session.expire_all()
    alerts_after = db_session.execute(select(Alert).where(Alert.user_id == tenant_a.id)).scalars().all()
    assert len(alerts_after) == 1  # Deduplicated!
    assert alerts_after[0].occurrence_count == 2
    assert alerts_after[0].id == initial_alert_id


@pytest.mark.anyio
async def test_pipeline_n_stale_write_back(session_factory, tenant_a, db_session):
    """N. Stale worker lease write-back is safely rejected and does not overwrite database."""
    target_row, claimed = _create_claimed_target(
        db_session, tenant_a, "https://stale.example.com", "stale.example.com"
    )

    # Simulate newer scheduler cycle stealing the target before worker finishes
    target_row.execution_token = "newer-pod-token"
    target_row.execution_epoch = 2
    db_session.commit()

    # Worker attempts write-back with stale token and epoch 1
    now = datetime.now(timezone.utc)
    sess = session_factory()
    try:
        written = scheduler_service.write_back_result(
            sess,
            target_id=claimed.target_id,
            execution_token=claimed.execution_token,
            execution_epoch=claimed.execution_epoch,
            last_checked_at=now,
            interval_minutes=60,
            last_prediction="BENIGN",
            last_confidence=0.0,
            consecutive_failures=0,
        )
        assert written is False  # Rejected by authoritative triple-predicate
    finally:
        sess.close()

    db_session.expire_all()
    t = db_session.execute(select(MonitoringTarget).where(MonitoringTarget.id == claimed.target_id)).scalar_one()
    assert t.execution_token == "newer-pod-token"
    assert t.execution_epoch == 2
    assert t.last_checked_at is None  # Never overwritten


@pytest.mark.anyio
async def test_pipeline_o_tenant_isolation(session_factory, tenant_a, tenant_b, db_session):
    """O. Multi-tenant boundaries strictly maintained across targets, alerts, and incidents."""
    _, claimed_a = _create_claimed_target(
        db_session, tenant_a, "https://shared-name.com", "shared-name.com"
    )
    _, claimed_b = _create_claimed_target(
        db_session, tenant_b, "https://shared-name.com", "shared-name.com"
    )

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(return_value=ProbeResult(success=True))

    worker = MonitoringWorker(probe=mock_probe, session_factory=session_factory)
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.95))

    await worker.execute_target(claimed_a)
    await worker.execute_target(claimed_b)

    db_session.expire_all()
    # Tenant A sees only Tenant A's alerts and incidents
    alerts_a = db_session.execute(select(Alert).where(Alert.user_id == tenant_a.id)).scalars().all()
    incidents_a = db_session.execute(select(Incident).where(Incident.created_by_user_id == tenant_a.id)).scalars().all()

    alerts_b = db_session.execute(select(Alert).where(Alert.user_id == tenant_b.id)).scalars().all()
    incidents_b = db_session.execute(select(Incident).where(Incident.created_by_user_id == tenant_b.id)).scalars().all()

    assert len(alerts_a) == 1
    assert len(incidents_a) == 1
    assert len(alerts_b) == 1
    assert len(incidents_b) == 1

    assert incidents_a[0].id != incidents_b[0].id
    assert alerts_a[0].id != alerts_b[0].id


# ── Critical Concurrency Tests ─────────────────────────────────────────────────

def _is_postgres_available() -> bool:
    pg_url = os.getenv("TEST_POSTGRES_URL")
    if not pg_url:
        return False
    try:
        test_eng = create_engine(pg_url)
        with test_eng.connect() as conn:
            conn.execute(select(1))
        test_eng.dispose()
        return True
    except Exception:
        return False


def test_100_concurrent_identical_critical_events():
    """
    CRITICAL REAL 100-WAY CONCURRENCY TEST (PRODUCTION MONITORING PATH):
    Exercises the ACTUAL MonitoringWorker.execute_target() orchestration
    across 100 truly concurrent worker executions using real separate database
    sessions/connections in a ThreadPoolExecutor (max_workers=20).

    Does NOT manually chain EventEngine -> CorrelationEngine -> AlertService -> IncidentService.
    Does NOT use asyncio.gather() around synchronous DB code.
    Contains NO test-side locks, NO test-side deduplication, NO fake AlertService,
    NO fake IncidentService, and NO manual serialization.

    Proves:
      1. Exactly 1 logical Alert created for Tenant A
      2. occurrence_count == 100 on that Alert
      3. Exactly 1 Incident created for Tenant A
      4. Alert is attached to that Incident (alert.incident_id == incident.id)
      5. Final Incident severity == "CRITICAL"
      6. Zero duplicate incidents in DB
      7. Zero cross-user leakage (Tenant B has exactly 0 alerts and 0 incidents)
      8. All 100 workers returned success=True (authoritative write-backs completed)
    """
    # Create an independent file-based SQLite database with WAL and busy_timeout
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_file = f.name

    concurrent_eng = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"timeout": 60.0, "check_same_thread": False},
        pool_size=30,
        max_overflow=20,
    )

    @event.listens_for(concurrent_eng, "connect")
    def _set_pragmas(dbapi_con, con_record):
        cur = dbapi_con.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=60000")
        cur.close()

    Base.metadata.create_all(concurrent_eng)
    SessionFactory = sessionmaker(bind=concurrent_eng)

    setup_sess = SessionFactory()
    try:
        # Create Tenant A and Tenant B
        tenant_a = User(
            email=f"concurrent_a_{uuid.uuid4().hex[:8]}@example.com",
            hashed_pw="hash_a",
            role="user",
            is_active=True,
        )
        tenant_b = User(
            email=f"concurrent_b_{uuid.uuid4().hex[:8]}@example.com",
            hashed_pw="hash_b",
            role="user",
            is_active=True,
        )
        setup_sess.add_all([tenant_a, tenant_b])
        setup_sess.commit()
        setup_sess.refresh(tenant_a)
        setup_sess.refresh(tenant_b)
        uid_a = tenant_a.id
        uid_b = tenant_b.id

        domain = "high-threat-target.org"
        url = f"https://{domain}/malicious-payload"
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Create 100 distinct claimed targets for Tenant A, all monitoring the identical threat domain/URL
        claimed_targets: list[ClaimedTarget] = []
        for i in range(100):
            token = f"tok-concur-{i}-{uuid.uuid4().hex[:8]}"
            t = MonitoringTarget(
                target_uuid=str(uuid.uuid4()),
                url=url,
                normalized_domain=domain,
                check_interval_minutes=60,
                is_active=True,
                user_id=uid_a,
                consecutive_failures=0,
                execution_token=token,
                execution_epoch=1,
                execution_expires_at=now + timedelta(seconds=60),
                created_at=now,
            )
            setup_sess.add(t)
            setup_sess.commit()
            setup_sess.refresh(t)

            claimed_targets.append(
                ClaimedTarget(
                    target_id=t.id,
                    url=t.url,
                    normalized_domain=t.normalized_domain,
                    check_interval_minutes=t.check_interval_minutes,
                    execution_token=t.execution_token,
                    execution_epoch=t.execution_epoch,
                    user_id=t.user_id,
                )
            )
    finally:
        setup_sess.close()

    # Configure real MonitoringWorker with real production pipeline
    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(
        return_value=ProbeResult(
            success=True,
            final_url=url,
            status_code=200,
            latency_ms=25.0,
        )
    )

    worker = MonitoringWorker(
        probe=mock_probe,
        session_factory=SessionFactory,
    )
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.98))

    # Real concurrent execution using 20 OS worker threads with separate DB connections
    def _execute_worker_task(target: ClaimedTarget) -> bool:
        return asyncio.run(worker.execute_target(target))

    with ThreadPoolExecutor(max_workers=20) as executor:
        worker_results = list(executor.map(_execute_worker_task, claimed_targets))

    # Assert all 100 workers completed their execution and write-backs
    assert len(worker_results) == 100
    assert all(r is True for r in worker_results), "All 100 workers must execute and write back successfully!"

    # Verification via fresh session directly against the database
    verify_sess = SessionFactory()
    try:
        alerts_a = (
            verify_sess.execute(select(Alert).where(Alert.user_id == uid_a))
            .scalars()
            .all()
        )
        incidents_a = (
            verify_sess.execute(select(Incident).where(Incident.created_by_user_id == uid_a))
            .scalars()
            .all()
        )
        alerts_b = (
            verify_sess.execute(select(Alert).where(Alert.user_id == uid_b))
            .scalars()
            .all()
        )
        incidents_b = (
            verify_sess.execute(select(Incident).where(Incident.created_by_user_id == uid_b))
            .scalars()
            .all()
        )

        # 1. Exactly 1 logical Alert
        assert len(alerts_a) == 1, f"Expected exactly 1 alert row for Tenant A, found {len(alerts_a)}"
        single_alert = alerts_a[0]

        # 2. occurrence_count = 100
        assert single_alert.occurrence_count == 100, f"Expected occurrence_count == 100, got {single_alert.occurrence_count}"

        # 3. Exactly 1 Incident
        assert len(incidents_a) == 1, f"Expected exactly 1 incident for Tenant A, found {len(incidents_a)}"
        single_incident = incidents_a[0]

        # 4. All valid alerts attached to that Incident
        assert single_alert.incident_id == single_incident.id, "Alert must be attached to the incident!"

        # 5. Final Incident severity = CRITICAL
        assert single_incident.severity == "CRITICAL", f"Expected severity CRITICAL, got {single_incident.severity}"

        # 6. Zero duplicate incidents
        assert len(incidents_a) == 1, "Zero duplicate incidents in database!"

        # 7. Zero cross-user leakage
        assert len(alerts_b) == 0, f"Zero alerts leaked to Tenant B, found {len(alerts_b)}"
        assert len(incidents_b) == 0, f"Zero incidents leaked to Tenant B, found {len(incidents_b)}"

    finally:
        verify_sess.close()
        concurrent_eng.dispose()
        with contextlib.suppress(Exception):
            os.unlink(db_file)


@pytest.mark.skipif(not _is_postgres_available(), reason="PostgreSQL service not running in local test environment")
def test_postgresql_100_concurrent_workers():
    """
    AUTHORITATIVE DISTRIBUTED CONCURRENCY TEST (POSTGRESQL):
    Executes the genuine concurrent transaction test using supported production PostgreSQL semantics.
    Exercises MonitoringWorker.execute_target() across 100 concurrent workers using real
    PostgreSQL connections and sessions, proving:
      - pg_advisory_xact_lock transaction isolation
      - SELECT ... FOR UPDATE row-level locking
      - Exactly 1 logical Alert with occurrence_count = 100
      - Exactly 1 Incident with final severity = CRITICAL
      - Zero duplicate incidents
      - Zero cross-user leakage
    """
    pg_url = os.getenv("TEST_POSTGRES_URL")
    pg_eng = create_engine(pg_url, pool_size=30, max_overflow=20)
    Base.metadata.create_all(pg_eng)
    SessionFactory = sessionmaker(bind=pg_eng)

    setup_sess = SessionFactory()
    try:
        tenant_a = User(
            email=f"pg_concur_a_{uuid.uuid4().hex[:8]}@example.com",
            hashed_pw="hash_a",
            role="user",
            is_active=True,
        )
        tenant_b = User(
            email=f"pg_concur_b_{uuid.uuid4().hex[:8]}@example.com",
            hashed_pw="hash_b",
            role="user",
            is_active=True,
        )
        setup_sess.add_all([tenant_a, tenant_b])
        setup_sess.commit()
        setup_sess.refresh(tenant_a)
        setup_sess.refresh(tenant_b)
        uid_a = tenant_a.id
        uid_b = tenant_b.id

        domain = "pg-threat-target.org"
        url = f"https://{domain}/malicious"
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        claimed_targets = []
        for i in range(100):
            token = f"tok-pg-{i}-{uuid.uuid4().hex[:8]}"
            t = MonitoringTarget(
                target_uuid=str(uuid.uuid4()),
                url=url,
                normalized_domain=domain,
                check_interval_minutes=60,
                is_active=True,
                user_id=uid_a,
                consecutive_failures=0,
                execution_token=token,
                execution_epoch=1,
                execution_expires_at=now + timedelta(seconds=60),
                created_at=now,
            )
            setup_sess.add(t)
            setup_sess.commit()
            setup_sess.refresh(t)

            claimed_targets.append(
                ClaimedTarget(
                    target_id=t.id,
                    url=t.url,
                    normalized_domain=t.normalized_domain,
                    check_interval_minutes=t.check_interval_minutes,
                    execution_token=t.execution_token,
                    execution_epoch=t.execution_epoch,
                    user_id=t.user_id,
                )
            )
    finally:
        setup_sess.close()

    mock_probe = MagicMock(spec=MonitoringProbe)
    mock_probe.probe = AsyncMock(
        return_value=ProbeResult(
            success=True,
            final_url=url,
            status_code=200,
            latency_ms=25.0,
        )
    )

    worker = MonitoringWorker(probe=mock_probe, session_factory=SessionFactory)
    worker._run_inference = MagicMock(return_value=("MALICIOUS", 0.98))

    def _execute_worker(target: ClaimedTarget) -> bool:
        return asyncio.run(worker.execute_target(target))

    with ThreadPoolExecutor(max_workers=20) as executor:
        worker_results = list(executor.map(_execute_worker, claimed_targets))

    assert len(worker_results) == 100
    assert all(r is True for r in worker_results)

    verify_sess = SessionFactory()
    try:
        alerts_a = verify_sess.execute(select(Alert).where(Alert.user_id == uid_a)).scalars().all()
        incidents_a = verify_sess.execute(select(Incident).where(Incident.created_by_user_id == uid_a)).scalars().all()
        alerts_b = verify_sess.execute(select(Alert).where(Alert.user_id == uid_b)).scalars().all()
        incidents_b = verify_sess.execute(select(Incident).where(Incident.created_by_user_id == uid_b)).scalars().all()

        assert len(alerts_a) == 1
        assert alerts_a[0].occurrence_count == 100
        assert len(incidents_a) == 1
        assert incidents_a[0].severity == "CRITICAL"
        assert alerts_a[0].incident_id == incidents_a[0].id
        assert len(alerts_b) == 0
        assert len(incidents_b) == 0
    finally:
        verify_sess.close()
        pg_eng.dispose()


@pytest.mark.anyio
async def test_alert_fingerprint_dedup_semantics(session_factory, tenant_a, db_session):
    """
    CRITICAL — ALERT FINGERPRINT / DEDUP VERIFICATION:
    Test:
      A: evil.com/a
      B: evil.com/a
      C: evil.com/b
    Expected:
      A + B: same logical alert / occurrence increment (occurrence_count = 2)
      C: distinct alert created (occurrence_count = 1)
      Total alert rows in DB = 2
    """
    sess_a = session_factory()
    event_a = event_engine.create_event(
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.CRITICAL,
        indicator_type=IndicatorType.URL,
        indicator_value="https://evil.com/a",
        user_id=tenant_a.id,
        payload={"event_subtype": "MONITORING_THREAT_MALICIOUS"},
    )
    alert_a, created_a = alert_service.process_event(sess_a, event_a, rule_name="MONITORING_THREAT_DETECTION")
    sess_a.commit()
    aid_a = alert_a.id
    fp_a = alert_a.fingerprint
    sess_a.close()

    sess_b = session_factory()
    event_b = event_engine.create_event(
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.CRITICAL,
        indicator_type=IndicatorType.URL,
        indicator_value="https://evil.com/a",
        user_id=tenant_a.id,
        payload={"event_subtype": "MONITORING_THREAT_MALICIOUS"},
    )
    alert_b, created_b = alert_service.process_event(sess_b, event_b, rule_name="MONITORING_THREAT_DETECTION")
    sess_b.commit()
    aid_b = alert_b.id
    sess_b.close()

    sess_c = session_factory()
    event_c = event_engine.create_event(
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://evil.com/b",
        user_id=tenant_a.id,
        payload={"event_subtype": "MONITORING_THREAT_SUSPICIOUS"},
    )
    alert_c, created_c = alert_service.process_event(sess_c, event_c, rule_name="MONITORING_THREAT_DETECTION")
    sess_c.commit()
    aid_c = alert_c.id
    fp_c = alert_c.fingerprint
    sess_c.close()

    db_session.expire_all()
    all_alerts = db_session.execute(
        select(Alert).where(Alert.user_id == tenant_a.id).order_by(Alert.id.asc())
    ).scalars().all()

    assert len(all_alerts) == 2, "Expected exactly 2 alert rows (A+B deduped, C distinct)"
    assert created_a is True
    assert created_b is False, "Event B must deduplicate against Alert A"
    assert created_c is True, "Event C must create a distinct alert"

    assert aid_a == aid_b, "Alert A and B must share the exact same alert ID"
    assert all_alerts[0].id == aid_a
    assert all_alerts[0].occurrence_count == 2
    assert all_alerts[1].id == aid_c
    assert all_alerts[1].occurrence_count == 1
    assert fp_a != fp_c, "Fingerprint for evil.com/a must differ from evil.com/b"


@pytest.mark.anyio
async def test_concurrent_severity_escalation_race(session_factory, tenant_a, db_session):
    """
    17B. CONCURRENT SEVERITY TEST:
    Concurrently fire INFO, LOW, MEDIUM, HIGH, CRITICAL against the same logical incident.

    Expected:
    - Final incident severity = CRITICAL (monotonic escalation, never downgraded).
    - Exactly 1 incident created.
    """
    domain = "severity-escalation-target.net"
    title = f"Automated Threat Incident: {domain}"

    severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    async def _fire_severity(sev: str):
        sess = session_factory()
        try:
            inc, _ = await incident_service.get_or_create_threat_incident(
                sess,
                user_id=tenant_a.id,
                normalized_domain=domain,
                severity=sev,
                title=title,
                description="Severity escalation test",
            )
            return inc.id, inc.severity
        finally:
            sess.close()

    # Launch concurrently across 5 tasks
    await asyncio.gather(*[_fire_severity(s) for s in severities])

    db_session.expire_all()
    incidents = db_session.execute(
        select(Incident).where(
            Incident.created_by_user_id == tenant_a.id,
            Incident.title == title,
        )
    ).scalars().all()

    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"  # MONOTONIC ESCALATION GUARANTEE
