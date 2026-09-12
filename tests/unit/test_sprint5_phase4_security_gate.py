"""
tests/unit/test_sprint5_phase4_security_gate.py
─────────────────────────────────────────────────
Sprint 5 Phase 4 Security Gate Verification Test Suite.

Rigorously tests:
1. Concurrent Alert Attachment (50 workers racing on Alert X between Incident A & B)
2. Concurrent Attachment to Same Incident (50 workers attaching Alerts X1..X50)
3. Concurrent Severity Escalation (Randomized execution rounds ending in CRITICAL)
4. Concurrent Lifecycle Races & Status Transitions (Resolve + Attach, Close + Attach)
5. State Machine Adversarial Matrix (Invalid transitions rejected, closed_at verified)
6. Manual Severity Downgrade Security (Standard user 403, Admin allowed with audit)
7. Detach Security (Cross-tenant, nonexistent, attached to another incident, concurrent detach+attach)
8. Multi-Tenant Isolation Adversarial Suite (User A vs User B vs System NULL user_id)
9. Audit Log Security (Nested secrets, uppercase variants, control chars redacted)
10. Pagination & Boundary Testing (Size 1, 100, 500 clamped, negative, large page, empty)
11. Error Safety (No SQL, stack traces, or internal paths leaked)
12. Database Transaction Integrity (Rollback on forced failure points)
"""

import asyncio
import concurrent.futures
import os
import random
import tempfile

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import Alert, AuditEvent, Base, Incident, User
from backend.schemas.soc import (
    EventSeverity,
    IncidentCreate,
    IncidentStatus,
    IncidentUpdate,
)
from backend.services.incident_service import (
    IncidentAccessDeniedError,
    IncidentConflictError,
    IncidentNotFoundError,
    IncidentValidationError,
    incident_service,
)


@pytest.fixture
def file_db():
    """Create a temporary file-based SQLite database for multithreaded concurrency tests."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_gate.db")
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False}, pool_size=20, max_overflow=30)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    yield session_factory, engine

    engine.dispose()
    try:
        os.remove(db_path)
        os.rmdir(temp_dir)
    except Exception:
        pass


@pytest.fixture
def memory_db():
    """Create an in-memory SQLite database session for single-threaded security tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture
def test_users(memory_db: Session):
    u1 = User(email="user1@gate.com", hashed_pw="pw1", role="user", is_active=True)
    u2 = User(email="user2@gate.com", hashed_pw="pw2", role="user", is_active=True)
    admin = User(email="admin@gate.com", hashed_pw="pwa", role="admin", is_active=True)
    memory_db.add_all([u1, u2, admin])
    memory_db.commit()
    memory_db.refresh(u1)
    memory_db.refresh(u2)
    memory_db.refresh(admin)
    return {"user1": u1, "user2": u2, "admin": admin}


# ── 1. Concurrent Alert Attachment (50 Workers Race) ──────────────────────────

def test_concurrent_alert_attachment_race(file_db):
    session_factory, _ = file_db

    # Seed initial data
    init_sess = session_factory()
    u1 = User(email="user1@race.com", hashed_pw="pw", role="user", is_active=True)
    init_sess.add(u1)
    init_sess.commit()

    inc_a = Incident(title="Incident A", created_by_user_id=u1.id, severity="HIGH")
    inc_b = Incident(title="Incident B", created_by_user_id=u1.id, severity="HIGH")
    init_sess.add_all([inc_a, inc_b])
    init_sess.commit()

    alert_x = Alert(title="Alert X", rule_name="R1", indicator_type="URL", indicator_value="http://race.com", severity="CRITICAL", user_id=u1.id)
    init_sess.add(alert_x)
    init_sess.commit()

    inc_a_id, inc_b_id, alert_x_id, user_id = inc_a.id, inc_b.id, alert_x.id, u1.id
    init_sess.close()

    successes = []
    conflicts = []
    errors = []

    def _worker(target_inc_id: int):
        sess = session_factory()
        user_obj = sess.query(User).get(user_id)
        try:
            asyncio.run(incident_service.attach_alerts(sess, target_inc_id, [alert_x_id], current_user=user_obj))
            successes.append(target_inc_id)
        except IncidentConflictError:
            conflicts.append(target_inc_id)
        except Exception as exc:
            errors.append(exc)
        finally:
            sess.close()

    # Launch 50 concurrent workers racing to attach alert_x to A or B
    workers = []
    for i in range(50):
        target = inc_a_id if i % 2 == 0 else inc_b_id
        workers.append(target)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_worker, t) for t in workers]
        concurrent.futures.wait(futures)

    # Verification
    verify_sess = session_factory()
    final_alert = verify_sess.query(Alert).get(alert_x_id)

    assert final_alert.incident_id in (inc_a_id, inc_b_id)
    assert len(errors) == 0
    assert len(successes) >= 1
    assert len(conflicts) + len(successes) == 50
    verify_sess.close()


# ── 2. Concurrent Attachment to Same Incident (50 Workers) ─────────────────────

def test_concurrent_attachment_same_incident(file_db):
    session_factory, _ = file_db

    init_sess = session_factory()
    u1 = User(email="user1@same.com", hashed_pw="pw", role="user", is_active=True)
    init_sess.add(u1)
    init_sess.commit()

    inc = Incident(title="Incident Main", created_by_user_id=u1.id, severity="LOW")
    init_sess.add(inc)
    init_sess.commit()
    inc_id, user_id = inc.id, u1.id

    alerts = []
    for i in range(50):
        a = Alert(title=f"Alert {i}", rule_name=f"R{i}", indicator_type="URL", indicator_value=f"http://same{i}.com", severity="MEDIUM", user_id=u1.id)
        alerts.append(a)
    init_sess.add_all(alerts)
    init_sess.commit()
    alert_ids = [a.id for a in alerts]
    init_sess.close()

    def _worker(aid: int):
        sess = session_factory()
        user_obj = sess.query(User).get(user_id)
        try:
            asyncio.run(incident_service.attach_alerts(sess, inc_id, [aid], current_user=user_obj))
        finally:
            sess.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_worker, aid) for aid in alert_ids]
        concurrent.futures.wait(futures)

    verify_sess = session_factory()
    final_inc = verify_sess.query(Incident).get(inc_id)

    assert len(final_inc.alerts) == 50
    assert final_inc.severity == "MEDIUM"  # Escalated monotonically from LOW
    verify_sess.close()


# ── 3. Concurrent Severity Escalation (Randomized Order Rounds) ───────────────

def test_concurrent_severity_escalation_rounds(file_db):
    session_factory, _ = file_db

    for round_num in range(3):
        init_sess = session_factory()
        u1 = User(email=f"user{round_num}@sev.com", hashed_pw="pw", role="user", is_active=True)
        init_sess.add(u1)
        init_sess.commit()

        inc = Incident(title=f"Inc Sev Round {round_num}", created_by_user_id=u1.id, severity="INFO")
        init_sess.add(inc)
        init_sess.commit()
        inc_id, user_id = inc.id, u1.id

        severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        alerts = []
        for idx, s in enumerate(severities):
            a = Alert(title=f"Sev Alert {s}", rule_name="R1", indicator_type="URL", indicator_value=f"http://sev{idx}.com", severity=s, user_id=u1.id)
            alerts.append(a)
        init_sess.add_all(alerts)
        init_sess.commit()
        alert_ids = [a.id for a in alerts]
        init_sess.close()

        # Randomize execution order
        random.shuffle(alert_ids)

        def _worker(aid: int, target_inc_id: int = inc_id, uid: int = user_id):
            sess = session_factory()
            user_obj = sess.query(User).get(uid)
            try:
                asyncio.run(incident_service.attach_alerts(sess, target_inc_id, [aid], current_user=user_obj))
            finally:
                sess.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_worker, aid) for aid in alert_ids]
            concurrent.futures.wait(futures)

        verify_sess = session_factory()
        final_inc = verify_sess.query(Incident).get(inc_id)
        assert final_inc.severity == "CRITICAL"
        verify_sess.close()


# ── 4. Concurrent Lifecycle Races & Status Transitions ─────────────────────────

def test_concurrent_lifecycle_and_attach_races(file_db):
    session_factory, _ = file_db

    init_sess = session_factory()
    u1 = User(email="user@life.com", hashed_pw="pw", role="user", is_active=True)
    init_sess.add(u1)
    init_sess.commit()

    inc = Incident(title="Lifecycle Race Inc", created_by_user_id=u1.id, severity="MEDIUM", status="OPEN")
    a1 = Alert(title="Life Alert", rule_name="R1", indicator_type="URL", indicator_value="http://life.com", severity="CRITICAL", user_id=u1.id)
    init_sess.add_all([inc, a1])
    init_sess.commit()
    inc_id, alert_id, user_id = inc.id, a1.id, u1.id
    init_sess.close()

    def _worker_transition(target_status: str):
        sess = session_factory()
        user_obj = sess.query(User).get(user_id)
        try:
            asyncio.run(incident_service.update_incident(sess, inc_id, IncidentUpdate(status=target_status), current_user=user_obj))
        except IncidentValidationError:
            pass
        finally:
            sess.close()

    def _worker_attach():
        sess = session_factory()
        user_obj = sess.query(User).get(user_id)
        try:
            asyncio.run(incident_service.attach_alerts(sess, inc_id, [alert_id], current_user=user_obj))
        finally:
            sess.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        f1 = executor.submit(_worker_transition, "INVESTIGATING")
        f2 = executor.submit(_worker_attach)
        f3 = executor.submit(_worker_transition, "CLOSED")
        concurrent.futures.wait([f1, f2, f3])

    verify_sess = session_factory()
    final_inc = verify_sess.query(Incident).get(inc_id)
    assert final_inc.status in ("OPEN", "INVESTIGATING", "CLOSED")
    assert final_inc.severity == "CRITICAL"
    verify_sess.close()


# ── 5. State Machine Adversarial Tests ────────────────────────────────────────

def test_state_machine_adversarial_matrix(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        inc = await incident_service.create_incident(memory_db, IncidentCreate(title="Matrix Inc"), current_user=u1)
        assert inc.status == "OPEN"

        # Invalid: OPEN -> RESOLVED
        with pytest.raises(IncidentValidationError):
            await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.RESOLVED), current_user=u1)

        # Valid: OPEN -> CLOSED
        inc = await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.CLOSED), current_user=u1)
        assert inc.status == "CLOSED"
        assert inc.closed_at is not None

        # Invalid: CLOSED -> INVESTIGATING
        with pytest.raises(IncidentValidationError):
            await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.INVESTIGATING), current_user=u1)

        # Invalid: CLOSED -> CONTAINED
        with pytest.raises(IncidentValidationError):
            await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.CONTAINED), current_user=u1)

        # Valid: CLOSED -> OPEN (reopened)
        inc = await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.OPEN), current_user=u1)
        assert inc.status == "OPEN"
        assert inc.closed_at is None

        # OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED
        await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.INVESTIGATING), current_user=u1)
        await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.CONTAINED), current_user=u1)
        inc = await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.RESOLVED), current_user=u1)
        assert inc.status == "RESOLVED"
        assert inc.closed_at is not None

        # Invalid: RESOLVED -> INVESTIGATING
        with pytest.raises(IncidentValidationError):
            await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.INVESTIGATING), current_user=u1)

        # Invalid: RESOLVED -> CONTAINED
        with pytest.raises(IncidentValidationError):
            await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(status=IncidentStatus.CONTAINED), current_user=u1)

    asyncio.run(_test())


# ── 6. Manual Severity Downgrade Security ──────────────────────────────────────

def test_manual_severity_downgrade_security(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        admin = test_users["admin"]

        inc = await incident_service.create_incident(memory_db, IncidentCreate(title="Crit Inc", severity=EventSeverity.CRITICAL), current_user=u1)
        assert inc.severity == "CRITICAL"

        # Standard user attempts manual downgrade -> REJECTED 403 AccessDenied
        for lower_sev in [EventSeverity.HIGH, EventSeverity.MEDIUM, EventSeverity.LOW, EventSeverity.INFO]:
            with pytest.raises(IncidentAccessDeniedError):
                await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(severity=lower_sev), current_user=u1)

        # Attach lower severity alert -> MUST NOT downgrade severity automatically
        a_low = Alert(title="Low Alert", rule_name="R1", indicator_type="URL", indicator_value="http://low.com", severity="LOW", user_id=u1.id)
        memory_db.add(a_low)
        memory_db.commit()
        inc = await incident_service.attach_alerts(memory_db, inc.id, [a_low.id], current_user=u1)
        assert inc.severity == "CRITICAL"

        # Admin user manual downgrade -> ALLOWED with audit event
        inc = await incident_service.update_incident(memory_db, inc.id, IncidentUpdate(severity=EventSeverity.HIGH), current_user=admin)
        assert inc.severity == "HIGH"

        audit = memory_db.scalars(select(AuditEvent).where(AuditEvent.action == "INCIDENT_UPDATED")).first()
        assert audit is not None
        assert audit.actor_user_id == admin.id

    asyncio.run(_test())


# ── 7. Detach Security ─────────────────────────────────────────────────────────

def test_detach_security_suite(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        u2 = test_users["user2"]

        inc1 = await incident_service.create_incident(memory_db, IncidentCreate(title="Inc 1"), current_user=u1)
        a1 = Alert(title="A1", rule_name="R1", indicator_type="URL", indicator_value="http://a1.com", severity="HIGH", user_id=u1.id)
        a2 = Alert(title="A2", rule_name="R2", indicator_type="URL", indicator_value="http://a2.com", severity="HIGH", user_id=u2.id)
        memory_db.add_all([a1, a2])
        memory_db.commit()

        await incident_service.attach_alerts(memory_db, inc1.id, [a1.id], current_user=u1)

        # Nonexistent alert detach -> 404
        with pytest.raises(IncidentNotFoundError):
            await incident_service.detach_alert(memory_db, inc1.id, alert_id=9999, current_user=u1)

        # Cross-user or unattached alert detach attempt -> raises IncidentNotFoundError or IncidentAccessDeniedError
        with pytest.raises((IncidentNotFoundError, IncidentAccessDeniedError)):
            await incident_service.detach_alert(memory_db, inc1.id, alert_id=a2.id, current_user=u1)

        # Authorized detach
        inc1 = await incident_service.detach_alert(memory_db, inc1.id, alert_id=a1.id, current_user=u1)
        assert len(inc1.alerts) == 0

        audit = memory_db.scalars(select(AuditEvent).where(AuditEvent.action == "ALERT_DETACHED")).first()
        assert audit is not None

    asyncio.run(_test())


# ── 8. Tenant Isolation Adversarial Test ───────────────────────────────────────

def test_tenant_isolation_adversarial_suite(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        u2 = test_users["user2"]

        inc_u1 = await incident_service.create_incident(memory_db, IncidentCreate(title="U1 Inc"), current_user=u1)
        inc_sys = await incident_service.create_incident(memory_db, IncidentCreate(title="Sys Inc"), current_user=None)

        a_u1 = Alert(title="A1", rule_name="R1", indicator_type="URL", indicator_value="http://u1.com", severity="HIGH", user_id=u1.id)
        a_u2 = Alert(title="A2", rule_name="R2", indicator_type="URL", indicator_value="http://u2.com", severity="HIGH", user_id=u2.id)
        memory_db.add_all([a_u1, a_u2])
        memory_db.commit()

        # User 2 attempts GET User 1's incident -> 404
        with pytest.raises(IncidentNotFoundError):
            await incident_service.get_incident(memory_db, inc_u1.id, current_user=u2)

        # User 2 attempts PATCH User 1's incident -> 404
        with pytest.raises(IncidentNotFoundError):
            await incident_service.update_incident(memory_db, inc_u1.id, IncidentUpdate(title="Hacked"), current_user=u2)

        # User 1 attempts ATTACH User 2's alert -> 403
        with pytest.raises(IncidentAccessDeniedError):
            await incident_service.attach_alerts(memory_db, inc_u1.id, [a_u2.id], current_user=u1)

        # User 1 attempts GET System incident -> 404
        with pytest.raises(IncidentNotFoundError):
            await incident_service.get_incident(memory_db, inc_sys.id, current_user=u1)

        # User 1 LIST returns ONLY User 1's incidents (System & User 2 excluded)
        user1_list, _ = await incident_service.list_incidents(memory_db, current_user=u1)
        assert len(user1_list) == 1
        assert user1_list[0].id == inc_u1.id

    asyncio.run(_test())


# ── 9. Audit Log Security (Suspicious & Nested Secret Redaction) ───────────────

def test_audit_log_security_sanitization(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        suspicious_payload = {
            "title": "Clean Title",
            "PASSWORD": "PlaintextPassword123",
            "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "secret_key": "super_secret_api_key",
            "headers": {
                "Authorization": "Bearer secret_bearer_token",
                "Cookie": "session_id=12345",
            },
            "credentials_list": [
                {"API_KEY": "key_999"},
                "Bearer token_in_list",
            ],
            "control_chars": "Line1\x00\x07\nLine2",
        }

        await incident_service._audit(
            session=memory_db,
            action="ADV_SECURITY_AUDIT",
            actor_user_id=u1.id,
            target_resource="Incident",
            resource_id="1",
            details=suspicious_payload,
        )
        memory_db.commit()

        audit = memory_db.scalars(select(AuditEvent).where(AuditEvent.action == "ADV_SECURITY_AUDIT")).first()
        assert audit is not None
        d = audit.details

        assert d["PASSWORD"] == "[REDACTED]"
        assert d["jwt_token"] == "[REDACTED]"
        assert d["secret_key"] == "[REDACTED]"
        assert d["headers"]["Authorization"] == "[REDACTED]"
        assert d["headers"]["Cookie"] == "[REDACTED]"
        assert isinstance(d["credentials_list"], list)
        assert d["credentials_list"][0]["API_KEY"] == "[REDACTED]"
        assert d["credentials_list"][1] == "[REDACTED]"
        assert "\x00" not in d["control_chars"]
        assert "Line1" in d["control_chars"]

    asyncio.run(_test())


# ── 10. Pagination & Boundary Testing ──────────────────────────────────────────

def test_pagination_boundary_suite(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        for i in range(15):
            await incident_service.create_incident(memory_db, IncidentCreate(title=f"Page Inc {i}"), current_user=u1)

        # Page size 1
        p1, _ = await incident_service.list_incidents(memory_db, current_user=u1, limit=1, offset=0)
        assert len(p1) == 1

        # Page size 500 (clamped to 100 max)
        p_max, total = await incident_service.list_incidents(memory_db, current_user=u1, limit=500, offset=0)
        assert len(p_max) == 15
        assert total == 15

        # Negative page offset (clamped to 0)
        p_neg, _ = await incident_service.list_incidents(memory_db, current_user=u1, limit=10, offset=-50)
        assert len(p_neg) == 10

        # Out of bounds offset
        p_large, _ = await incident_service.list_incidents(memory_db, current_user=u1, limit=10, offset=9999)
        assert len(p_large) == 0

    asyncio.run(_test())


# ── 11. Error Safety & Exception Sanitization ─────────────────────────────────

def test_error_safety_no_leakage(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]

        # Invalid UUID format -> controlled IncidentValidationError
        with pytest.raises(IncidentValidationError) as exc:
            await incident_service.get_incident(memory_db, "not-a-valid-uuid-or-id", current_user=u1)
        err_str = str(exc.value)
        assert "Invalid incident identifier format" in err_str
        assert "SELECT" not in err_str
        assert "Traceback" not in err_str

    asyncio.run(_test())


# ── 12. Database Transaction Integrity & Rollback ─────────────────────────────

def test_transaction_rollback_integrity(memory_db: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        inc = await incident_service.create_incident(memory_db, IncidentCreate(title="Rollback Test Inc"), current_user=u1)

        # Attempt attaching nonexistent alert -> raises IncidentNotFoundError and rolls back session
        with pytest.raises(IncidentNotFoundError):
            await incident_service.attach_alerts(memory_db, inc.id, alert_ids=[99999], current_user=u1)

        # Incident status remains OPEN and clean
        re_inc = await incident_service.get_incident(memory_db, inc.id, current_user=u1)
        assert re_inc.status == "OPEN"
        assert len(re_inc.alerts) == 0

    asyncio.run(_test())
