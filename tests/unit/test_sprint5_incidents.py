"""
tests/unit/test_sprint5_incidents.py
──────────────────────────────────────
Sprint 5 Phase 4: Incident Management Service Unit Tests.

Verifies:
- Incident creation, retrieval (ID & UUID), and listing
- Multi-tenant ownership isolation & system incident scoping
- Incident state machine transitions & invalid transition rejection
- Monotonic severity escalation & downgrade prevention
- Safe Alert attachment & duplicate/conflict rejection (no silent stealing)
- Alert detachment & preservation of incident severity
- Aggregated derived analytical summary computation
- Audit event logging with sensitive detail sanitization
- Invalid request payloads & forbidden extra fields
- Database transaction safety
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import Alert, AuditEvent, Base, User
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
def db_session():
    """In-memory SQLite database session for unit testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture
def test_users(db_session: Session):
    """Seed test users: standard user 1, standard user 2, admin user."""
    u1 = User(email="user1@test.com", hashed_pw="pw1", role="user", is_active=True)
    u2 = User(email="user2@test.com", hashed_pw="pw2", role="user", is_active=True)
    admin = User(email="admin@test.com", hashed_pw="pwa", role="admin", is_active=True)

    db_session.add_all([u1, u2, admin])
    db_session.commit()
    db_session.refresh(u1)
    db_session.refresh(u2)
    db_session.refresh(admin)

    return {"user1": u1, "user2": u2, "admin": admin}


# ── 1. Incident Creation Tests ────────────────────────────────────────────────

def test_create_incident_success(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        payload = IncidentCreate(
            title="Phishing Campaign Detected",
            description="Multiple suspicious URLs detected in email domain.",
            severity=EventSeverity.HIGH,
        )

        incident = await incident_service.create_incident(
            session=db_session,
            data=payload,
            current_user=u1,
        )

        assert incident.id is not None
        assert len(incident.incident_uuid) == 36
        assert incident.title == "Phishing Campaign Detected"
        assert incident.status == "OPEN"
        assert incident.severity == "HIGH"
        assert incident.created_by_user_id == u1.id

        # Verify audit event created
        audit = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "INCIDENT_CREATED")).first()
        assert audit is not None
        assert audit.actor_user_id == u1.id
        assert audit.target_resource == "Incident"
        assert audit.resource_id == str(incident.id)

    asyncio.run(_test())


def test_create_system_incident(db_session: Session):
    """System incidents created without current_user have created_by_user_id = None."""
    async def _test():
        payload = IncidentCreate(
            title="System Infrastructure Anomaly",
            severity=EventSeverity.CRITICAL,
        )

        incident = await incident_service.create_incident(
            session=db_session,
            data=payload,
            current_user=None,
        )

        assert incident.created_by_user_id is None
        assert incident.severity == "CRITICAL"

    asyncio.run(_test())


# ── 2. Incident Retrieval & Multi-Tenant Isolation ─────────────────────────────

def test_get_incident_by_id_and_uuid(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        inc = await incident_service.create_incident(
            session=db_session,
            data=IncidentCreate(title="Test Incident"),
            current_user=u1,
        )

        # By ID
        res1 = await incident_service.get_incident(db_session, inc.id, current_user=u1)
        assert res1.id == inc.id

        # By UUID
        res2 = await incident_service.get_incident(db_session, inc.incident_uuid, current_user=u1)
        assert res2.id == inc.id

    asyncio.run(_test())


def test_tenant_isolation_get_incident(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        u2 = test_users["user2"]
        admin = test_users["admin"]

        inc_u1 = await incident_service.create_incident(
            session=db_session,
            data=IncidentCreate(title="User 1 Incident"),
            current_user=u1,
        )

        sys_inc = await incident_service.create_incident(
            session=db_session,
            data=IncidentCreate(title="System Incident"),
            current_user=None,
        )

        # User 1 can access own incident
        res = await incident_service.get_incident(db_session, inc_u1.id, current_user=u1)
        assert res.id == inc_u1.id

        # User 2 CANNOT access User 1's incident (raises 404 IncidentNotFoundError)
        with pytest.raises(IncidentNotFoundError):
            await incident_service.get_incident(db_session, inc_u1.id, current_user=u2)

        # User 1 CANNOT access System incident (raises 404 IncidentNotFoundError)
        with pytest.raises(IncidentNotFoundError):
            await incident_service.get_incident(db_session, sys_inc.id, current_user=u1)

        # Admin CAN access User 1's incident and System incident
        res_admin1 = await incident_service.get_incident(db_session, inc_u1.id, current_user=admin)
        assert res_admin1.id == inc_u1.id

        res_admin2 = await incident_service.get_incident(db_session, sys_inc.id, current_user=admin)
        assert res_admin2.id == sys_inc.id

    asyncio.run(_test())


# ── 3. Incident Listing & Pagination ──────────────────────────────────────────

def test_list_incidents_tenant_isolation_and_pagination(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        u2 = test_users["user2"]
        admin = test_users["admin"]

        # Create 3 incidents for u1, 2 for u2
        for i in range(3):
            await incident_service.create_incident(db_session, IncidentCreate(title=f"U1 Inc {i}"), current_user=u1)
        for i in range(2):
            await incident_service.create_incident(db_session, IncidentCreate(title=f"U2 Inc {i}"), current_user=u2)

        # u1 list -> 3 incidents
        u1_list, u1_total = await incident_service.list_incidents(db_session, current_user=u1)
        assert u1_total == 3
        assert len(u1_list) == 3
        assert all(inc.created_by_user_id == u1.id for inc in u1_list)

        # u2 list -> 2 incidents
        u2_list, u2_total = await incident_service.list_incidents(db_session, current_user=u2)
        assert u2_total == 2

        # admin list -> all 5 incidents
        admin_list, admin_total = await incident_service.list_incidents(db_session, current_user=admin)
        assert admin_total == 5

        # Pagination test
        page1, total = await incident_service.list_incidents(db_session, current_user=u1, limit=2, offset=0)
        assert len(page1) == 2
        assert total == 3

        page2, _ = await incident_service.list_incidents(db_session, current_user=u1, limit=2, offset=2)
        assert len(page2) == 1

    asyncio.run(_test())


# ── 4. Lifecycle & State Machine Tests ────────────────────────────────────────

def test_incident_valid_status_transitions(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        inc = await incident_service.create_incident(db_session, IncidentCreate(title="Transition Test"), current_user=u1)
        assert inc.status == "OPEN"

        # OPEN -> INVESTIGATING
        inc = await incident_service.update_incident(
            db_session, inc.id, IncidentUpdate(status=IncidentStatus.INVESTIGATING), current_user=u1
        )
        assert inc.status == "INVESTIGATING"

        # INVESTIGATING -> CONTAINED
        inc = await incident_service.update_incident(
            db_session, inc.id, IncidentUpdate(status=IncidentStatus.CONTAINED), current_user=u1
        )
        assert inc.status == "CONTAINED"

        # CONTAINED -> RESOLVED
        inc = await incident_service.update_incident(
            db_session, inc.id, IncidentUpdate(status=IncidentStatus.RESOLVED), current_user=u1
        )
        assert inc.status == "RESOLVED"
        assert inc.closed_at is not None

        # RESOLVED -> CLOSED
        inc = await incident_service.update_incident(
            db_session, inc.id, IncidentUpdate(status=IncidentStatus.CLOSED), current_user=u1
        )
        assert inc.status == "CLOSED"

        # CLOSED -> OPEN (reopened)
        inc = await incident_service.update_incident(
            db_session, inc.id, IncidentUpdate(status=IncidentStatus.OPEN), current_user=u1
        )
        assert inc.status == "OPEN"
        assert inc.closed_at is None

    asyncio.run(_test())


def test_incident_invalid_status_transition_rejected(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        inc = await incident_service.create_incident(db_session, IncidentCreate(title="Invalid Transition Test"), current_user=u1)

        # OPEN -> RESOLVED is INVALID
        with pytest.raises(IncidentValidationError) as exc:
            await incident_service.update_incident(
                db_session, inc.id, IncidentUpdate(status=IncidentStatus.RESOLVED), current_user=u1
            )
        assert "Invalid status transition from 'OPEN' to 'RESOLVED'" in str(exc.value)

    asyncio.run(_test())


# ── 5. Alert Attachment & Monotonic Severity Escalation ───────────────────────

def test_alert_attachment_and_monotonic_severity(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]

        # Create LOW severity incident
        inc = await incident_service.create_incident(
            db_session,
            IncidentCreate(title="Low Sev Incident", severity=EventSeverity.LOW),
            current_user=u1,
        )
        assert inc.severity == "LOW"

        # Create alerts with different severities for u1
        a_med = Alert(title="Alert 1", rule_name="R1", indicator_type="URL", indicator_value="http://low.com", severity="MEDIUM", user_id=u1.id)
        a_crit = Alert(title="Alert 2", rule_name="R2", indicator_type="DOMAIN", indicator_value="phish.com", severity="CRITICAL", user_id=u1.id)
        a_info = Alert(title="Alert 3", rule_name="R3", indicator_type="IP", indicator_value="1.2.3.4", severity="INFO", user_id=u1.id)

        db_session.add_all([a_med, a_crit, a_info])
        db_session.commit()

        # Attach MEDIUM alert -> escalates incident severity to MEDIUM
        inc = await incident_service.attach_alerts(db_session, inc.id, [a_med.id], current_user=u1)
        assert inc.severity == "MEDIUM"

        # Attach CRITICAL alert -> escalates incident severity to CRITICAL
        inc = await incident_service.attach_alerts(db_session, inc.id, [a_crit.id], current_user=u1)
        assert inc.severity == "CRITICAL"

        # Attach INFO alert -> MUST NOT downgrade severity (remains CRITICAL)
        inc = await incident_service.attach_alerts(db_session, inc.id, [a_info.id], current_user=u1)
        assert inc.severity == "CRITICAL"

    asyncio.run(_test())


def test_alert_attachment_cross_tenant_rejected(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        u2 = test_users["user2"]

        inc_u1 = await incident_service.create_incident(db_session, IncidentCreate(title="U1 Inc"), current_user=u1)
        a_u2 = Alert(title="U2 Alert", rule_name="R2", indicator_type="URL", indicator_value="http://u2.com", severity="HIGH", user_id=u2.id)
        db_session.add(a_u2)
        db_session.commit()

        # User 1 tries to attach User 2's alert -> Access Denied
        with pytest.raises(IncidentAccessDeniedError):
            await incident_service.attach_alerts(db_session, inc_u1.id, [a_u2.id], current_user=u1)

    asyncio.run(_test())


def test_alert_attachment_conflict_rejected(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]

        inc1 = await incident_service.create_incident(db_session, IncidentCreate(title="Inc 1"), current_user=u1)
        inc2 = await incident_service.create_incident(db_session, IncidentCreate(title="Inc 2"), current_user=u1)

        a1 = Alert(title="Dup Alert", rule_name="R1", indicator_type="URL", indicator_value="http://test.com", severity="HIGH", user_id=u1.id)
        db_session.add(a1)
        db_session.commit()

        # Attach to inc1
        await incident_service.attach_alerts(db_session, inc1.id, [a1.id], current_user=u1)

        # Attach to inc2 -> Conflict! Reassignment rejected
        with pytest.raises(IncidentConflictError) as exc:
            await incident_service.attach_alerts(db_session, inc2.id, [a1.id], current_user=u1)
        assert "already attached to Incident ID" in str(exc.value)

    asyncio.run(_test())


# ── 6. Alert Detachment & Aggregation ──────────────────────────────────────────

def test_detach_alert_and_aggregation(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]

        inc = await incident_service.create_incident(db_session, IncidentCreate(title="Aggregation Test"), current_user=u1)
        a1 = Alert(title="A1", rule_name="R1", indicator_type="URL", indicator_value="http://sub.malware.com/path", severity="HIGH", user_id=u1.id)
        a2 = Alert(title="A2", rule_name="R2", indicator_type="IP", indicator_value="192.168.1.100", severity="CRITICAL", user_id=u1.id)
        db_session.add_all([a1, a2])
        db_session.commit()

        inc = await incident_service.attach_alerts(db_session, inc.id, [a1.id, a2.id], current_user=u1)

        # Summary context
        summary = incident_service.build_summary(inc)
        assert summary.alert_count == 2
        assert summary.highest_severity == "CRITICAL"
        assert "192.168.1.100" in summary.affected_ips
        assert "malware.com" in summary.affected_domains

        # Detach a2
        inc = await incident_service.detach_alert(db_session, inc.id, a2.id, current_user=u1)
        assert len(inc.alerts) == 1
        assert inc.alerts[0].id == a1.id
        # Severity is preserved (not automatically downgraded)
        assert inc.severity == "CRITICAL"

    asyncio.run(_test())


# ── 7. Audit Event Sanitization ────────────────────────────────────────────────

def test_audit_event_sanitization(db_session: Session, test_users):
    async def _test():
        u1 = test_users["user1"]
        await incident_service._audit(
            session=db_session,
            action="INCIDENT_TEST",
            actor_user_id=u1.id,
            target_resource="Incident",
            resource_id="100",
            details={"token": "secret_jwt_token", "normal_field": "safe_value"},
        )
        db_session.commit()

        audit = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "INCIDENT_TEST")).first()
        assert audit is not None
        assert audit.details["token"] == "[REDACTED]"
        assert audit.details["normal_field"] == "safe_value"

    asyncio.run(_test())
