"""
tests/unit/test_alert_triage.py
───────────────────────────────
Sprint 5 Phase 5C: Unit tests for Security Alert Triage Lifecycle & State Transitions.

Verifies:
1. Canonical AlertStatus state machine:
   - OPEN -> ACKNOWLEDGED, RESOLVED, DISMISSED
   - ACKNOWLEDGED -> RESOLVED, DISMISSED, OPEN
   - RESOLVED -> OPEN
   - DISMISSED -> OPEN
2. Forbidden terminal state transitions:
   - RESOLVED -> DISMISSED (400 / AlertInvalidTransitionError)
   - DISMISSED -> RESOLVED (400 / AlertInvalidTransitionError)
3. Idempotent self-transitions (no duplicate audit events, no timestamp mutation)
4. Triage notes & dismissal metadata requirements (dismiss_reason min length 3)
5. Timestamp correctness (setting and clearing timestamps on transition)
6. Dismissed/Resolved Alert recurrence creates a brand-new Alert entity (no silent suppression)
7. Alert triage does NOT mutate parent Incident state (strict decoupling)
8. Multi-tenant access controls and anti-enumeration 404 behavior
9. Alert statistics calculation (instantaneous counts and rolling 24-hour dedup ratio)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import Alert, AuditEvent, Base, Incident, User
from backend.schemas.alerts import AlertStatus
from backend.schemas.soc import EventSeverity, EventType, IndicatorType, SecurityEventSchema
from backend.services.alert_service import (
    AlertInvalidTransitionError,
    AlertNotFoundError,
    AlertValidationError,
    alert_service,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def db_session():
    """Create in-memory SQLite database session for unit tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    # Seed test users
    u1 = User(id=1, email="analyst1@test.com", hashed_pw="pw1", role="user", is_active=True)
    u2 = User(id=2, email="analyst2@test.com", hashed_pw="pw2", role="user", is_active=True)
    admin = User(id=3, email="admin@test.com", hashed_pw="pwa", role="admin", is_active=True)
    session.add_all([u1, u2, admin])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(engine)


def _seed_alert(
    session: Session,
    user_id: int = 1,
    status: str = AlertStatus.OPEN.value,
    severity: str = "HIGH",
    rule_name: str = "TEST_RULE",
    fingerprint: str | None = None,
) -> Alert:
    """Helper to seed an alert in the database."""
    now = datetime.now(timezone.utc)
    fp = fingerprint or f"fp_{uuid.uuid4().hex[:16]}"
    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        title=f"Test Alert for {rule_name}",
        description="Test alert description",
        severity=severity,
        status=status,
        rule_name=rule_name,
        indicator_type="DOMAIN",
        indicator_value="evil-domain.com",
        fingerprint=fp,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
        user_id=user_id,
    )
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


# ── State Machine Transition Tests ─────────────────────────────────────────────

@pytest.mark.anyio
async def test_transition_open_to_acknowledged(db_session: Session):
    """Analyst claims an OPEN alert, moving it to ACKNOWLEDGED."""
    u1 = db_session.query(User).filter_by(id=1).one()
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    res = await alert_service.acknowledge_alert(
        db_session, alert.alert_uuid, u1, notes="Investigating suspicious beaconing"
    )

    assert res.status == AlertStatus.ACKNOWLEDGED.value
    assert res.acknowledged_at is not None
    assert res.triage_notes == "Investigating suspicious beaconing"

    # Verify AuditEvent
    audit = db_session.execute(
        select(AuditEvent).where(
            AuditEvent.resource_id == alert.alert_uuid,
            AuditEvent.action == "ALERT_ACKNOWLEDGED",
        )
    ).scalar_one_or_none()
    assert audit is not None
    assert audit.actor_user_id == 1


@pytest.mark.anyio
async def test_transition_open_to_resolved(db_session: Session):
    """Fast resolution of an OPEN alert."""
    u1 = db_session.query(User).filter_by(id=1).one()
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    res = await alert_service.resolve_alert(
        db_session, alert.alert_uuid, u1, notes="Pre-mitigated by firewall rule"
    )

    assert res.status == AlertStatus.RESOLVED.value
    assert res.resolved_at is not None
    assert res.triage_notes == "Pre-mitigated by firewall rule"

    audit = db_session.execute(
        select(AuditEvent).where(
            AuditEvent.resource_id == alert.alert_uuid,
            AuditEvent.action == "ALERT_RESOLVED",
        )
    ).scalar_one_or_none()
    assert audit is not None


@pytest.mark.anyio
async def test_transition_open_to_dismissed(db_session: Session):
    """Analyst dismisses an OPEN alert with reason."""
    u1 = db_session.query(User).filter_by(id=1).one()
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    res = await alert_service.dismiss_alert(
        db_session, alert.alert_uuid, u1, reason="BENIGN_SCAN", notes="Authorized pen-test IP"
    )

    assert res.status == AlertStatus.DISMISSED.value
    assert res.dismissed_at is not None
    assert res.dismiss_reason == "BENIGN_SCAN"
    assert res.triage_notes == "Authorized pen-test IP"

    audit = db_session.execute(
        select(AuditEvent).where(
            AuditEvent.resource_id == alert.alert_uuid,
            AuditEvent.action == "ALERT_DISMISSED",
        )
    ).scalar_one_or_none()
    assert audit is not None


@pytest.mark.anyio
async def test_transition_acknowledged_to_open(db_session: Session):
    """Analyst unclaims an ACKNOWLEDGED alert, releasing it back to OPEN."""
    u1 = db_session.query(User).filter_by(id=1).one()
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)
    await alert_service.acknowledge_alert(db_session, alert.alert_uuid, u1)

    # Reopen / release back to OPEN
    res = await alert_service.reopen_alert(db_session, alert.alert_uuid, u1, notes="Releasing back to queue")
    assert res.status == AlertStatus.OPEN.value
    assert res.acknowledged_at is None
    assert res.triage_notes == "Releasing back to queue"


@pytest.mark.anyio
async def test_reopen_clears_terminal_timestamps(db_session: Session):
    """Reopening a RESOLVED or DISMISSED alert clears resolved_at / dismissed_at."""
    u1 = db_session.query(User).filter_by(id=1).one()

    # Resolve and then Reopen
    alert_res = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)
    await alert_service.resolve_alert(db_session, alert_res.alert_uuid, u1)
    reopened = await alert_service.reopen_alert(db_session, alert_res.alert_uuid, u1, notes="Threat re-occurred")
    assert reopened.status == AlertStatus.OPEN.value
    assert reopened.resolved_at is None

    # Dismiss and then Reopen
    alert_dis = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)
    await alert_service.dismiss_alert(db_session, alert_dis.alert_uuid, u1, reason="FALSE_POSITIVE")
    reopened_dis = await alert_service.reopen_alert(db_session, alert_dis.alert_uuid, u1, notes="FP reversed")
    assert reopened_dis.status == AlertStatus.OPEN.value
    assert reopened_dis.dismissed_at is None
    assert reopened_dis.dismiss_reason is None


@pytest.mark.anyio
async def test_forbidden_terminal_flips(db_session: Session):
    """
    Direct transitions between RESOLVED and DISMISSED are strictly forbidden (Section 1.4).
    Must return AlertInvalidTransitionError (mapped to HTTP 400).
    """
    u1 = db_session.query(User).filter_by(id=1).one()

    # Case 1: RESOLVED -> DISMISSED is forbidden
    resolved = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)
    await alert_service.resolve_alert(db_session, resolved.alert_uuid, u1)
    with pytest.raises(AlertInvalidTransitionError):
        await alert_service.dismiss_alert(db_session, resolved.alert_uuid, u1, reason="FALSE_POSITIVE")

    # Case 2: DISMISSED -> RESOLVED is forbidden
    dismissed = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)
    await alert_service.dismiss_alert(db_session, dismissed.alert_uuid, u1, reason="FALSE_POSITIVE")
    with pytest.raises(AlertInvalidTransitionError):
        await alert_service.resolve_alert(db_session, dismissed.alert_uuid, u1)


@pytest.mark.anyio
async def test_idempotent_self_transitions(db_session: Session):
    """Transition to current state is a safe no-op returning existing entity without audit pollution."""
    u1 = db_session.query(User).filter_by(id=1).one()
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    # First acknowledge -> 1 audit event
    await alert_service.acknowledge_alert(db_session, alert.alert_uuid, u1)
    audits_after_1 = db_session.execute(
        select(AuditEvent).where(AuditEvent.resource_id == alert.alert_uuid)
    ).scalars().all()
    assert len(audits_after_1) == 1

    # Second acknowledge -> Idempotent, exactly 1 audit event remains
    res = await alert_service.acknowledge_alert(db_session, alert.alert_uuid, u1)
    assert res.status == AlertStatus.ACKNOWLEDGED.value
    audits_after_2 = db_session.execute(
        select(AuditEvent).where(AuditEvent.resource_id == alert.alert_uuid)
    ).scalars().all()
    assert len(audits_after_2) == 1


@pytest.mark.anyio
async def test_dismiss_requires_valid_reason(db_session: Session):
    """dismiss_alert requires a non-empty reason with min length 3."""
    u1 = db_session.query(User).filter_by(id=1).one()
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    with pytest.raises(AlertValidationError):
        await alert_service.dismiss_alert(db_session, alert.alert_uuid, u1, reason="")

    with pytest.raises(AlertValidationError):
        await alert_service.dismiss_alert(db_session, alert.alert_uuid, u1, reason="no")


# ── Recurrence Handling Tests ──────────────────────────────────────────────────

@pytest.mark.anyio
async def test_dismissed_alert_recurrence_creates_brand_new_alert(db_session: Session):
    """
    CRITICAL: When an indicator previously DISMISSED is detected again,
    must create a brand-new Alert entity with status='OPEN' and occurrence_count=1.
    The historical dismissed alert must NOT be mutated.
    """
    u1 = db_session.query(User).filter_by(id=1).one()

    # 1. Process initial event
    now = datetime.now(timezone.utc)
    ev1 = SecurityEventSchema(
        event_uuid=str(uuid.uuid4()),
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="recurrence-evil.com",
        user_id=u1.id,
        timestamp=now,
    )
    alert1, is_new1 = alert_service.process_event(db_session, ev1, rule_name="DETECTION_RECURRENCE")
    assert is_new1 is True
    assert alert1.status == AlertStatus.OPEN.value
    fp = alert1.fingerprint
    id1 = alert1.id
    uuid1 = alert1.alert_uuid

    # 2. Analyst dismisses alert1
    await alert_service.dismiss_alert(
        db_session, uuid1, u1, reason="ACCEPTED_RISK", notes="Whitelisted vendor domain"
    )
    db_session.refresh(alert1)
    assert alert1.status == AlertStatus.DISMISSED.value
    assert alert1.dismiss_reason == "ACCEPTED_RISK"
    assert alert1.occurrence_count == 1

    # 3. New security event arrives with same fingerprint
    ev2 = SecurityEventSchema(
        event_uuid=str(uuid.uuid4()),
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="recurrence-evil.com",
        user_id=u1.id,
        timestamp=now + timedelta(minutes=5),
    )
    alert2, is_new2 = alert_service.process_event(db_session, ev2, rule_name="DETECTION_RECURRENCE")

    # 4. Verify invariants:
    # A) A brand-new Alert entity was created
    assert is_new2 is True
    assert alert2.id != id1
    assert alert2.alert_uuid != uuid1
    assert alert2.fingerprint == fp
    assert alert2.status == AlertStatus.OPEN.value
    assert alert2.occurrence_count == 1

    # B) The historical alert1 remains untouched and DISMISSED
    alert1_fresh = db_session.query(Alert).filter_by(id=id1).one()
    assert alert1_fresh.status == AlertStatus.DISMISSED.value
    assert alert1_fresh.dismiss_reason == "ACCEPTED_RISK"
    assert alert1_fresh.occurrence_count == 1


@pytest.mark.anyio
async def test_resolved_alert_recurrence_creates_brand_new_alert(db_session: Session):
    """Same recurrence contract verification for RESOLVED alerts."""
    u1 = db_session.query(User).filter_by(id=1).one()
    now = datetime.now(timezone.utc)

    ev1 = SecurityEventSchema(
        event_uuid=str(uuid.uuid4()),
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="resolved-evil.com",
        user_id=u1.id,
        timestamp=now,
    )
    alert1, _ = alert_service.process_event(db_session, ev1)
    await alert_service.resolve_alert(db_session, alert1.alert_uuid, u1, notes="Host isolated")
    id1 = alert1.id

    ev2 = SecurityEventSchema(
        event_uuid=str(uuid.uuid4()),
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="resolved-evil.com",
        user_id=u1.id,
        timestamp=now + timedelta(minutes=10),
    )
    alert2, is_new = alert_service.process_event(db_session, ev2)

    assert is_new is True
    assert alert2.id != id1
    assert alert2.status == AlertStatus.OPEN.value

    # Historical alert remains RESOLVED
    db_session.refresh(alert1)
    assert alert1.status == AlertStatus.RESOLVED.value


# ── Alert ↔ Incident Boundary Test ─────────────────────────────────────────────

@pytest.mark.anyio
async def test_alert_triage_does_not_mutate_incident_state(db_session: Session):
    """
    CRITICAL: Resolving or dismissing an alert attached to an Incident
    must NEVER mutate the Incident's status or close the Incident.
    """
    u1 = db_session.query(User).filter_by(id=1).one()
    now = datetime.now(timezone.utc)

    # Seed Incident
    inc = Incident(
        incident_uuid=str(uuid.uuid4()),
        title="Test Threat Incident",
        severity="HIGH",
        status="OPEN",
        created_by_user_id=u1.id,
        created_at=now,
    )
    db_session.add(inc)
    db_session.commit()
    db_session.refresh(inc)

    # Seed Alert attached to this Incident
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)
    alert.incident_id = inc.id
    db_session.commit()

    # Analyst resolves the alert
    await alert_service.resolve_alert(db_session, alert.alert_uuid, u1, notes="Contained host")

    # Verify Incident status is STILL "OPEN"
    db_session.refresh(inc)
    assert inc.status == "OPEN", "Resolving an alert must not mutate Incident status"


# ── Tenant Isolation Tests ─────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_tenant_isolation_get_and_triage_alert(db_session: Session):
    """A standard user cannot view or triage an alert belonging to another tenant."""
    u2 = db_session.query(User).filter_by(id=2).one()

    # User 1's alert
    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    # User 2 attempts to get User 1's alert -> AlertNotFoundError (404 anti-enumeration)
    with pytest.raises(AlertNotFoundError):
        await alert_service.get_alert_by_uuid(db_session, alert.alert_uuid, u2)

    # User 2 attempts to acknowledge User 1's alert -> AlertNotFoundError
    with pytest.raises(AlertNotFoundError):
        await alert_service.acknowledge_alert(db_session, alert.alert_uuid, u2)


@pytest.mark.anyio
async def test_admin_role_can_triage_any_alert(db_session: Session):
    """Admin role can access and triage alerts across any tenant."""
    admin = db_session.query(User).filter_by(id=3).one()
    assert admin.role == "admin"

    alert = _seed_alert(db_session, user_id=1, status=AlertStatus.OPEN.value)

    # Admin acknowledges User 1's alert
    res = await alert_service.acknowledge_alert(db_session, alert.alert_uuid, admin, notes="SOC manager triage")
    assert res.status == AlertStatus.ACKNOWLEDGED.value


# ── Alert Statistics & Dedup Savings Ratio Test ────────────────────────────────

@pytest.mark.anyio
async def test_alert_stats_calculation(db_session: Session):
    """
    Verifies Section 8.2 mathematical bounds and dedup_savings_ratio formula:
    ratio = 1.0 - (D_distinct / N_occurrences)
    where D_distinct is candidate alerts in 24h window, and N_occurrences is sum(occurrence_count).
    """
    u1 = db_session.query(User).filter_by(id=1).one()
    now = datetime.now(timezone.utc)

    # Alert A: 150 occurrences, last_seen 2 hours ago
    a1 = Alert(
        alert_uuid=str(uuid.uuid4()),
        title="Alert A",
        severity="HIGH",
        status=AlertStatus.OPEN.value,
        rule_name="RULE_A",
        indicator_type="DOMAIN",
        indicator_value="a.com",
        fingerprint="fp_a",
        occurrence_count=150,
        first_seen_at=now - timedelta(days=3),
        last_seen_at=now - timedelta(hours=2),
        user_id=u1.id,
    )

    # Alert B: 50 occurrences, last_seen 1 hour ago
    a2 = Alert(
        alert_uuid=str(uuid.uuid4()),
        title="Alert B",
        severity="CRITICAL",
        status=AlertStatus.ACKNOWLEDGED.value,
        rule_name="RULE_B",
        indicator_type="DOMAIN",
        indicator_value="b.com",
        fingerprint="fp_b",
        occurrence_count=50,
        first_seen_at=now - timedelta(hours=1),
        last_seen_at=now - timedelta(hours=1),
        user_id=u1.id,
    )

    # Alert C: outside 24h window (last seen 48 hours ago)
    a3 = Alert(
        alert_uuid=str(uuid.uuid4()),
        title="Alert C",
        severity="LOW",
        status=AlertStatus.RESOLVED.value,
        rule_name="RULE_C",
        indicator_type="DOMAIN",
        indicator_value="c.com",
        fingerprint="fp_c",
        occurrence_count=10,
        first_seen_at=now - timedelta(days=5),
        last_seen_at=now - timedelta(hours=48),
        user_id=u1.id,
    )

    db_session.add_all([a1, a2, a3])
    db_session.commit()

    stats = await alert_service.get_alert_stats(db_session, u1)

    assert stats.total_alerts == 3
    assert stats.open_alerts == 1
    assert stats.acknowledged_alerts == 1
    assert stats.resolved_alerts == 1
    assert stats.dismissed_alerts == 0

    # 24h window: A and B touched -> 2 alerts
    assert stats.alerts_last_24h == 2
    assert stats.alert_velocity_per_hour == pytest.approx(2 / 24.0, abs=0.01)

    # dedup_savings_ratio: D=2, N=150+50=200 -> 1.0 - (2/200) = 0.99
    assert stats.dedup_savings_ratio == pytest.approx(0.99, abs=0.001)
    assert 0.0 <= stats.dedup_savings_ratio <= 1.0
