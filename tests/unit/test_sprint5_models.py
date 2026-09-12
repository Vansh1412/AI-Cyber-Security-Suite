"""
tests/unit/test_sprint5_models.py
───────────────────────────────────
Sprint 5 Phase 1 Model & Database Unit Tests.

Verifies:
- All 6 new ORM models (Alert, Incident, MonitoringTarget, NotificationPreference, Notification, AuditEvent)
- Strict 1-to-many Alert <-> Incident relationship
- Foreign key definitions and cascade behavior
- Index creation and table structure
- Default UUID and timestamp assignments
"""

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import (
    Alert,
    AuditEvent,
    Base,
    Incident,
    MonitoringTarget,
    Notification,
    NotificationPreference,
    User,
)


@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for model tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_local = sessionmaker(bind=engine)
    session = session_local()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


def test_user_creation(in_memory_db: Session):
    """Verify User model baseline."""
    user = User(email="analyst@example.com", hashed_pw="secret_hash", role="analyst")
    in_memory_db.add(user)
    in_memory_db.commit()

    assert user.id is not None
    assert user.email == "analyst@example.com"
    assert user.role == "analyst"


def test_alert_incident_one_to_many_relationship(in_memory_db: Session):
    """
    CRITICAL SECURITY CHECK:
    Verify strict 1-to-many relationship:
    - 1 Incident has N Alerts
    - ONLY alerts.incident_id references incidents.id
    - No incident_alerts join table
    - No circular foreign keys
    """
    user = User(email="soc@example.com", hashed_pw="hash")
    in_memory_db.add(user)
    in_memory_db.commit()

    incident = Incident(
        title="Phishing Campaign Alpha",
        description="Multiple high-confidence phishing alerts detected",
        severity="CRITICAL",
        status="OPEN",
        creator_user=user,
    )
    in_memory_db.add(incident)
    in_memory_db.commit()

    alert1 = Alert(
        title="Malicious URL Detected",
        rule_name="HIGH_CONFIDENCE_MALICIOUS",
        indicator_type="URL",
        indicator_value="http://evil-phish.com/login",
        severity="HIGH",
        incident=incident,
        user=user,
    )
    alert2 = Alert(
        title="Zero-Day Phish Detected",
        rule_name="ZERO_DAY_INGESTION",
        indicator_type="DOMAIN",
        indicator_value="evil-phish.com",
        severity="CRITICAL",
        incident=incident,
        user=user,
    )

    in_memory_db.add_all([alert1, alert2])
    in_memory_db.commit()

    # Re-query incident
    in_memory_db.refresh(incident)

    assert len(incident.alerts) == 2
    assert alert1.incident_id == incident.id
    assert alert2.incident_id == incident.id
    assert alert1.incident.title == "Phishing Campaign Alpha"

    # Verify foreign keys using SQLAlchemy inspector
    inspector = inspect(in_memory_db.bind)
    alert_fks = inspector.get_foreign_keys("alerts")
    incident_fks = inspector.get_foreign_keys("incidents")

    # alerts table should have foreign keys to users and incidents
    alert_fk_targets = {fk["referred_table"] for fk in alert_fks}
    assert "incidents" in alert_fk_targets
    assert "users" in alert_fk_targets

    # incidents table should ONLY have foreign keys to users (NO foreign key back to alerts!)
    incident_fk_targets = {fk["referred_table"] for fk in incident_fks}
    assert "alerts" not in incident_fk_targets
    assert incident_fk_targets == {"users"}


def test_monitoring_target_model(in_memory_db: Session):
    """Verify MonitoringTarget model fields and relationship."""
    user = User(email="mon@example.com", hashed_pw="hash")
    in_memory_db.add(user)
    in_memory_db.commit()

    target = MonitoringTarget(
        url="https://secure-login.org",
        normalized_domain="secure-login.org",
        check_interval_minutes=30,
        user=user,
    )
    in_memory_db.add(target)
    in_memory_db.commit()

    assert target.id is not None
    assert target.target_uuid is not None
    assert len(target.target_uuid) == 36
    assert target.is_active is True
    assert target.user_id == user.id
    assert len(user.monitoring_targets) == 1


def test_notification_preference_one_to_one(in_memory_db: Session):
    """Verify NotificationPreference model 1-to-1 relationship with User."""
    user = User(email="pref@example.com", hashed_pw="hash")
    in_memory_db.add(user)
    in_memory_db.commit()

    pref = NotificationPreference(
        user=user,
        in_app_enabled=True,
        email_enabled=True,
        webhook_enabled=True,
        webhook_url="https://example.com/webhook",
        webhook_secret="whsec_enc_token_123",
        min_severity="CRITICAL",
    )
    in_memory_db.add(pref)
    in_memory_db.commit()

    assert pref.id is not None
    assert pref.user_id == user.id
    assert user.notification_preferences.webhook_url == "https://example.com/webhook"


def test_notification_and_audit_event_models(in_memory_db: Session):
    """Verify Notification and AuditEvent models."""
    user = User(email="audit@example.com", hashed_pw="hash")
    in_memory_db.add(user)
    in_memory_db.commit()

    notif = Notification(
        user=user,
        title="High Severity Alert",
        message="A new high severity threat alert was generated.",
        severity="HIGH",
    )
    audit = AuditEvent(
        action="ALERT_ACKNOWLEDGED",
        actor_user=user,
        target_resource="Alert",
        resource_id="101",
        details={"previous_status": "OPEN", "new_status": "ACKNOWLEDGED"},
    )
    in_memory_db.add_all([notif, audit])
    in_memory_db.commit()

    assert notif.id is not None
    assert notif.is_read is False
    assert audit.id is not None
    assert audit.action == "ALERT_ACKNOWLEDGED"
    assert audit.details["new_status"] == "ACKNOWLEDGED"


def test_scan_result_index_presence(in_memory_db: Session):
    """Verify scan_results user_id + created_at index presence."""
    inspector = inspect(in_memory_db.bind)
    indexes = inspector.get_indexes("scan_results")
    index_names = {idx["name"] for idx in indexes}
    assert "idx_scan_results_user_created" in index_names
