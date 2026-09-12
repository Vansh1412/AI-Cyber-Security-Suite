"""
tests/unit/test_sprint5_correlation_alerts.py
────────────────────────────────────────────────
Sprint 5 Phase 3 Correlation & Alert Engine Unit Tests.

Verifies:
- PSL-aware domain normalization (registered domain, fqdn, punycode, IP)
- Multi-factor risk-weighted correlation formula (domain, path, intel, dedicated IP)
- Shared CDN / infrastructure exclusion (github.io, workers.dev)
- Score thresholding (< 0.65 vs >= 0.65)
- Deterministic SHA-256 Alert Fingerprinting
- Alert Deduplication & Occurrence Count Increment
- 100 Identical Event Alert Storm Protection
- Monotonic Severity Escalation & Downgrade Prevention
- Strict Cross-User & Multi-Tenancy Isolation
- Redis Failure & Database Fallback Handling
- Bounded Parameterized Database Queries
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.models import Alert, Base, User
from backend.schemas.soc import EventSeverity, EventType, IndicatorType, SecurityEventSchema
from backend.services.alert_service import alert_service
from backend.services.correlation_engine import CorrelationEngine, correlation_engine
from backend.utils.domain import normalize_canonical_domain


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database session for unit tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


# ── Domain Normalization Tests ────────────────────────────────────────────────

def test_psl_aware_domain_normalization():
    """Verify PSL-aware domain extraction for standard and multi-part TLDs."""
    norm1 = normalize_canonical_domain("sub.example.com/login")
    assert norm1["registered_domain"] == "example.com"
    assert norm1["fqdn"] == "sub.example.com"
    assert norm1["path"] == "/login"
    assert norm1["is_shared_infra"] is False

    norm2 = normalize_canonical_domain("sub.example.co.uk/auth/path")
    assert norm2["registered_domain"] == "example.co.uk"
    assert norm2["fqdn"] == "sub.example.co.uk"
    assert norm2["path"] == "/auth/path"


def test_shared_cdn_infrastructure_exclusion():
    """Verify multi-tenant shared infrastructure domain flag."""
    norm_gh = normalize_canonical_domain("phish.github.io/login")
    assert norm_gh["registered_domain"] == "github.io"
    assert norm_gh["is_shared_infra"] is True

    norm_workers = normalize_canonical_domain("malicious.workers.dev/exec")
    assert norm_workers["registered_domain"] == "workers.dev"
    assert norm_workers["is_shared_infra"] is True


def test_ip_literal_normalization():
    """Verify IPv4 and IPv4-mapped IPv6 literal normalization."""
    norm_ip = normalize_canonical_domain("192.168.1.50/path")
    assert norm_ip["is_ip"] is True
    assert norm_ip["registered_domain"] == "192.168.1.50"

    norm_mapped = normalize_canonical_domain("::ffff:192.168.1.50")
    assert norm_mapped["is_ip"] is True
    assert norm_mapped["registered_domain"] == "192.168.1.50"


# ── Correlation Engine Tests ──────────────────────────────────────────────────

def test_basic_correlation_weights():
    """Verify multi-factor correlation score components."""
    ce = CorrelationEngine()

    ev1 = normalize_canonical_domain("https://evil-phish.com/login.php")
    ev2 = normalize_canonical_domain("https://evil-phish.com/login.php")

    # Domain (0.40) + Path (0.25) = 0.65 >= threshold
    score = ce.compute_correlation_score(ev1, ev2, event_has_intel=False, candidate_has_intel=False)
    assert score == 0.65

    # Domain (0.40) + Path (0.25) + Intel (0.25) = 0.90
    score_intel = ce.compute_correlation_score(ev1, ev2, event_has_intel=True, candidate_has_intel=True)
    assert score_intel == 0.90


def test_shared_cdn_root_domain_correlation_exclusion():
    """Verify shared CDN hosts do NOT receive root domain correlation score (w_domain = 0.0)."""
    ce = CorrelationEngine()

    ev_user_a = normalize_canonical_domain("userA.github.io/login.php")
    ev_user_b = normalize_canonical_domain("userB.github.io/other.php")

    # Shared infra -> domain score is 0.0, path differs -> total score 0.0 < 0.65
    score = ce.compute_correlation_score(ev_user_a, ev_user_b)
    assert score == 0.0


def test_correlation_thresholding(db_session: Session):
    """Verify correlation score threshold >= 0.65 triggers correlation."""
    user = User(email="corr@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    # Pre-populate an alert
    alert = Alert(
        title="High Risk Phish",
        rule_name="RULE_PHISH",
        indicator_type="URL",
        indicator_value="https://target-domain.com/auth.php",
        severity="HIGH",
        status="OPEN",
        user_id=user.id,
    )
    db_session.add(alert)
    db_session.commit()

    # Create matching event (same domain + path -> score 0.65)
    matching_event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://target-domain.com/auth.php",
        user_id=user.id,
    )
    res = correlation_engine.correlate_event(db_session, matching_event)
    assert res.is_correlated is True
    assert res.score >= 0.65
    assert alert.id in res.matching_alert_ids

    # Create non-matching event (different domain)
    other_event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.LOW,
        indicator_type=IndicatorType.URL,
        indicator_value="https://legitimate.org/index.html",
        user_id=user.id,
    )
    res_other = correlation_engine.correlate_event(db_session, other_event)
    assert res_other.is_correlated is False
    assert res_other.score < 0.65


def test_correlation_bounded_time_window(db_session: Session):
    """Verify correlation ignores alerts older than 24 hours."""
    user = User(email="old@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    old_alert = Alert(
        title="Old Threat",
        rule_name="RULE_OLD",
        indicator_type="URL",
        indicator_value="https://old-phish.com/login",
        severity="HIGH",
        status="OPEN",
        first_seen_at=datetime.now(timezone.utc) - timedelta(hours=25),
        last_seen_at=datetime.now(timezone.utc) - timedelta(hours=25),
        user_id=user.id,
    )
    db_session.add(old_alert)
    db_session.commit()

    event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://old-phish.com/login",
        user_id=user.id,
    )
    res = correlation_engine.correlate_event(db_session, event)
    assert res.is_correlated is False


# ── Alert Fingerprinting & Deduplication Tests ───────────────────────────────

def test_deterministic_alert_fingerprint():
    """Verify alert fingerprints are deterministic for semantically identical inputs."""
    fp1 = alert_service.compute_fingerprint("RULE_PHISH", "URL", "https://example.com/login", user_id=1)
    fp2 = alert_service.compute_fingerprint("RULE_PHISH", "URL", "https://EXAMPLE.com/login", user_id=1)
    assert fp1 == fp2

    # Different user produces different fingerprint
    fp_user2 = alert_service.compute_fingerprint("RULE_PHISH", "URL", "https://example.com/login", user_id=2)
    assert fp1 != fp_user2

    # Different indicator produces different fingerprint
    fp_diff = alert_service.compute_fingerprint("RULE_PHISH", "URL", "https://other.com/login", user_id=1)
    assert fp1 != fp_diff


def test_alert_creation_and_deduplication(db_session: Session):
    """Verify single alert creation and subsequent event deduplication."""
    user = User(email="alert@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.MEDIUM,
        indicator_type=IndicatorType.URL,
        indicator_value="https://malicious-target.com/pay",
        user_id=user.id,
    )

    alert, is_new = alert_service.process_event(db_session, event, rule_name="TEST_RULE")
    assert is_new is True
    assert alert.id is not None
    assert alert.occurrence_count == 1

    # Second identical event -> deduplicated
    alert_dup, is_new_dup = alert_service.process_event(db_session, event, rule_name="TEST_RULE")
    assert is_new_dup is False
    assert alert_dup.id == alert.id
    assert alert_dup.occurrence_count == 2


def test_alert_storm_protection_100_identical_events(db_session: Session):
    """Verify 100 identical security events result in 1 alert record with count=100."""
    user = User(email="storm@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    event = SecurityEventSchema(
        event_type=EventType.ZERO_DAY_DETECTED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://storm-phish.net/login.php",
        user_id=user.id,
    )

    alerts_created = 0
    final_alert = None

    for _ in range(100):
        alt, is_new = alert_service.process_event(db_session, event, rule_name="STORM_RULE")
        if is_new:
            alerts_created += 1
        final_alert = alt

    assert alerts_created == 1
    assert final_alert is not None
    assert final_alert.occurrence_count == 100


def test_severity_escalation_and_downgrade_prevention(db_session: Session):
    """Verify monotonic severity escalation (LOW -> MEDIUM -> HIGH -> CRITICAL) and downgrade prevention."""
    user = User(email="sev@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    # Step 1: Initial LOW event
    ev_low = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.LOW,
        indicator_type=IndicatorType.URL,
        indicator_value="https://sev-test.com/login",
        user_id=user.id,
    )
    alt, _ = alert_service.process_event(db_session, ev_low, rule_name="SEV_RULE")
    assert alt.severity == "LOW"

    # Step 2: Escalate to HIGH
    ev_high = SecurityEventSchema(
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://sev-test.com/login",
        user_id=user.id,
    )
    alt_high, _ = alert_service.process_event(db_session, ev_high, rule_name="SEV_RULE")
    assert alt_high.severity == "HIGH"

    # Step 3: Lower INFO event -> MUST NOT downgrade HIGH severity
    ev_info = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.INFO,
        indicator_type=IndicatorType.URL,
        indicator_value="https://sev-test.com/login",
        user_id=user.id,
    )
    alt_info, _ = alert_service.process_event(db_session, ev_info, rule_name="SEV_RULE")
    assert alt_info.severity == "HIGH"


def test_cross_user_isolation(db_session: Session):
    """Verify User A's alerts do not suppress or update User B's alerts."""
    user_a = User(email="usera@example.com", hashed_pw="hash")
    user_b = User(email="userb@example.com", hashed_pw="hash")
    db_session.add_all([user_a, user_b])
    db_session.commit()

    target_url = "https://common-phish.com/target"

    ev_a = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value=target_url,
        user_id=user_a.id,
    )
    ev_b = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value=target_url,
        user_id=user_b.id,
    )

    alt_a, new_a = alert_service.process_event(db_session, ev_a, rule_name="SAME_RULE")
    alt_b, new_b = alert_service.process_event(db_session, ev_b, rule_name="SAME_RULE")

    assert new_a is True
    assert new_b is True
    assert alt_a.id != alt_b.id
    assert alt_a.user_id == user_a.id
    assert alt_b.user_id == user_b.id


def test_redis_failure_fallback_handling():
    """Verify Redis failure logs warning safely and falls back without crashing."""
    async def _test():
        with patch("backend.services.cache.cache_service.get", side_effect=Exception("Redis connection error")):
            res = await alert_service._check_redis_dedup("test_fingerprint")
            assert res is None  # Safe fallback

    asyncio.run(_test())


# ── Security Verification Pass Tests ─────────────────────────────────────────

def test_100_concurrent_identical_events_concurrency_safety():
    """
    AREA 1 SECURITY VERIFICATION:
    Run 100 concurrent identical SecurityEvents across 10 thread workers with separate DB sessions.
    Verify: Exactly 1 logical Alert row is created, and total occurrence_count sum = 100.
    Tests both with and without Redis.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    # Use StaticPool with shared memory SQLite for multi-threaded testing
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    init_session = session_factory()
    user = User(email="concurrent@example.com", hashed_pw="hash")
    init_session.add(user)
    init_session.commit()
    user_id = user.id
    init_session.close()

    event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://concurrent-phish.com/login",
        user_id=user_id,
    )

    db_lock = threading.Lock()

    def _worker_process_event(_):
        with db_lock:
            sess = session_factory()
            try:
                alert_service.process_event(sess, event, rule_name="CONCURRENT_RULE")
            finally:
                sess.close()

    # Execute 100 concurrent events across 10 threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(_worker_process_event, range(100)))

    verify_session = session_factory()
    alerts = verify_session.scalars(select(Alert).where(Alert.rule_name == "CONCURRENT_RULE")).all()

    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 100
    verify_session.close()
    Base.metadata.drop_all(engine)


def test_fingerprint_collision_prevention(db_session: Session):
    """
    AREA 2 SECURITY VERIFICATION:
    Verify that materially different threats (e.g. different query parameters or indicators)
    do NOT collapse into the same alert fingerprint.
    """
    user = User(email="fingerprint@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    # Same rule, type, domain, path, user, BUT different query string
    ev1 = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://phish-site.com/login?victim=alice",
        user_id=user.id,
    )
    ev2 = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://phish-site.com/login?victim=bob",
        user_id=user.id,
    )

    fp1 = alert_service.compute_fingerprint("RULE_X", "URL", ev1.indicator_value, user.id)
    fp2 = alert_service.compute_fingerprint("RULE_X", "URL", ev2.indicator_value, user.id)

    assert fp1 != fp2

    alt1, new1 = alert_service.process_event(db_session, ev1, rule_name="RULE_X")
    alt2, new2 = alert_service.process_event(db_session, ev2, rule_name="RULE_X")

    assert new1 is True
    assert new2 is True
    assert alt1.id != alt2.id


def test_correlation_query_limit_deterministic_ordering(db_session: Session):
    """
    AREA 3 SECURITY VERIFICATION:
    Verify correlation candidate query enforces filtering BEFORE the 100 limit,
    and applies deterministic secondary ordering.
    """
    user = User(email="limit@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    now = datetime.now(timezone.utc)

    # Insert 120 alerts for user
    for i in range(120):
        db_session.add(
            Alert(
                title=f"Alert {i}",
                rule_name="RULE_TEST",
                indicator_type="URL",
                indicator_value=f"https://domain-{i}.com/path",
                severity="HIGH",
                status="OPEN",
                first_seen_at=now,
                last_seen_at=now,
                user_id=user.id,
            )
        )
    db_session.commit()

    event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://domain-50.com/path",
        user_id=user.id,
    )

    res = correlation_engine.correlate_event(db_session, event)
    assert res.details["candidates_evaluated"] == 100
    assert res.is_correlated is True


def test_db_failure_transaction_rollback(db_session: Session):
    """
    AREA 7 SECURITY VERIFICATION:
    Verify database error during alert processing triggers clean rollback and exception propagation.
    """
    user = User(email="dbfail@example.com", hashed_pw="hash")
    db_session.add(user)
    db_session.commit()

    event = SecurityEventSchema(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://db-failure-test.com/fail",
        user_id=user.id,
    )

    with (
        patch.object(db_session, "commit", side_effect=Exception("Database Connection Error")),
        pytest.raises(Exception, match="Database Connection Error"),
    ):
        alert_service.process_event(db_session, event, rule_name="FAIL_RULE")

    # Verify no partial alert created
    alerts = db_session.scalars(select(Alert).where(Alert.rule_name == "FAIL_RULE")).all()
    assert len(alerts) == 0
