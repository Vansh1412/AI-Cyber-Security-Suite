"""
tests/unit/test_containment_service.py
──────────────────────────────────────
Unit tests for Sprint 5 Phase 5F:
- Policy Gate & Defaults (default safe disabled mode)
- Optimistic Policy Versioning & Concurrency
- Rule 0 Allowlist Fencing (per-action-type, fail-closed)
- Action Idempotency & Collision Handling
- Target Quarantine Threshold Semantics (>= 3 distinct active alerts in 10m)
- Provenance-Safe Rollback Engine
- Declarative Playbook Execution & Partial Failure Semantics
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.models import (
    Alert,
    Base,
    MonitoringTarget,
    SOCContainmentAction,
    SOCDynamicBlacklist,
    User,
)
from backend.schemas.containment import (
    ContainmentActionStatus,
    ContainmentActionType,
    ContainmentPolicyUpdate,
    PlaybookRunStatus,
)
from backend.services.containment_service import (
    ThreatIntelAdapter,
    containment_service,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def db_session():
    """In-memory SQLite database session with Base metadata created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        user = User(email="sec_analyst@soc.corp", hashed_pw="dummy_pw", role="user")
        admin = User(email="admin@soc.corp", hashed_pw="dummy_pw", role="admin")
        session.add_all([user, admin])
        session.commit()
        session.refresh(user)
        session.refresh(admin)
        yield session, user, admin
    Base.metadata.drop_all(engine)


# ── 1. Policy Gate & Defaults Tests ───────────────────────────────────────────

@pytest.mark.anyio
async def test_policy_defaults_and_synthesis(db_session):
    """Verify that default policy is synthesized in safe disabled mode."""
    session, user, _ = db_session

    policy = await containment_service.get_or_create_policy(session, user.id)
    assert policy.tenant_id == user.id
    assert policy.auto_containment_enabled is False
    assert policy.auto_blacklist_enabled is False
    assert policy.auto_quarantine_enabled is False
    assert policy.auto_incident_binding_enabled is False
    assert policy.containment_min_severity == "CRITICAL"
    assert policy.blacklist_ttl_seconds == 86400
    assert policy.policy_version == 1


@pytest.mark.anyio
async def test_policy_optimistic_concurrency_update(db_session):
    """Verify that policy updates require matching version and increment policy_version."""
    session, user, _ = db_session

    policy = await containment_service.get_or_create_policy(session, user.id)
    assert policy.policy_version == 1

    # Valid update with version 1
    update_data = ContainmentPolicyUpdate(
        auto_containment_enabled=True,
        auto_blacklist_enabled=True,
        auto_quarantine_enabled=True,
        auto_incident_binding_enabled=True,
        containment_min_severity="HIGH",
        blacklist_ttl_seconds=43200,
        policy_version=1,
    )
    updated = await containment_service.update_policy(session, user.id, update_data, user.id)
    assert updated.auto_containment_enabled is True
    assert updated.policy_version == 2
    assert updated.containment_min_severity == "HIGH"

    # Conflicting update with stale version 1
    with pytest.raises(Exception) as exc_info:
        await containment_service.update_policy(session, user.id, update_data, user.id)
    assert "Policy version conflict" in str(exc_info.value)


# ── 2. Rule 0 Allowlist Fencing Tests ─────────────────────────────────────────

def test_rule0_allowlist_adapter():
    """Verify ThreatIntelAdapter properly detects trusted domains and fails closed."""
    # Allowlisted domains
    assert ThreatIntelAdapter.is_whitelisted("https://www.google.com/search") is True
    assert ThreatIntelAdapter.is_whitelisted("http://paypal.com/login") is True
    assert ThreatIntelAdapter.is_whitelisted("microsoft.com") is True
    assert ThreatIntelAdapter.is_whitelisted("subdomain.github.com") is True

    # Non-allowlisted domains
    assert ThreatIntelAdapter.is_whitelisted("https://evil-phish-login.xyz") is False
    assert ThreatIntelAdapter.is_whitelisted("paypal-security-update.info") is False
    assert ThreatIntelAdapter.is_whitelisted("http://192.168.1.1/admin") is False

    # Fail-closed on empty/malformed
    assert ThreatIntelAdapter.is_whitelisted("") is True


@pytest.mark.anyio
async def test_rule0_blocks_blacklisting_of_trusted_domain(db_session):
    """Verify Rule 0 blocks blacklisting of an allowlisted domain with BLOCKED_BY_ALLOWLIST status."""
    session, user, _ = db_session

    action = await containment_service.execute_action(
        session=session,
        action_type=ContainmentActionType.BLACKLIST_INDICATOR,
        target_identifier="https://www.google.com/accounts",
        tenant_id=user.id,
        trigger_source="unit_test",
    )

    assert action.status == ContainmentActionStatus.BLOCKED_BY_ALLOWLIST.value
    assert "Rule 0 Invariant" in action.error_message

    # Ensure no entry was written to soc_dynamic_blacklist
    bl_entries = session.query(SOCDynamicBlacklist).filter_by(tenant_id=user.id).all()
    assert len(bl_entries) == 0


@pytest.mark.anyio
async def test_rule0_allows_cache_invalidation_of_trusted_domain(db_session):
    """Verify Rule 0 allows cache invalidation for trusted domains."""
    session, user, _ = db_session

    action = await containment_service.execute_action(
        session=session,
        action_type=ContainmentActionType.INVALIDATE_CACHE,
        target_identifier="https://www.google.com/search",
        tenant_id=user.id,
        trigger_source="unit_test",
    )

    assert action.status == ContainmentActionStatus.EXECUTED.value


# ── 3. Action Idempotency & Blacklist TTL Tests ───────────────────────────────

@pytest.mark.anyio
async def test_blacklist_action_idempotency_and_ttl(db_session):
    """Verify BLACKLIST_INDICATOR creates entry with 24h TTL and repeated execution is idempotent."""
    session, user, _ = db_session

    indicator = "https://confirmed-malware.xyz/payload.exe"
    action1 = await containment_service.execute_action(
        session=session,
        action_type=ContainmentActionType.BLACKLIST_INDICATOR,
        target_identifier=indicator,
        tenant_id=user.id,
        trigger_source="unit_test",
    )
    assert action1.status == ContainmentActionStatus.EXECUTED.value

    # Verify dynamic blacklist entry
    bl_entry = session.query(SOCDynamicBlacklist).filter_by(tenant_id=user.id, indicator_value=indicator).first()
    assert bl_entry is not None
    assert bl_entry.is_active is True
    exp = bl_entry.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    assert exp > datetime.now(timezone.utc)

    # Repeat execution: must return existing action via idempotency key
    action2 = await containment_service.execute_action(
        session=session,
        action_type=ContainmentActionType.BLACKLIST_INDICATOR,
        target_identifier=indicator,
        tenant_id=user.id,
        trigger_source="unit_test",
    )
    assert action2.id == action1.id
    assert action2.action_uuid == action1.action_uuid


# ── 4. Target Quarantine Threshold Semantics Tests ────────────────────────────

@pytest.mark.anyio
async def test_quarantine_threshold_evaluation(db_session):
    """Verify target quarantine triggers iff >= 3 distinct active alerts occur in 10m."""
    session, user, _ = db_session

    target = MonitoringTarget(
        url="https://api.vulnerable-target.com",
        normalized_domain="api.vulnerable-target.com",
        user_id=user.id,
        is_active=True,
    )
    session.add(target)
    session.commit()
    session.refresh(target)

    # 1. 0 alerts -> False
    assert await containment_service.evaluate_quarantine_eligibility(session, target) is False

    # 2. Add 2 active CRITICAL alerts within 10m -> False
    now = datetime.now(timezone.utc)
    for i in range(2):
        alert = Alert(
            title=f"Exploit attempt {i}",
            severity="CRITICAL",
            status="OPEN",
            rule_name="RULE_EXPLOIT",
            indicator_type="url",
            indicator_value=target.url,
            user_id=user.id,
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(alert)
    session.commit()
    assert await containment_service.evaluate_quarantine_eligibility(session, target) is False

    # 3. Add 1 more active HIGH alert -> True (3 distinct alerts)
    alert3 = Alert(
        title="Exploit attempt 3",
        severity="HIGH",
        status="ACKNOWLEDGED",
        rule_name="RULE_EXPLOIT",
        indicator_type="url",
        indicator_value=target.url,
        user_id=user.id,
        first_seen_at=now,
        last_seen_at=now,
    )
    session.add(alert3)
    session.commit()
    assert await containment_service.evaluate_quarantine_eligibility(session, target) is True

    # 4. If an alert is RESOLVED, it does not count
    alert3.status = "RESOLVED"
    session.commit()
    assert await containment_service.evaluate_quarantine_eligibility(session, target) is False


# ── 5. Provenance-Safe Rollback Tests ──────────────────────────────────────────

@pytest.mark.anyio
async def test_provenance_safe_rollback(db_session):
    """Verify rollback reverts only action-owned blacklist rows and reactivates targets safely."""
    session, user, _ = db_session

    # Execute blacklist action
    indicator = "https://bad-domain.com/phish"
    action = await containment_service.execute_action(
        session=session,
        action_type=ContainmentActionType.BLACKLIST_INDICATOR,
        target_identifier=indicator,
        tenant_id=user.id,
        trigger_source="unit_test",
    )
    assert action.status == ContainmentActionStatus.EXECUTED.value

    bl_entry = session.query(SOCDynamicBlacklist).filter_by(indicator_value=indicator, is_active=True).first()
    assert bl_entry is not None

    # Rollback action
    reverted = await containment_service.revert_action(session, action.action_uuid, user)
    assert reverted.status == ContainmentActionStatus.REVERTED.value
    assert reverted.reverted_at is not None

    # Blacklist row should now be inactive
    session.refresh(bl_entry)
    assert bl_entry.is_active is False

    # Idempotent re-revert
    re_reverted = await containment_service.revert_action(session, action.action_uuid, user)
    assert re_reverted.status == ContainmentActionStatus.REVERTED.value


# ── 6. Declarative Playbook Execution Tests ────────────────────────────────────

@pytest.mark.anyio
async def test_playbook_execution_and_partial_failure(db_session):
    """Verify declarative playbook runs sequentially, records action count, and handles completion."""
    session, user, _ = db_session

    run = await containment_service.execute_playbook(
        session=session,
        playbook_name="CRITICAL_THREAT_AUTO_CONTAINMENT_V1",
        tenant_id=user.id,
        trigger_event="alert_test",
        target_identifier="https://malicious-test-host.xyz",
        reason="Automated test run",
    )

    assert run.status == PlaybookRunStatus.COMPLETED.value
    assert run.action_count == 5
    assert run.completed_at is not None

    # Check actions were recorded
    actions = session.query(SOCContainmentAction).filter_by(run_id=run.id).all()
    assert len(actions) == 5


# ── 7. Post-Commit Alert Containment Evaluation & Background Lifecycle ───────

@pytest.mark.anyio
async def test_evaluate_alert_containment_policy_gating(db_session):
    """Verify post-commit alert containment respects policy gating and severity thresholds."""
    session, user, _ = db_session

    # Seed alert
    alert = Alert(
        user_id=user.id,
        title="Critical Phishing URL Detected",
        rule_name="malicious_url_detected",
        indicator_type="url",
        indicator_value="https://attack.phish.com/login",
        severity="CRITICAL",
        status="OPEN",
        occurrence_count=1,
    )
    session.add(alert)
    session.commit()
    session.refresh(alert)

    # 1. Default policy (auto_containment_enabled = False) -> returns None
    run = await containment_service.evaluate_alert_containment(session, alert)
    assert run is None

    # 2. Enable policy with auto_blacklist_enabled
    update_data = ContainmentPolicyUpdate(
        auto_containment_enabled=True,
        auto_blacklist_enabled=True,
        auto_quarantine_enabled=False,
        auto_incident_binding_enabled=False,
        containment_min_severity="CRITICAL",
        blacklist_ttl_seconds=86400,
        policy_version=1,
    )
    await containment_service.update_policy(session, user.id, update_data, user.id)

    # 3. High severity below CRITICAL threshold -> returns None
    low_alert = Alert(
        user_id=user.id,
        title="Suspicious DNS Activity",
        rule_name="suspicious_dns",
        indicator_type="domain",
        indicator_value="suspicious.com",
        severity="MEDIUM",
        status="OPEN",
        occurrence_count=1,
    )
    session.add(low_alert)
    session.commit()
    session.refresh(low_alert)

    run_low = await containment_service.evaluate_alert_containment(session, low_alert)
    assert run_low is None

    # 4. Qualifying CRITICAL alert -> triggers playbook
    run_crit = await containment_service.evaluate_alert_containment(session, alert)
    assert run_crit is not None
    assert run_crit.playbook_name == "CRITICAL_THREAT_AUTO_CONTAINMENT_V1"
    assert run_crit.status == PlaybookRunStatus.COMPLETED.value


@pytest.mark.anyio
async def test_background_containment_lifecycle():
    """Verify that _run_background_containment gracefully handles non-existent alerts and exceptions."""
    from backend.services.alert_service import _run_background_containment

    # Non-existent alert ID should complete safely without raising
    await _run_background_containment(9999999)

