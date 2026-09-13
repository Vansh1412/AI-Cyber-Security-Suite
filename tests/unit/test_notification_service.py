"""
tests/unit/test_notification_service.py
───────────────────────────────────────
Unit tests for Sprint 5 Phase 5D:
- AES-256-GCM Encryption / Decryption with versioned v1$ envelope
- Key length validation and tampering detection
- Cryptographically secure secret generation (32 bytes = 64 hex chars)
- Canonical HMAC-SHA256 signature byte-parity and 300s replay window
- SSRF pre-flight validation (RFC 1918, loopback, link-local, cloud metadata)
- Alert-to-Notification matrix, severity escalation, and outbox idempotency
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security_network import SSRFSecurityError
from backend.database.models import Alert, Base, Notification, NotificationPreference, User
from backend.schemas.notification import (
    NotificationPreferenceUpdate,
)
from backend.services.notification_service import (
    DecryptionError,
    NotificationOutbox,
    compute_hmac_signature,
    decrypt_webhook_secret,
    encrypt_webhook_secret,
    generate_webhook_secret,
    get_secret_preview,
    notification_service,
    verify_hmac_signature,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def sync_db_session():
    """In-memory SQLite database session for unit tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        # Create test user
        user = User(email="analyst@soc.corp", hashed_pw="dummy_pw", role="user")
        session.add(user)
        session.commit()
        session.refresh(user)
        yield session, user
    Base.metadata.drop_all(engine)


# ── 1. AES-256-GCM Encryption & Key Management Tests ─────────────────────────

def test_aes_gcm_encrypt_decrypt_roundtrip():
    """Verify that plaintext webhook secret encrypts and decrypts losslessly."""
    raw_secret = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
    encrypted = encrypt_webhook_secret(raw_secret)

    assert encrypted.startswith("v1$")
    assert raw_secret not in encrypted

    decrypted = decrypt_webhook_secret(encrypted)
    assert decrypted == raw_secret


def test_aes_gcm_tampered_ciphertext_fails():
    """Verify that tampering with ciphertext tag or payload raises DecryptionError."""
    raw_secret = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
    encrypted = encrypt_webhook_secret(raw_secret)

    parts = encrypted.split("$")
    # Mutate the ciphertext payload
    tampered_ct = parts[3][:-4] + "AAAA"
    tampered_envelope = f"{parts[0]}${parts[1]}${parts[2]}${tampered_ct}"

    with pytest.raises(DecryptionError, match="authentication tag mismatch|Decryption failed"):
        decrypt_webhook_secret(tampered_envelope)


def test_aes_gcm_unsupported_version_fails():
    """Verify that non-v1$ envelope format fails closed."""
    with pytest.raises(DecryptionError, match="Unsupported or missing"):
        decrypt_webhook_secret("v2$salt$nonce$ct")


def test_aes_gcm_short_root_key_fails():
    """Verify that master encryption key < 32 bytes fails fast at startup."""
    with patch.dict(os.environ, {"WEBHOOK_ENCRYPTION_KEY": "short-key-16bytes"}), patch.object(settings, "SECRET_KEY", "short-key-16bytes"), pytest.raises(ValueError, match="at least 32 bytes"):
        encrypt_webhook_secret("valid_secret_with_more_than_32_characters_here")


# ── 2. Webhook Secret Entropy & Representation Tests ─────────────────────────

def test_generate_webhook_secret_entropy():
    """Verify generated secret is 64 hex characters (32 bytes = 256 bits)."""
    secret = generate_webhook_secret()
    assert len(secret) == 64
    assert all(c in "0123456789abcdef" for c in secret)


def test_get_secret_preview_masking():
    """Verify plaintext secret is masked with only last 4 characters visible."""
    secret = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
    preview = get_secret_preview(secret)
    assert preview == "wh_sec_...abcd"
    assert secret[:32] not in preview


def test_pydantic_rejects_short_or_trivial_secret():
    """Verify API schema rejects user secrets shorter than 32 chars or low entropy."""
    # Too short (< 32)
    with pytest.raises(ValidationError, match="at least 32 characters"):
        NotificationPreferenceUpdate(webhook_secret="too-short")

    # Trivial repeated characters
    with pytest.raises(ValidationError, match="insufficient entropy"):
        NotificationPreferenceUpdate(webhook_secret="a" * 32)

    # Valid secret
    valid = NotificationPreferenceUpdate(
        webhook_secret="this_is_a_sufficiently_long_and_complex_secret_1234"
    )
    assert valid.webhook_secret == "this_is_a_sufficiently_long_and_complex_secret_1234"


# ── 3. Canonical HMAC-SHA256 Signature Tests ──────────────────────────────────

def test_canonical_hmac_sha256_byte_parity():
    """Verify exact byte parity with canonical timestamp + '.' + raw_body."""
    secret = "my_super_secret_webhook_signing_key_32bytes"
    timestamp = 1741891200
    raw_body = b'{"event":"ALERT_TRIGGERED","alert_uuid":"1234"}'

    # Architecture formula: canonical = f"{timestamp}." + raw_body
    canonical = f"{timestamp}.".encode() + raw_body
    expected_hex = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    actual_hex = compute_hmac_signature(secret, timestamp, raw_body)
    assert actual_hex == expected_hex


def test_hmac_signature_verification_and_replay_window():
    """Verify signature verification succeeds within 300s and fails on stale replay."""
    secret = "my_super_secret_webhook_signing_key_32bytes"
    now_ts = int(time.time())
    raw_body = b'{"event":"ALERT_TRIGGERED"}'

    sig = compute_hmac_signature(secret, now_ts, raw_body)

    # Valid within tolerance
    assert verify_hmac_signature(secret, now_ts, raw_body, sig, tolerance_seconds=300.0) is True

    # Invalid signature bytes
    assert verify_hmac_signature(secret, now_ts, raw_body, "bad_signature", tolerance_seconds=300.0) is False

    # Stale replay: 301 seconds old
    stale_ts = now_ts - 301
    stale_sig = compute_hmac_signature(secret, stale_ts, raw_body)
    assert verify_hmac_signature(secret, stale_ts, raw_body, stale_sig, tolerance_seconds=300.0) is False

    # Future replay: 301 seconds in future
    future_ts = now_ts + 301
    future_sig = compute_hmac_signature(secret, future_ts, raw_body)
    assert verify_hmac_signature(secret, future_ts, raw_body, future_sig, tolerance_seconds=300.0) is False


# ── 4. SSRF & Network Security Pre-Flight Tests ───────────────────────────────

@pytest.mark.anyio
async def test_ssrf_blocks_private_and_metadata_ips():
    """Verify that all blocked CIDRs fail pre-flight validation."""
    from backend.core.security_network import is_blocked_ip, validate_target_url

    # Syntactic & blocked IPs
    blocked_ips = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
    ]
    for ip_str in blocked_ips:
        assert is_blocked_ip(ip_str) is True, f"IP {ip_str} should be classified as blocked"

    # Direct URL validation
    with pytest.raises(SSRFSecurityError, match="blocked address"):
        validate_target_url("http://127.0.0.1:8080/hook")

    with pytest.raises(SSRFSecurityError, match="blocked address"):
        validate_target_url("http://169.254.169.254/latest/meta-data")

    # Prohibited scheme
    with pytest.raises(SSRFSecurityError, match="Unsupported URL scheme"):
        validate_target_url("ftp://webhook.partner.com/hook")

    # Embedded credentials
    with pytest.raises(SSRFSecurityError, match="userinfo"):
        validate_target_url("http://admin:secret@webhook.partner.com/hook")


# ── 5. Alert-to-Notification Matrix & Outbox Enqueueing Tests ─────────────────

def test_alert_creation_enqueues_in_app_and_outbox(sync_db_session):
    """Verify that creating an OPEN HIGH alert inserts In-App notification and Outbox job atomically."""
    session, user = sync_db_session

    # Configure preference
    pref = NotificationPreference(
        user_id=user.id,
        in_app_enabled=True,
        webhook_enabled=True,
        webhook_url="https://siem.corp/webhook",
        webhook_secret=encrypt_webhook_secret(generate_webhook_secret()),
        min_severity="HIGH",
    )
    session.add(pref)
    session.commit()

    # Create qualifying HIGH alert
    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        user_id=user.id,
        title="High Severity Phishing Campaign",
        description="Automated ML classified phishing attempt.",
        severity="HIGH",
        status="OPEN",
        rule_name="PHISHING_DETECTION",
        indicator_type="DOMAIN",
        indicator_value="malicious-bank.com",
        occurrence_count=1,
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    session.add(alert)

    # Atomic enqueue inside the same transaction
    notification_service.create_in_app_and_outbox_for_alert(session, alert, is_escalation=False)
    session.commit()

    # Assert In-App notification was created
    notif = session.query(Notification).filter(Notification.user_id == user.id).first()
    assert notif is not None
    assert notif.severity == "HIGH"
    assert "High Severity Phishing Campaign" in notif.title
    assert notif.is_read is False

    # Assert Outbox job was created
    outbox = session.query(NotificationOutbox).filter(NotificationOutbox.user_id == user.id).first()
    assert outbox is not None
    assert outbox.status == "PENDING"
    assert outbox.destination_url == "https://siem.corp/webhook"
    assert outbox.attempt_count == 0
    assert outbox.payload_json["event"] == "ALERT_TRIGGERED"
    assert outbox.payload_json["severity"] == "HIGH"


def test_alert_below_threshold_skips_outbox(sync_db_session):
    """Verify that an alert with severity < min_severity creates In-App but skips Outbox."""
    session, user = sync_db_session

    pref = NotificationPreference(
        user_id=user.id,
        in_app_enabled=True,
        webhook_enabled=True,
        webhook_url="https://siem.corp/webhook",
        webhook_secret=encrypt_webhook_secret(generate_webhook_secret()),
        min_severity="HIGH",
    )
    session.add(pref)
    session.commit()

    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        user_id=user.id,
        title="Low Severity Scan Notice",
        severity="LOW",
        status="OPEN",
        rule_name="LOW_PRIORITY",
        indicator_type="IP",
        indicator_value="1.2.3.4",
        occurrence_count=1,
    )
    session.add(alert)
    notification_service.create_in_app_and_outbox_for_alert(session, alert, is_escalation=False)
    session.commit()

    # In-App created
    assert session.query(Notification).filter(Notification.user_id == user.id).count() == 1
    # Outbox skipped
    assert session.query(NotificationOutbox).filter(NotificationOutbox.user_id == user.id).count() == 0


def test_severity_escalation_enqueues_escalated_outbox(sync_db_session):
    """Verify that severity escalation creates outbox job with distinct idempotency key."""
    session, user = sync_db_session

    pref = NotificationPreference(
        user_id=user.id,
        in_app_enabled=True,
        webhook_enabled=True,
        webhook_url="https://siem.corp/webhook",
        webhook_secret=encrypt_webhook_secret(generate_webhook_secret()),
        min_severity="HIGH",
    )
    session.add(pref)
    session.commit()

    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        user_id=user.id,
        title="Escalated Threat",
        severity="CRITICAL",
        status="OPEN",
        rule_name="THREAT_DETECTION",
        indicator_type="DOMAIN",
        indicator_value="threat.com",
        occurrence_count=2,
    )
    session.add(alert)

    notification_service.create_in_app_and_outbox_for_alert(
        session, alert, is_escalation=True, old_severity="MEDIUM"
    )
    session.commit()

    outbox = session.query(NotificationOutbox).filter(NotificationOutbox.user_id == user.id).first()
    assert outbox is not None
    assert "ESCALATED" in outbox.idempotency_key
    assert outbox.payload_json["event"] == "ALERT_ESCALATED"


def test_outbox_idempotency_prevents_duplicate_jobs(sync_db_session):
    """Verify calling enqueue twice on the same alert state does not duplicate outbox job."""
    session, user = sync_db_session

    pref = NotificationPreference(
        user_id=user.id,
        webhook_enabled=True,
        webhook_url="https://siem.corp/webhook",
        webhook_secret=encrypt_webhook_secret(generate_webhook_secret()),
        min_severity="HIGH",
    )
    session.add(pref)
    session.commit()

    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        user_id=user.id,
        title="Repeat Threat",
        severity="HIGH",
        status="OPEN",
        rule_name="THREAT_DETECTION",
        indicator_type="DOMAIN",
        indicator_value="repeat.com",
        occurrence_count=1,
    )
    session.add(alert)

    # First call
    notification_service.create_in_app_and_outbox_for_alert(session, alert)
    session.commit()
    assert session.query(NotificationOutbox).count() == 1

    # Second call with same state
    notification_service.create_in_app_and_outbox_for_alert(session, alert)
    session.commit()
    assert session.query(NotificationOutbox).count() == 1
