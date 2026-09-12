"""
tests/unit/test_sprint5_events.py
──────────────────────────────────
Sprint 5 Phase 2 Event Engine & Schema Unit Tests.

Verifies:
- SecurityEvent schema validation
- Bounded payload size checks (max 10 KB)
- Event type, severity, indicator type enums
- UUIDv4 format validation
- User ownership vs System event logic
- Serialization and deserialization determinism
- Error handling for invalid/oversized/malformed fields
"""

import uuid
from datetime import datetime, timezone

import pytest

from backend.schemas.soc import (
    EventSeverity,
    EventType,
    IndicatorType,
    SecurityEventSchema,
)
from backend.services.event_engine import EventEngine, EventEngineError, event_engine


def test_valid_security_event_creation():
    """Verify clean creation of a valid SecurityEvent via EventEngine."""
    event = event_engine.create_event(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.HIGH,
        indicator_type=IndicatorType.URL,
        indicator_value="https://malicious-phish.net/login.php",
        user_id=42,
        payload={"prediction": "phishing", "confidence": 0.98},
    )

    assert isinstance(event, SecurityEventSchema)
    assert event.event_type == EventType.SCAN_COMPLETED
    assert event.severity == EventSeverity.HIGH
    assert event.indicator_type == IndicatorType.URL
    assert event.indicator_value == "https://malicious-phish.net/login.php"
    assert event.user_id == 42
    assert event.is_system_event is False
    assert uuid.UUID(event.event_uuid, version=4)


def test_system_event_identification():
    """Verify system event logic when user_id is None or event is SYSTEM_AUDIT."""
    sys_event1 = event_engine.create_event(
        event_type=EventType.SYSTEM_AUDIT,
        severity=EventSeverity.INFO,
        indicator_type=IndicatorType.USER,
        indicator_value="system",
        user_id=None,
    )
    assert sys_event1.is_system_event is True

    sys_event2 = event_engine.create_event(
        event_type=EventType.ZERO_DAY_DETECTED,
        severity=EventSeverity.CRITICAL,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="zero-day-phish.org",
        user_id=None,
    )
    assert sys_event2.is_system_event is True


def test_invalid_event_type():
    """Verify error on invalid event_type string."""
    with pytest.raises(EventEngineError, match="SecurityEvent creation failed"):
        event_engine.create_event(
            event_type="INVALID_EVENT_TYPE",
            severity=EventSeverity.HIGH,
            indicator_type=IndicatorType.URL,
            indicator_value="http://example.com",
        )


def test_invalid_severity():
    """Verify error on invalid severity string."""
    with pytest.raises(EventEngineError, match="SecurityEvent creation failed"):
        event_engine.create_event(
            event_type=EventType.SCAN_COMPLETED,
            severity="ULTRA_CRITICAL",
            indicator_type=IndicatorType.URL,
            indicator_value="http://example.com",
        )


def test_invalid_indicator_type():
    """Verify error on invalid indicator_type string."""
    with pytest.raises(EventEngineError, match="SecurityEvent creation failed"):
        event_engine.create_event(
            event_type=EventType.SCAN_COMPLETED,
            severity=EventSeverity.MEDIUM,
            indicator_type="MAC_ADDRESS",
            indicator_value="00:11:22:33:44:55",
        )


def test_oversized_indicator_value():
    """Verify error when indicator_value exceeds 512 characters."""
    long_indicator = "https://example.com/" + "a" * 600
    with pytest.raises(EventEngineError):
        event_engine.create_event(
            event_type=EventType.SCAN_COMPLETED,
            severity=EventSeverity.LOW,
            indicator_type=IndicatorType.URL,
            indicator_value=long_indicator,
        )


def test_oversized_payload_rejection():
    """Verify rejection when payload size exceeds 10 KB (10,240 bytes)."""
    large_payload = {"data": "x" * 12000}
    with pytest.raises(EventEngineError, match="Payload size exceeds maximum allowed limit"):
        event_engine.create_event(
            event_type=EventType.SCAN_COMPLETED,
            severity=EventSeverity.HIGH,
            indicator_type=IndicatorType.URL,
            indicator_value="https://example.com",
            payload=large_payload,
        )


def test_malformed_uuid_validation():
    """Verify error when invalid UUID string is passed into SecurityEventSchema."""
    with pytest.raises(ValueError, match="Invalid UUIDv4 format"):
        SecurityEventSchema(
            event_uuid="not-a-valid-uuid-v4",
            event_type=EventType.SCAN_COMPLETED,
            severity=EventSeverity.INFO,
            indicator_type=IndicatorType.IP,
            indicator_value="1.1.1.1",
        )


def test_timestamp_normalization():
    """Verify timestamp parsing and normalization to UTC ISO string."""
    naive_dt = datetime(2026, 9, 12, 10, 30, 0)
    event = event_engine.create_event(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.INFO,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="example.com",
        timestamp=naive_dt,
    )
    assert event.timestamp.tzinfo == timezone.utc

    iso_str = "2026-09-12T10:30:00Z"
    event_iso = event_engine.create_event(
        event_type=EventType.SCAN_COMPLETED,
        severity=EventSeverity.INFO,
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="example.com",
        timestamp=iso_str,
    )
    assert event_iso.timestamp.tzinfo == timezone.utc


def test_event_serialization_and_deserialization():
    """Verify deterministic serialization to JSON and deserialization back to object."""
    engine = EventEngine()
    original_event = engine.create_event(
        event_type=EventType.HIGH_RISK_ENRICHMENT,
        severity=EventSeverity.CRITICAL,
        indicator_type=IndicatorType.IP,
        indicator_value="198.51.100.42",
        user_id=10,
        payload={"whois_age_days": 2, "tls_valid": False},
    )

    json_str = engine.serialize_event(original_event)
    assert isinstance(json_str, str)
    assert "198.51.100.42" in json_str

    deserialized = engine.deserialize_event(json_str)
    assert deserialized.event_uuid == original_event.event_uuid
    assert deserialized.event_type == original_event.event_type
    assert deserialized.severity == original_event.severity
    assert deserialized.indicator_type == original_event.indicator_type
    assert deserialized.indicator_value == original_event.indicator_value
    assert deserialized.user_id == original_event.user_id
    assert deserialized.payload == original_event.payload


def test_emit_event_with_subscribers():
    """Verify event emission notifies subscribers correctly."""
    received_events = []

    def test_subscriber(evt):
        received_events.append(evt)

    engine = EventEngine()
    engine._event_subscribers.append(test_subscriber)

    emitted = engine.emit_event(
        {
            "event_type": EventType.REPUTATION_CHANGED,
            "severity": EventSeverity.HIGH,
            "indicator_type": IndicatorType.DOMAIN,
            "indicator_value": "phish-domain.com",
        }
    )

    assert len(received_events) == 1
    assert received_events[0].event_uuid == emitted.event_uuid
    assert received_events[0].indicator_value == "phish-domain.com"
