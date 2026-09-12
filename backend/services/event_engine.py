"""
backend/services/event_engine.py
─────────────────────────────────
Sprint 5: Event Engine Service for SOC Domain Events.

Responsibilities:
- Event creation, validation, and normalization
- Bounded payload size enforcement
- Thread-safe / Async event emission infrastructure
- Deterministic event serialization/deserialization
- User ownership vs. System event tracking
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from backend.schemas.soc import (
    EventSeverity,
    EventType,
    IndicatorType,
    SecurityEventCreate,
    SecurityEventSchema,
)
from src.utils.logger import logger


class EventEngineError(Exception):
    """Raised when event creation, validation, or emission fails."""

    pass


class EventEngine:
    """
    Centralized SOC Event Engine.

    Validates, normalizes, serializes, and dispatches security events across
    the AI Cyber Security Suite.
    """

    def __init__(self, in_memory_buffer_max: int = 1000):
        self._buffer_max = in_memory_buffer_max
        self._event_subscribers: list[Any] = []

    def create_event(
        self,
        event_type: EventType | str,
        severity: EventSeverity | str,
        indicator_type: IndicatorType | str,
        indicator_value: str,
        user_id: int | None = None,
        payload: dict[str, Any] | None = None,
        timestamp: datetime | str | None = None,
    ) -> SecurityEventSchema:
        """
        Construct, validate, and normalize a SecurityEvent instance.

        Raises:
            EventEngineError: If validation fails or payload exceeds limits.
        """
        try:
            create_schema = SecurityEventCreate(
                event_type=event_type,  # type: ignore[arg-type]
                severity=severity,      # type: ignore[arg-type]
                indicator_type=indicator_type,  # type: ignore[arg-type]
                indicator_value=indicator_value,
                user_id=user_id,
                payload=payload or {},
                timestamp=timestamp,  # type: ignore[arg-type]
            )
            event_schema = SecurityEventSchema(
                event_type=create_schema.event_type,
                severity=create_schema.severity,
                indicator_type=create_schema.indicator_type,
                indicator_value=create_schema.indicator_value,
                user_id=create_schema.user_id,
                payload=create_schema.payload,
                timestamp=create_schema.timestamp or datetime.now(timezone.utc),
            )
            return event_schema
        except Exception as exc:
            raise EventEngineError(f"SecurityEvent creation failed: {exc}") from exc

    def emit_event(self, event: SecurityEventSchema | SecurityEventCreate | dict[str, Any]) -> SecurityEventSchema:
        """
        Synchronously validate and emit a security event.

        Returns:
            The validated SecurityEventSchema instance.
        """
        if isinstance(event, dict):
            event_obj = self.create_event(**event)
        elif isinstance(event, SecurityEventCreate):
            event_obj = self.create_event(
                event_type=event.event_type,
                severity=event.severity,
                indicator_type=event.indicator_type,
                indicator_value=event.indicator_value,
                user_id=event.user_id,
                payload=event.payload,
                timestamp=event.timestamp,
            )
        elif isinstance(event, SecurityEventSchema):
            event_obj = event
        else:
            raise EventEngineError(f"Unsupported event type for emission: {type(event)}")

        logger.info(
            "[EVENT_ENGINE] Emitted %s (%s) for %s:%s [User: %s]",
            event_obj.event_type.value,
            event_obj.severity.value,
            event_obj.indicator_type.value,
            event_obj.indicator_value[:64],
            event_obj.user_id if event_obj.user_id is not None else "SYSTEM",
        )

        for subscriber in self._event_subscribers:
            try:
                subscriber(event_obj)
            except Exception as exc:
                logger.error("[EVENT_ENGINE] Subscriber dispatch failed: %s", exc)

        return event_obj

    def serialize_event(self, event: SecurityEventSchema) -> str:
        """Serialize a SecurityEventSchema to a deterministic JSON string."""
        return json.dumps(
            {
                "event_uuid": event.event_uuid,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "indicator_type": event.indicator_type.value,
                "indicator_value": event.indicator_value,
                "user_id": event.user_id,
                "payload": event.payload,
                "timestamp": event.timestamp.isoformat(),
                "is_system_event": event.is_system_event,
            },
            sort_keys=True,
        )

    def deserialize_event(self, json_str: str) -> SecurityEventSchema:
        """Deserialize a JSON string into a validated SecurityEventSchema."""
        try:
            data = json.loads(json_str)
            return SecurityEventSchema(
                event_uuid=data["event_uuid"],
                event_type=EventType(data["event_type"]),
                severity=EventSeverity(data["severity"]),
                indicator_type=IndicatorType(data["indicator_type"]),
                indicator_value=data["indicator_value"],
                user_id=data.get("user_id"),
                payload=data.get("payload", {}),
                timestamp=datetime.fromisoformat(data["timestamp"]),
            )
        except Exception as exc:
            raise EventEngineError(f"Failed to deserialize SecurityEvent JSON: {exc}") from exc


# Singleton instance
event_engine = EventEngine()
