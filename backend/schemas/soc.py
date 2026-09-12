"""
backend/schemas/soc.py
────────────────────────
Pydantic v2 schemas for Sprint 5 Security Operations Center (SOC) domain events.

Defines:
- EventType, EventSeverity, IndicatorType Enums
- SecurityEventCreate (Validation schema for creating events)
- SecurityEventSchema (Full validated event representation)
- Bounded payload validation (Max 10 KB serialized JSON)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PAYLOAD_SIZE_BYTES = 10240  # 10 KB
MAX_INDICATOR_VALUE_LENGTH = 512


class EventType(str, Enum):
    SCAN_COMPLETED = "SCAN_COMPLETED"
    ZERO_DAY_DETECTED = "ZERO_DAY_DETECTED"
    REPUTATION_CHANGED = "REPUTATION_CHANGED"
    TARGET_STATUS_CHANGED = "TARGET_STATUS_CHANGED"
    HIGH_RISK_ENRICHMENT = "HIGH_RISK_ENRICHMENT"
    SYSTEM_AUDIT = "SYSTEM_AUDIT"


class EventSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IndicatorType(str, Enum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    HASH = "HASH"
    USER = "USER"


class SecurityEventCreate(BaseModel):
    """Input payload for creating a Security Event with strict validation."""

    event_type: EventType = Field(..., description="Type of security event.")
    severity: EventSeverity = Field(..., description="Event severity level.")
    indicator_type: IndicatorType = Field(..., description="Type of primary indicator.")
    indicator_value: str = Field(..., max_length=MAX_INDICATOR_VALUE_LENGTH, description="Value of primary indicator.")
    user_id: int | None = Field(default=None, description="Associated user ID or None for system events.")
    payload: dict[str, Any] = Field(default_factory=dict, description="Bounded JSON metadata payload.")
    timestamp: datetime | None = Field(default=None, description="Event timestamp in UTC. Defaults to current time.")

    model_config = ConfigDict(extra="forbid")

    @field_validator("indicator_value")
    @classmethod
    def validate_indicator_value(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("indicator_value cannot be empty or whitespace.")
        return v.strip()

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        try:
            serialized = json.dumps(v, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Payload contains non-serializable data: {exc}") from exc

        if len(serialized.encode("utf-8")) > MAX_PAYLOAD_SIZE_BYTES:
            raise ValueError(f"Payload size exceeds maximum allowed limit of {MAX_PAYLOAD_SIZE_BYTES} bytes (10 KB).")
        return v

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        if v is None:
            return datetime.now(timezone.utc)
        if isinstance(v, str):
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError as exc:
                raise ValueError(f"Invalid ISO timestamp format: '{v}'") from exc
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        raise ValueError(f"Invalid timestamp type: {type(v)}")


class SecurityEventSchema(BaseModel):
    """Full validated domain event payload."""

    event_uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique UUIDv4 for event.")
    event_type: EventType
    severity: EventSeverity
    indicator_type: IndicatorType
    indicator_value: str = Field(..., max_length=MAX_INDICATOR_VALUE_LENGTH)
    user_id: int | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    @field_validator("event_uuid")
    @classmethod
    def validate_uuid_format(cls, v: str) -> str:
        try:
            val = uuid.UUID(v, version=4)
            return str(val)
        except ValueError as exc:
            raise ValueError(f"Invalid UUIDv4 format: '{v}'") from exc

    @property
    def is_system_event(self) -> bool:
        """Return True if event is a system-level event (no specific user owner)."""
        return self.user_id is None or self.event_type == EventType.SYSTEM_AUDIT


# ── Phase 4 Incident Management Schemas ────────────────────────────────────────

class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


INCIDENT_STATUS_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.OPEN,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.OPEN},
    IncidentStatus.CLOSED: {IncidentStatus.OPEN},
}


class IncidentCreate(BaseModel):
    """Payload for creating a new Security Incident."""

    title: str = Field(min_length=1, max_length=255, description="Incident title.")
    description: str | None = Field(default=None, max_length=5000, description="Incident description.")
    severity: EventSeverity = Field(default=EventSeverity.HIGH, description="Incident severity level.")
    assigned_to_user_id: int | None = Field(default=None, description="User ID assigned to handle incident.")
    alert_ids: list[int] = Field(default_factory=list, description="Initial list of Alert IDs to link.")

    model_config = ConfigDict(extra="forbid")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("title cannot be empty or whitespace.")
        return v.strip()


class IncidentUpdate(BaseModel):
    """Payload for updating an existing Security Incident."""

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    severity: EventSeverity | None = Field(default=None)
    status: IncidentStatus | None = Field(default=None)
    assigned_to_user_id: int | None = Field(default=None)
    resolution_notes: str | None = Field(default=None, max_length=5000)

    model_config = ConfigDict(extra="forbid")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str | None) -> str | None:
        if v is not None:
            if not v or not v.strip():
                raise ValueError("title cannot be empty or whitespace.")
            return v.strip()
        return v


class AttachAlertsRequest(BaseModel):
    """Payload for attaching alert IDs to an incident."""

    alert_ids: list[int] = Field(min_length=1, max_length=100, description="Alert IDs to attach (1-100).")

    model_config = ConfigDict(extra="forbid")


class AlertResponse(BaseModel):
    """Response schema representing an Alert linked to an Incident."""

    id: int
    rule_name: str
    indicator_type: IndicatorType | str
    indicator_value: str
    severity: EventSeverity | str
    status: str
    fingerprint: str | None = None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    user_id: int | None = None
    incident_id: int | None = None

    model_config = ConfigDict(from_attributes=True)


class IncidentAggregateSummary(BaseModel):
    """Aggregated analytical context derived from attached Alerts."""

    alert_count: int = 0
    highest_severity: EventSeverity | str = EventSeverity.HIGH
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    affected_indicators: list[str] = Field(default_factory=list)
    affected_domains: list[str] = Field(default_factory=list)
    affected_ips: list[str] = Field(default_factory=list)


class IncidentResponse(BaseModel):
    """Full API representation of a Security Incident."""

    id: int
    incident_uuid: str
    title: str
    description: str | None = None
    severity: EventSeverity | str
    status: IncidentStatus | str
    assigned_to_user_id: int | None = None
    created_by_user_id: int | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
    resolution_notes: str | None = None
    alert_count: int = 0
    alerts: list[AlertResponse] = Field(default_factory=list)
    summary: IncidentAggregateSummary | None = None

    model_config = ConfigDict(from_attributes=True)


IncidentCreate.model_rebuild()
IncidentUpdate.model_rebuild()
AttachAlertsRequest.model_rebuild()
AlertResponse.model_rebuild()
IncidentAggregateSummary.model_rebuild()
IncidentResponse.model_rebuild()
