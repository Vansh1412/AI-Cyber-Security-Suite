"""backend/schemas/alerts.py
─────────────────────────────
Pydantic v2 schemas for Sprint 5 Phase 5C: SOC Alert Management,
Triage Lifecycle, Operational Controls, and Telemetry.

Defines:
- AlertStatus enum (authoritative 4-state lifecycle)
- ALERT_STATUS_TRANSITIONS directed transition mapping
- Triage request schemas (Acknowledge, Resolve, Dismiss, Reopen)
- Alert listing, detail, and telemetry responses
- Target diagnostics and operational telemetry responses
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AlertStatus(str, Enum):
    """Authoritative 4-state lifecycle for Security Alerts."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


ALERT_STATUS_TRANSITIONS: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.OPEN: {
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.RESOLVED,
        AlertStatus.DISMISSED,
    },
    AlertStatus.ACKNOWLEDGED: {
        AlertStatus.RESOLVED,
        AlertStatus.DISMISSED,
        AlertStatus.OPEN,  # Analyst unclaims/releases alert back to unassigned triage pool
    },
    AlertStatus.RESOLVED: {
        AlertStatus.OPEN,  # Reopen on new findings or re-triage
    },
    AlertStatus.DISMISSED: {
        AlertStatus.OPEN,  # Reopen on false-positive correction
    },
}


# ── Triage Request Schemas ───────────────────────────────────────────────────

class AlertAcknowledgeRequest(BaseModel):
    """Payload for acknowledging an Alert."""

    notes: str | None = Field(default=None, max_length=5000, description="Optional triage notes.")

    model_config = ConfigDict(extra="forbid")


class AlertResolveRequest(BaseModel):
    """Payload for resolving an Alert."""

    resolution_notes: str | None = Field(
        default=None, max_length=5000, description="Optional resolution rationale."
    )

    model_config = ConfigDict(extra="forbid")


class AlertDismissRequest(BaseModel):
    """Payload for dismissing an Alert (e.g. false positive)."""

    dismiss_reason: str = Field(
        ..., min_length=1, max_length=255, description="Required justification for dismissal."
    )
    triage_notes: str | None = Field(
        default=None, max_length=5000, description="Optional supporting investigation notes."
    )
    notes: str | None = Field(
        default=None, max_length=5000, description="Optional supporting investigation notes (alias)."
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("dismiss_reason")
    @classmethod
    def validate_dismiss_reason(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("dismiss_reason cannot be empty or whitespace.")
        return clean


class AlertReopenRequest(BaseModel):
    """Payload for reopening a resolved or dismissed Alert."""

    reopen_notes: str | None = Field(
        default=None, max_length=5000, description="Optional reason for reopening."
    )

    model_config = ConfigDict(extra="forbid")


# ── Alert Response Schemas ───────────────────────────────────────────────────

class AlertResponse(BaseModel):
    """Full API representation of a Security Alert."""

    id: int
    alert_uuid: str
    title: str
    description: str | None = None
    severity: str
    status: str
    rule_name: str
    indicator_type: str
    indicator_value: str
    fingerprint: str | None = None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    dismissed_at: datetime | None = None
    dismiss_reason: str | None = None
    triage_notes: str | None = None
    user_id: int | None = None
    incident_id: int | None = None

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    """Paginated list of Security Alerts."""

    items: list[AlertResponse]
    total: int
    page: int
    page_size: int
    has_next: bool


class AlertStatsResponse(BaseModel):
    """Aggregated alert metrics, velocity, and deduplication savings ratio."""

    total_alerts: int
    open_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    dismissed_alerts: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    alerts_last_24h: int
    alert_velocity_per_hour: float
    dedup_savings_ratio: float


# ── Monitoring Operational Schemas ───────────────────────────────────────────

class MonitoringTargetDiagnosticsResponse(BaseModel):
    """Diagnostic outcome and telemetry from last execution of a monitoring target."""

    target_uuid: str
    url: str
    is_active: bool
    consecutive_failures: int
    last_checked_at: datetime | None = None
    last_status_code: int | None = None
    last_response_time_ms: float | None = None
    last_error_message: str | None = None
    last_prediction: str | None = None
    last_confidence: float | None = None

    model_config = ConfigDict(from_attributes=True)


class MonitoringStatsResponse(BaseModel):
    """Aggregated target distribution and scheduler health telemetry."""

    total_targets: int
    active_targets: int
    paused_targets: int
    suspended_targets: int
    failing_targets: int
    scheduler_leader: str | None = None
    scheduler_epoch: int = 0
    active_workers: int = 0
    pool_capacity: int = 10


class CheckNowResponse(BaseModel):
    """Response returned upon successfully dispatching an on-demand check."""

    target_uuid: str
    execution_token: str
    dispatched_at: datetime
    message: str
