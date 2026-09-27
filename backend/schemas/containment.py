"""
backend/schemas/containment.py
──────────────────────────────
Pydantic schemas and enums for Sprint 5 Phase 5F:
Automated Threat Containment, Declarative SOAR-Lite Playbooks & Lifecycle Retention.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ContainmentActionType(str, Enum):
    BLACKLIST_INDICATOR = "BLACKLIST_INDICATOR"
    INVALIDATE_CACHE = "INVALIDATE_CACHE"
    QUARANTINE_TARGET = "QUARANTINE_TARGET"
    CREATE_INCIDENT = "CREATE_INCIDENT"
    EMIT_SOC_EVENT = "EMIT_SOC_EVENT"
    SEND_NOTIFICATION = "SEND_NOTIFICATION"


class ContainmentActionStatus(str, Enum):
    PENDING = "PENDING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    BLOCKED_BY_ALLOWLIST = "BLOCKED_BY_ALLOWLIST"
    SKIPPED = "SKIPPED"
    REVERTED = "REVERTED"


class PlaybookRunStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIALLY_REVERTED = "PARTIALLY_REVERTED"
    REVERTED = "REVERTED"


# ── Policy Schemas ────────────────────────────────────────────────────────────

class ContainmentPolicyBase(BaseModel):
    auto_containment_enabled: bool = Field(
        default=False,
        description="Master kill-switch for automated containment on tenant alerts.",
    )
    auto_blacklist_enabled: bool = Field(
        default=False,
        description="Enables automated indicator blacklisting upon qualifying critical alerts.",
    )
    auto_quarantine_enabled: bool = Field(
        default=False,
        description="Enables automated target quarantine when threshold criteria are met.",
    )
    auto_incident_binding_enabled: bool = Field(
        default=False,
        description="Enables automated incident creation or binding for containment alerts.",
    )
    containment_min_severity: str = Field(
        default="CRITICAL",
        description="Minimum alert severity to evaluate for automated containment ('CRITICAL' or 'HIGH').",
    )
    blacklist_ttl_seconds: int = Field(
        default=86400,
        ge=60,
        le=2592000,
        description="Default TTL in seconds for automated blacklist entries (default 24h).",
    )


class ContainmentPolicyUpdate(ContainmentPolicyBase):
    policy_version: int = Field(
        default=1,
        description="Optimistic concurrency control version. Must match current policy_version.",
    )


class ContainmentPolicyResponse(ContainmentPolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    policy_version: int
    created_at: datetime
    updated_at: datetime
    updated_by: int | None = None


# ── Action Schemas ────────────────────────────────────────────────────────────

class ContainmentRequest(BaseModel):
    action_type: ContainmentActionType
    target_identifier: str = Field(..., min_length=1, max_length=512)
    alert_id: int | None = None
    reason: str = Field(default="Analyst manual containment", max_length=255)


class ContainmentActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_uuid: str
    run_id: int | None = None
    tenant_id: int
    alert_id: int | None = None
    incident_id: int | None = None
    target_identifier: str
    action_type: str
    status: str
    actor_user_id: int | None = None
    trigger_source: str
    action_idempotency_key: str
    rollback_metadata: dict[str, Any] | None = None
    result_metadata: dict[str, Any] | None = None
    error_message: str | None = None
    expires_at: datetime | None = None
    reverted_at: datetime | None = None
    reverted_by_user_id: int | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class PaginatedContainmentActions(BaseModel):
    items: list[ContainmentActionResponse]
    total: int
    page: int
    page_size: int


# ── Playbook Run Schemas ──────────────────────────────────────────────────────

class PlaybookRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_uuid: str
    playbook_name: str
    playbook_version: str
    tenant_id: int
    trigger_event: str
    alert_id: int | None = None
    target_id: int | None = None
    status: str
    fencing_token: int
    action_count: int
    idempotency_key: str
    error_message: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    actions: list[ContainmentActionResponse] = Field(default_factory=list)


class PaginatedPlaybookRuns(BaseModel):
    items: list[PlaybookRunResponse]
    total: int
    page: int
    page_size: int
