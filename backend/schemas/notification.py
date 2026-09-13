"""
backend/schemas/notification.py
───────────────────────────────
Sprint 5 Phase 5D: Pydantic schemas for In-App Notifications,
Preferences, Webhook Egress, and Outbox Queue.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OutboxStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"


class OutboxChannel(str, Enum):
    WEBHOOK = "WEBHOOK"
    IN_APP = "IN_APP"


# ── In-App Notification Schemas ───────────────────────────────────────────────

class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    notification_uuid: str
    user_id: int
    title: str
    message: str
    severity: str
    is_read: bool
    link_url: str | None = None
    created_at: datetime


class NotificationListResponse(BaseModel):
    items: list[NotificationResponse]
    total: int
    unread_count: int
    page: int
    page_size: int
    has_next: bool


class UnreadCountResponse(BaseModel):
    unread_count: int


class MarkAllReadResponse(BaseModel):
    updated_count: int


# ── Notification Preference Schemas ───────────────────────────────────────────

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


class NotificationPreferenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    in_app_enabled: bool
    email_enabled: bool
    webhook_enabled: bool
    webhook_url: str | None = None
    has_webhook_secret: bool
    webhook_secret_preview: str | None = None
    min_severity: str = "HIGH"
    circuit_broken: bool = False
    circuit_broken_at: datetime | None = None
    updated_at: datetime


class NotificationPreferenceUpdate(BaseModel):
    in_app_enabled: bool | None = None
    email_enabled: bool | None = None
    webhook_enabled: bool | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None
    rotate_secret: bool | None = False
    clear_webhook_secret: bool | None = False
    min_severity: str | None = None

    @field_validator("webhook_secret")
    @classmethod
    def validate_webhook_secret(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v_stripped = v.strip()
        if not v_stripped:
            return None
        if len(v_stripped) < 32:
            raise ValueError("Webhook secret must contain at least 32 characters.")
        if len(set(v_stripped)) < 2:
            raise ValueError("Webhook secret is too simple / insufficient entropy.")
        return v_stripped

    @field_validator("min_severity")
    @classmethod
    def validate_min_severity(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v_upper = v.upper().strip()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"min_severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}")
        return v_upper

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v_stripped = v.strip()
        if not v_stripped:
            return None
        if not v_stripped.startswith(("http://", "https://")):
            raise ValueError("webhook_url must start with http:// or https://")
        return v_stripped


# ── Webhook Payload Schema ───────────────────────────────────────────────────

class WebhookAlertPayload(BaseModel):
    event: str = Field(..., description="ALERT_TRIGGERED, ALERT_ESCALATED, TARGET_SUSPENDED, etc.")
    alert_uuid: str
    title: str
    description: str | None = None
    severity: str
    status: str
    rule_name: str
    indicator_type: str
    indicator_value: str
    occurrence_count: int
    first_seen_at: str
    last_seen_at: str
