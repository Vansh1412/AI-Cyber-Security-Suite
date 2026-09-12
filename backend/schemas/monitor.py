"""
backend/schemas/monitor.py
────────────────────────────
Sprint 5 Phase 5A: Pydantic v2 schemas for Monitoring Target CRUD.

Defines:
  MonitoringTargetCreate  — registration payload (SSRF pre-check enforced at router)
  MonitoringTargetUpdate  — PATCH payload (all fields optional)
  MonitoringTargetResponse — full API representation
  MonitoringTargetListResponse — paginated list wrapper

Constraints enforced here:
  - check_interval_minutes: 5 ≤ value ≤ 1440
  - url: must be a non-empty string ≤ 2048 chars with http/https scheme (syntactic only;
    SSRF validation at the network layer happens in the router/service)
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 1440  # 24 hours
MAX_URL_LENGTH = 2048


def _require_http_scheme(url: str) -> str:
    """Syntactically validate that the URL uses http or https scheme."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL must use http or https scheme, got: '{parsed.scheme or '(none)'}'"
        )
    if not parsed.netloc:
        raise ValueError("URL must contain a valid host.")
    return url.strip()


class MonitoringTargetCreate(BaseModel):
    """Payload for registering a new monitoring target."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=MAX_URL_LENGTH,
        description="Target URL to monitor (http/https only).",
    )
    check_interval_minutes: int = Field(
        default=60,
        ge=MIN_INTERVAL_MINUTES,
        le=MAX_INTERVAL_MINUTES,
        description=(
            f"Monitoring check interval in minutes "
            f"({MIN_INTERVAL_MINUTES}–{MAX_INTERVAL_MINUTES})."
        ),
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        return _require_http_scheme(v)


class MonitoringTargetUpdate(BaseModel):
    """Payload for updating an existing monitoring target (all fields optional)."""

    check_interval_minutes: int | None = Field(
        default=None,
        ge=MIN_INTERVAL_MINUTES,
        le=MAX_INTERVAL_MINUTES,
        description="New monitoring interval in minutes.",
    )
    is_active: bool | None = Field(
        default=None,
        description="Set False to pause monitoring; True to resume.",
    )

    model_config = ConfigDict(extra="forbid")


class MonitoringTargetResponse(BaseModel):
    """Full API representation of a monitoring target."""

    id: int
    target_uuid: str
    url: str
    normalized_domain: str
    check_interval_minutes: int
    is_active: bool
    last_checked_at: datetime | None = None
    next_check_at: datetime
    last_prediction: str | None = None
    last_confidence: float | None = None
    consecutive_failures: int
    user_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MonitoringTargetListResponse(BaseModel):
    """Paginated list of monitoring targets."""

    items: list[MonitoringTargetResponse]
    total: int
    page: int
    page_size: int
    has_more: bool

    model_config = ConfigDict(from_attributes=True)
