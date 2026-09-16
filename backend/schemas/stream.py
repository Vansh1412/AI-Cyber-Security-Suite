"""
backend/schemas/stream.py
─────────────────────────
Sprint 5 Phase 5E: Real-Time SOC Alert Streaming Gateway Schemas.

Pydantic schemas for Server-Sent Events (SSE) envelopes, stream ticket exchange,
and stream status control frames.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SSEEventEnvelope(BaseModel):
    """Authoritative SSE payload envelope with monotonic cursor ordering."""

    cursor_id: int = Field(..., description="Monotonically increasing 64-bit sequence cursor")
    event_id: str = Field(..., description="Unique UUID v4 for client-side deduplication")
    event_type: str = Field(
        ...,
        description="Event type (alert_created, alert_updated, notification_dispatched, target_status_changed, etc.)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO-8601 UTC event creation timestamp",
    )
    tenant_id: int = Field(..., description="Owning tenant user_id")
    channel: str = Field(default="soc", description="Event channel (alerts, notifications, monitor, soc)")
    aggregate_id: str | None = Field(default=None, description="Identifier of originating domain resource")
    data: dict[str, Any] = Field(default_factory=dict, description="Sanitized event data payload (max 16 KB)")

    model_config = ConfigDict(from_attributes=True)

    def to_sse_frame(self) -> str:
        """Format envelope into W3C Server-Sent Event text frame."""
        dumped = self.model_dump(mode="json")
        # Ensure timestamp is ISO formatted
        if isinstance(dumped.get("timestamp"), datetime):
            dumped["timestamp"] = dumped["timestamp"].isoformat()
        payload = json.dumps(dumped)
        return f"event: {self.event_type}\nid: {self.cursor_id}\ndata: {payload}\n\n"


class StreamTicketRequest(BaseModel):
    """Optional configuration for stream ticket creation."""

    channel: str | None = Field(default="soc", description="Requested stream channel")


class StreamTicketResponse(BaseModel):
    """Single-use stream ticket response for native EventSource authentication."""

    ticket: str = Field(..., description="Opaque single-use stream ticket (st_<uuid>)")
    expires_in: int = Field(default=30, description="Ticket validity window in seconds")
    user_id: int = Field(..., description="Authenticated tenant user ID bound to ticket")


class StreamControlFrame(BaseModel):
    """Control frame sent to client to signal overflow, reset, or server shutdown."""

    action: str = Field(..., description="Control action (reconnect, resync_required, server_shutdown)")
    reason: str | None = Field(default=None, description="Detailed reason for control action")
    last_delivered_id: int | None = Field(default=None, description="Last cursor delivered before break")
    reconnect_after: int | None = Field(default=None, description="Recommended backoff in seconds")
