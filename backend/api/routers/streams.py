"""
backend/api/routers/streams.py
──────────────────────────────
Sprint 5 Phase 5E: Real-Time SOC Alert Streaming Gateway Endpoints.

Endpoints:
  POST /v1/streams/ticket           — Exchange Bearer JWT for 30s single-use stream ticket
  GET  /v1/alerts/stream            — Real-time SSE stream of alert events
  GET  /v1/notifications/stream     — Real-time SSE stream of notification events
  GET  /v1/soc/stream               — Unified multiplexed real-time SOC stream
  GET  /v1/admin/soc/stream         — Canonical global admin SOC stream (Admin only)
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.core.rate_limit import limiter
from backend.database.models import AuditEvent, User
from backend.schemas.stream import (
    StreamTicketRequest,
    StreamTicketResponse,
)
from backend.services.event_broadcaster import event_broadcaster
from src.utils.logger import logger

router = APIRouter(tags=["Real-Time Streaming Gateway"])


# ── Dependency: Authenticate Stream Connection ─────────────────────────────────

async def get_stream_user(
    request: Request,
    ticket: str | None = Query(default=None, description="Single-use 30s stream ticket"),
    token: str | None = Query(default=None, description="Prohibited reusable query JWT parameter"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Authenticate streaming connection.
    Strictly forbids reusable JWT in query parameter (?token=...) to prevent URL logging leaks.
    Accepts standard 'Authorization: Bearer <jwt>' header OR single-use stream ticket (?ticket=st_...).
    """
    # 1. Enforce strict prohibition on reusable JWT query parameter
    if token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Passing reusable JWT tokens in query parameters is prohibited for security. "
                "Use 'Authorization: Bearer <token>' header or request a single-use stream ticket "
                "via POST /v1/streams/ticket."
            ),
        )

    # 2. Check standard Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token_str = auth_header[7:].strip()
        override_fn = getattr(request.app, "dependency_overrides", {}).get(get_current_user)
        if override_fn:
            import inspect
            if inspect.iscoroutinefunction(override_fn):
                return await override_fn()
            return override_fn()
        return await get_current_user(token=token_str, db=db)

    # 3. Check single-use stream ticket
    if ticket:
        user_id = await event_broadcaster.validate_and_burn_stream_ticket(ticket)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or already consumed stream ticket.",
            )
        stmt = select(User).where(User.id == user_id)
        res = await db.execute(stmt)
        user = res.scalars().first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or not found.",
            )
        return user

    # 4. No valid credentials provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication. Provide 'Authorization: Bearer <token>' header or valid '?ticket=<st_ticket>'.",
    )


# ── POST /v1/streams/ticket ───────────────────────────────────────────────────

@router.post("/streams/ticket", response_model=StreamTicketResponse)
@limiter.limit("20/minute")
async def create_stream_ticket(
    request: Request,
    payload: StreamTicketRequest | None = None,
    current_user: User = Depends(get_current_user),
) -> StreamTicketResponse:
    """
    Exchange a valid Bearer JWT for a single-use, 30-second stream ticket.
    Enables native EventSource browser connections without exposing reusable JWTs in URLs.
    """
    channel = payload.channel if payload and payload.channel else "soc"
    ticket = await event_broadcaster.create_stream_ticket(user_id=current_user.id, channel=channel)
    return StreamTicketResponse(
        ticket=ticket,
        expires_in=event_broadcaster.TICKET_TTL_SECONDS,
        user_id=current_user.id,
    )


# ── Helper: Stream Generator ──────────────────────────────────────────────────

async def _sse_event_stream_generator(
    user: User,
    channel: str,
    min_severity: str | None,
    last_event_id: str | None,
    db: AsyncSession,
    is_admin: bool = False,
    request: Request | None = None,
    max_events: int | None = None,
    q: asyncio.Queue | None = None,
) -> AsyncGenerator[str, None]:
    """Asynchronous generator yielding W3C formatted SSE frames with lifecycle protection."""
    if max_events is None and request:
        limit_header = request.headers.get("X-Stream-Limit")
        if limit_header is not None:
            with contextlib.suppress(ValueError):
                max_events = int(limit_header)

    if q is None:
        q = await event_broadcaster.register_listener(
            user=user,
            channel=channel,
            min_severity=min_severity,
            is_admin_stream=is_admin,
        )

    start_time = time.time()
    last_auth_check = time.time()
    events_yielded = 0

    try:
        # Initial connection acknowledgment comment
        yield f": connected (pod_id: {event_broadcaster.pod_id})\n\n"

        if max_events is not None and max_events == 0:
            return

        # Handle Last-Event-ID replay if requested
        if last_event_id:
            try:
                cursor_val = int(last_event_id.strip())
                replay_events, is_expired = await event_broadcaster.get_replay_events(
                    session=db,
                    tenant_id=user.id,
                    last_event_id=cursor_val,
                    is_admin=is_admin,
                )
                if is_expired:
                    yield 'event: stream_reset\ndata: {"action": "resync_required", "reason": "cursor_expired"}\n\n'
                    events_yielded += 1
                    if max_events is not None and events_yielded >= max_events:
                        return
                else:
                    for ev in replay_events:
                        yield ev.to_sse_frame()
                        events_yielded += 1
                        if max_events is not None and events_yielded >= max_events:
                            return
            except (ValueError, TypeError) as exc:
                logger.warning("[SSE_STREAM] Invalid Last-Event-ID format '%s': %s", last_event_id, exc)

        # Main event loop
        while True:
            # 1. Enforce Maximum Stream Lifetime (3,600s)
            elapsed = time.time() - start_time
            if elapsed >= event_broadcaster.STREAM_MAX_LIFETIME_SECONDS:
                yield 'event: stream_refresh\ndata: {"refresh": true, "reason": "max_lifetime_reached"}\n\n'
                break

            # 2. Periodic Auth Lifecycle Check (Every 45s)
            if time.time() - last_auth_check > 45:
                last_auth_check = time.time()
                check_stmt = select(User.is_active, User.role).where(User.id == user.id)
                res = await db.execute(check_stmt)
                user_state = res.first()
                if not user_state or not user_state.is_active:
                    yield 'event: stream_auth_revoked\ndata: {"reason": "account_deactivated"}\n\n'
                    break
                if is_admin and user_state.role != "admin":
                    yield 'event: stream_auth_revoked\ndata: {"reason": "admin_role_revoked"}\n\n'
                    break

            # 3. Await event from queue with timeout (1s for prompt disconnect responsiveness)
            try:
                item = await asyncio.wait_for(q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Process control frames or envelopes
            if isinstance(item, dict) and "control" in item:
                ctrl = item["control"]
                if ctrl == "heartbeat":
                    yield ": ping\n\n"
                elif ctrl == "server_shutdown":
                    yield f'event: server_shutdown\ndata: {{"reconnect_after": {item.get("reconnect_after", 5)}}}\n\n'
                    break
                elif ctrl == "stream_overflow":
                    last_deliv = item.get("last_delivered_id")
                    yield f'event: stream_overflow\ndata: {{"reconnect": true, "last_delivered_id": {last_deliv}}}\n\n'
                    break
            elif hasattr(item, "to_sse_frame"):
                yield item.to_sse_frame()
                events_yielded += 1
                if max_events is not None and events_yielded >= max_events:
                    break

    except asyncio.CancelledError:
        logger.debug("[SSE_STREAM] Client disconnected from stream (user_id=%d, channel=%s)", user.id, channel)
    except Exception as exc:
        logger.error("[SSE_STREAM] Error in SSE stream loop: %s", exc)
    finally:
        await event_broadcaster.unregister_listener(user=user, q=q, is_admin_stream=is_admin)


def _build_sse_response(generator: AsyncGenerator[str, None]) -> StreamingResponse:
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Content-Type": "text/event-stream; charset=utf-8",
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── GET /v1/alerts/stream ────────────────────────────────────────────────     

@router.get("/alerts/stream")
async def stream_alerts(
    request: Request,
    min_severity: str | None = Query(default=None, description="Minimum severity filter (e.g. HIGH, CRITICAL)"),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    max_events: int | None = Query(default=None, description="Optional maximum events to receive before closing"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_stream_user),
) -> StreamingResponse:
    """Stream real-time security alerts scoped strictly to the authenticated tenant."""
    q = await event_broadcaster.register_listener(
        user=current_user,
        channel="alerts",
        min_severity=min_severity,
        is_admin_stream=False,
    )
    generator = _sse_event_stream_generator(
        user=current_user,
        channel="alerts",
        min_severity=min_severity,
        last_event_id=last_event_id,
        db=db,
        is_admin=False,
        request=request,
        max_events=max_events,
        q=q,
    )
    return _build_sse_response(generator)


# ── GET /v1/notifications/stream ──────────────────────────────────────────────

@router.get("/notifications/stream")
async def stream_notifications(
    request: Request,
    min_severity: str | None = Query(default=None, description="Minimum notification severity filter"),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    max_events: int | None = Query(default=None, description="Optional maximum events to receive before closing"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_stream_user),
) -> StreamingResponse:
    """Stream real-time notification events scoped strictly to the authenticated tenant."""
    q = await event_broadcaster.register_listener(
        user=current_user,
        channel="notifications",
        min_severity=min_severity,
        is_admin_stream=False,
    )
    generator = _sse_event_stream_generator(
        user=current_user,
        channel="notifications",
        min_severity=min_severity,
        last_event_id=last_event_id,
        db=db,
        is_admin=False,
        request=request,
        max_events=max_events,
        q=q,
    )
    return _build_sse_response(generator)


# ── GET /v1/soc/stream ────────────────────────────────────────────────        

@router.get("/soc/stream")
async def stream_soc(
    request: Request,
    min_severity: str | None = Query(default=None, description="Minimum severity filter"),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    max_events: int | None = Query(default=None, description="Optional maximum events to receive before closing"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_stream_user),
) -> StreamingResponse:
    """Stream unified alerts and notification events for the authenticated tenant."""
    q = await event_broadcaster.register_listener(
        user=current_user,
        channel="soc",
        min_severity=min_severity,
        is_admin_stream=False,
    )
    generator = _sse_event_stream_generator(
        user=current_user,
        channel="soc",
        min_severity=min_severity,
        last_event_id=last_event_id,
        db=db,
        is_admin=False,
        request=request,
        max_events=max_events,
        q=q,
    )
    return _build_sse_response(generator)


# ── GET /v1/admin/soc/stream ──────────────────────────────────────────────────

@router.get("/admin/soc/stream")
async def stream_admin_soc(
    request: Request,
    min_severity: str | None = Query(default=None, description="Minimum severity filter"),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    max_events: int | None = Query(default=None, description="Optional maximum events to receive before closing"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_stream_user),
) -> StreamingResponse:
    """
    Canonical administrative global real-time SOC threat stream.
    Requires administrator role. Audits access and enforces strict administrative stream caps.
    """
    if getattr(current_user, "role", "user") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to the global SOC stream requires administrative privileges.",
        )

    # Log admin audit event for stream connection
    ip = request.client.host if request.client else None
    audit = AuditEvent(
        action="ADMIN_SOC_STREAM_CONNECTED",
        actor_user_id=current_user.id,
        target_resource="streams",
        resource_id="admin/soc/stream",
        details={"channel": "admin_soc", "ip": ip},
        ip_address=ip,
    )
    db.add(audit)
    await db.commit()

    q = await event_broadcaster.register_listener(
        user=current_user,
        channel="soc",
        min_severity=min_severity,
        is_admin_stream=True,
    )

    generator = _sse_event_stream_generator(
        user=current_user,
        channel="soc",
        min_severity=min_severity,
        last_event_id=last_event_id,
        db=db,
        is_admin=True,
        request=request,
        max_events=max_events,
        q=q,
    )
    return _build_sse_response(generator)
