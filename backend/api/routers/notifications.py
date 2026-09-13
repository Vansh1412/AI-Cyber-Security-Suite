"""
backend/api/routers/notifications.py
────────────────────────────────────
Sprint 5 Phase 5D: REST API for In-App Notifications and User Webhook Preferences.

Endpoints:
  GET   /v1/notifications                 — List own notifications (paginated, filtered)
  GET   /v1/notifications/unread-count    — Get unread notification count
  POST  /v1/notifications/{uuid}/read     — Mark single notification as read
  POST  /v1/notifications/mark-all-read   — Mark all unread notifications as read
  GET   /v1/notifications/preferences     — Get user preferences (masked secret preview)
  PUT   /v1/notifications/preferences     — Update preferences (AES-encrypted secret)
"""

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.core.rate_limit import limiter
from backend.database.models import User
from backend.schemas.notification import (
    MarkAllReadResponse,
    NotificationListResponse,
    NotificationPreferenceResponse,
    NotificationPreferenceUpdate,
    NotificationResponse,
    UnreadCountResponse,
)
from backend.services.notification_service import (
    NotificationNotFoundError,
    NotificationServiceError,
    notification_service,
)
from src.utils.logger import logger

router = APIRouter(prefix="/notifications", tags=["Notifications"])


# ── GET /v1/notifications ─────────────────────────────────────────────────────

@router.get(
    "",
    response_model=NotificationListResponse,
    summary="List Notifications",
    description="Retrieve paginated list of notifications scoped strictly to the authenticated tenant.",
)
@limiter.limit("60/minute")
async def list_notifications(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)"),
    is_read: bool | None = Query(default=None, description="Filter by read status"),
    severity: str | None = Query(default=None, description="Filter by severity level"),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> NotificationListResponse:
    try:
        return await notification_service.list_notifications(
            session=session,
            current_user=current_user,
            page=page,
            page_size=page_size,
            is_read=is_read,
            severity=severity,
        )
    except Exception as exc:
        logger.error("[API] Failed to list notifications for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve notifications.",
        ) from exc


# ── GET /v1/notifications/unread-count ────────────────────────────────────────

@router.get(
    "/unread-count",
    response_model=UnreadCountResponse,
    summary="Get Unread Notification Count",
    description="Return total count of unread notifications for authenticated user.",
)
@limiter.limit("120/minute")
async def get_unread_count(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UnreadCountResponse:
    try:
        count = await notification_service.get_unread_count(session, current_user)
        return UnreadCountResponse(unread_count=count)
    except Exception as exc:
        logger.error("[API] Failed to get unread count for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve unread notification count.",
        ) from exc


# ── POST /v1/notifications/{notification_uuid}/read ───────────────────────────

@router.post(
    "/{notification_uuid}/read",
    response_model=NotificationResponse,
    summary="Mark Notification as Read",
    description="Mark single notification as read. Returns 404 for foreign tenant or invalid UUID.",
)
@limiter.limit("60/minute")
async def mark_notification_read(
    request: Request,
    notification_uuid: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> NotificationResponse:
    try:
        return await notification_service.mark_as_read(
            session=session,
            notification_uuid=notification_uuid,
            current_user=current_user,
        )
    except NotificationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("[API] Failed to mark notification read for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification.",
        ) from exc


# ── POST /v1/notifications/mark-all-read ──────────────────────────────────────

@router.post(
    "/mark-all-read",
    response_model=MarkAllReadResponse,
    summary="Mark All Notifications as Read",
    description="Mark all unread notifications as read for the authenticated tenant.",
)
@limiter.limit("30/minute")
async def mark_all_notifications_read(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MarkAllReadResponse:
    try:
        count = await notification_service.mark_all_as_read(session, current_user)
        return MarkAllReadResponse(updated_count=count)
    except Exception as exc:
        logger.error("[API] Failed to mark all read for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark notifications read.",
        ) from exc


# ── GET /v1/notifications/preferences ─────────────────────────────────────────

@router.get(
    "/preferences",
    response_model=NotificationPreferenceResponse,
    summary="Get Notification Preferences",
    description="Retrieve notification and webhook configuration with masked secret preview.",
)
@limiter.limit("30/minute")
async def get_preferences(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> NotificationPreferenceResponse:
    try:
        return await notification_service.get_preferences(session, current_user)
    except Exception as exc:
        logger.error("[API] Failed to get preferences for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve notification preferences.",
        ) from exc


# ── PUT /v1/notifications/preferences ─────────────────────────────────────────

@router.put(
    "/preferences",
    response_model=NotificationPreferenceResponse,
    summary="Update Notification Preferences",
    description="Update notification and webhook configuration. Plaintext secrets are AES-encrypted at rest.",
)
@limiter.limit("15/minute")
async def update_preferences(
    request: Request,
    payload: NotificationPreferenceUpdate = Body(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> NotificationPreferenceResponse:
    client_ip = getattr(getattr(request, "client", None), "host", None)
    try:
        return await notification_service.update_preferences(
            session=session,
            current_user=current_user,
            payload=payload,
            ip_address=client_ip,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except NotificationServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("[API] Failed to update preferences for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification preferences.",
        ) from exc
