"""
backend/api/routers/monitor.py
───────────────────────────────
Sprint 5 Phase 5A: Monitoring Target CRUD API Endpoints.

Endpoints (all require authentication):
  POST   /v1/monitor/targets            — Register a new monitoring target
  GET    /v1/monitor/targets            — List own targets (paginated)
  GET    /v1/monitor/targets/{uuid}     — Get target detail
  PATCH  /v1/monitor/targets/{uuid}     — Update interval or activation
  DELETE /v1/monitor/targets/{uuid}     — Soft-delete (deactivate) a target

Security:
  - All endpoints require a valid Bearer token (get_current_user dependency).
  - Registration performs a full SSRF pre-check (scheme + host resolution).
  - Per-user target limit enforced at registration (MAX_TARGETS_PER_USER).
  - UUID-based target identity prevents sequential ID enumeration.
  - Multi-tenant scoping: every query filters by user_id.
"""

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.core.rate_limit import limiter
from backend.database.models import User
from backend.schemas.alerts import (
    CheckNowResponse,
    MonitoringStatsResponse,
    MonitoringTargetDiagnosticsResponse,
)
from backend.schemas.monitor import (
    MonitoringTargetCreate,
    MonitoringTargetListResponse,
    MonitoringTargetResponse,
    MonitoringTargetUpdate,
)
from backend.services.monitoring_service import (
    MonitorAccessDeniedError,
    MonitorLeaseConflictError,
    MonitorLimitExceededError,
    MonitorNotFoundError,
    MonitorServiceError,
    MonitorSSRFError,
    MonitorTargetSuspendedError,
    MonitorValidationError,
    monitoring_service,
)

router = APIRouter(prefix="/monitor", tags=["Monitoring"])
targets_router = APIRouter(prefix="/targets", tags=["Monitoring Targets"])


# ── POST /v1/monitor/targets ───────────────────────────────────────────────────

@targets_router.post("", response_model=MonitoringTargetResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def register_target(
    request: Request,
    payload: MonitoringTargetCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetResponse:
    """
    Register a new monitoring target.

    The URL is SSRF-validated at registration time (scheme + DNS resolution).
    Returns HTTP 422 if the URL fails syntactic validation.
    Returns HTTP 400 if the URL fails SSRF host validation.
    Returns HTTP 429 if the per-user target limit is reached.
    """
    ip = request.client.host if request.client else None
    try:
        target = await monitoring_service.register_target(
            session=db,
            data=payload,
            current_user=current_user,
            ip_address=ip,
        )
        return MonitoringTargetResponse.model_validate(target)
    except MonitorLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)
        )
    except MonitorSSRFError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    except MonitorValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── GET /v1/monitor/targets ────────────────────────────────────────────────────

@targets_router.get("", response_model=MonitoringTargetListResponse)
@limiter.limit("60/minute")
async def list_targets(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    include_inactive: bool = Query(False, description="Include deactivated targets"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetListResponse:
    """List monitoring targets owned by the current user, paginated."""
    try:
        return await monitoring_service.list_targets(
            session=db,
            current_user=current_user,
            page=page,
            page_size=page_size,
            include_inactive=include_inactive,
        )
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── GET /v1/monitor/targets/{target_uuid} ─────────────────────────────────────

@targets_router.get("/{target_uuid}", response_model=MonitoringTargetResponse)
@limiter.limit("120/minute")
async def get_target(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetResponse:
    """Retrieve a monitoring target by UUID (owner-scoped)."""
    try:
        target = await monitoring_service.get_target_by_uuid(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
        )
        return MonitoringTargetResponse.model_validate(target)
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── PATCH /v1/monitor/targets/{target_uuid} ───────────────────────────────────

@targets_router.patch("/{target_uuid}", response_model=MonitoringTargetResponse)
@limiter.limit("30/minute")
async def update_target(
    request: Request,
    target_uuid: str,
    payload: MonitoringTargetUpdate = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetResponse:
    """Update check interval or activation state of a monitoring target."""
    ip = request.client.host if request.client else None
    try:
        target = await monitoring_service.update_target(
            session=db,
            target_uuid=target_uuid,
            data=payload,
            current_user=current_user,
            ip_address=ip,
        )
        return MonitoringTargetResponse.model_validate(target)
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── DELETE /v1/monitor/targets/{target_uuid} ──────────────────────────────────

@targets_router.delete("/{target_uuid}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("30/minute")
async def delete_target(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Soft-delete (deactivate) a monitoring target.

    The row is preserved for audit history; only `is_active` is set to False.
    Returns HTTP 204 No Content on success.
    """
    ip = request.client.host if request.client else None
    try:
        await monitoring_service.delete_target(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
            ip_address=ip,
        )
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/monitor/targets/{target_uuid}/pause ──────────────────────────────

@targets_router.post("/{target_uuid}/pause", response_model=MonitoringTargetResponse)
@limiter.limit("30/minute")
async def pause_target(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetResponse:
    """Pause an active monitoring target. Returns 409 if target is auto-suspended."""
    ip = request.client.host if request.client else None
    try:
        target = await monitoring_service.pause_target(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
            ip_address=ip,
        )
        return MonitoringTargetResponse.model_validate(target)
    except MonitorTargetSuspendedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )



# ── POST /v1/monitor/targets/{target_uuid}/resume ─────────────────────────────

@targets_router.post("/{target_uuid}/resume", response_model=MonitoringTargetResponse)
@limiter.limit("30/minute")
async def resume_target(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetResponse:
    """Resume a paused monitoring target. Rejects suspended targets with HTTP 409."""
    ip = request.client.host if request.client else None
    try:
        target = await monitoring_service.resume_target(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
            ip_address=ip,
        )
        return MonitoringTargetResponse.model_validate(target)
    except MonitorTargetSuspendedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/monitor/targets/{target_uuid}/reactivate ─────────────────────────

@targets_router.post("/{target_uuid}/reactivate", response_model=MonitoringTargetResponse)
@limiter.limit("30/minute")
async def reactivate_target(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetResponse:
    """Reactivate an auto-suspended or paused target, clearing failure count."""
    ip = request.client.host if request.client else None
    try:
        target = await monitoring_service.reactivate_target(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
            ip_address=ip,
        )
        return MonitoringTargetResponse.model_validate(target)
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/monitor/targets/{target_uuid}/check-now ──────────────────────────

@targets_router.post("/{target_uuid}/check-now", response_model=CheckNowResponse)
@limiter.limit("5/minute")
async def check_now(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CheckNowResponse:
    """Request immediate execution of a target using the existing lease mechanism."""
    ip = request.client.host if request.client else None
    try:
        return await monitoring_service.trigger_check_now(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
            ip_address=ip,
        )
    except MonitorLeaseConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except MonitorTargetSuspendedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except MonitorValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── GET /v1/monitor/targets/{target_uuid}/diagnostics ─────────────────────────

@targets_router.get(
    "/{target_uuid}/diagnostics",
    response_model=MonitoringTargetDiagnosticsResponse,
)
@limiter.limit("60/minute")
async def get_diagnostics(
    request: Request,
    target_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringTargetDiagnosticsResponse:
    """Retrieve diagnostic details from the last execution of a monitoring target."""
    try:
        return await monitoring_service.get_target_diagnostics(
            session=db,
            target_uuid=target_uuid,
            current_user=current_user,
        )
    except MonitorNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except MonitorAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── GET /v1/monitor/stats ─────────────────────────────────────────────────────

@router.get("/stats", response_model=MonitoringStatsResponse)
@limiter.limit("30/minute")
async def get_monitor_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MonitoringStatsResponse:
    """Retrieve aggregate monitoring target status distribution and scheduler health."""
    try:
        return await monitoring_service.get_monitoring_stats(
            session=db,
            current_user=current_user,
        )
    except MonitorServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# Mount target sub-router
router.include_router(targets_router)

