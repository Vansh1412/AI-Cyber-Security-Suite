"""
backend/api/routers/alerts.py
─────────────────────────────
Sprint 5 Phase 5C: Security Alert Management and Triage REST API.

Endpoints (all require Bearer authentication):
  GET   /v1/alerts                        — List own alerts (or all if admin), paginated & filtered
  GET   /v1/alerts/stats                  — Aggregated alert metrics, velocity, and dedup ratio
  GET   /v1/alerts/{alert_uuid}           — Get full alert detail (tenant-scoped)
  POST  /v1/alerts/{alert_uuid}/acknowledge — Claim/acknowledge alert
  POST  /v1/alerts/{alert_uuid}/resolve   — Resolve alert
  POST  /v1/alerts/{alert_uuid}/dismiss   — Dismiss alert (requires dismiss_reason)
  POST  /v1/alerts/{alert_uuid}/reopen    — Reopen alert back to OPEN

Security & Multi-Tenancy:
  - All endpoints require get_current_user.
  - Queries are server-side filtered by current_user.id unless current_user.role == "admin".
  - Knowledge of alert_uuid does not bypass authorization: foreign tenant access returns 404.
"""


from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.core.rate_limit import limiter
from backend.database.models import User
from backend.schemas.alerts import (
    AlertAcknowledgeRequest,
    AlertDismissRequest,
    AlertListResponse,
    AlertReopenRequest,
    AlertResolveRequest,
    AlertResponse,
    AlertStatsResponse,
)
from backend.services.alert_service import (
    AlertAccessDeniedError,
    AlertInvalidTransitionError,
    AlertNotFoundError,
    AlertServiceError,
    AlertValidationError,
    alert_service,
)

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


# ── GET /v1/alerts ─────────────────────────────────────────────────────────────

@router.get("", response_model=AlertListResponse)
@limiter.limit("60/minute")
async def list_alerts(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(None, description="Filter by severity (e.g. HIGH, CRITICAL)"),
    status: str | None = Query(None, description="Filter by alert status (OPEN, ACKNOWLEDGED, RESOLVED, DISMISSED)"),
    rule_name: str | None = Query(None, description="Filter by detection rule"),
    indicator_type: str | None = Query(None, description="Filter by indicator type"),
    incident_id: int | None = Query(None, description="Filter by linked incident ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertListResponse:
    """List security alerts scoped to current tenant (or all for admin), paginated."""
    try:
        return await alert_service.list_alerts(
            session=db,
            current_user=current_user,
            page=page,
            page_size=page_size,
            severity=severity,
            status=status,
            rule_name=rule_name,
            indicator_type=indicator_type,
            incident_id=incident_id,
        )
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── GET /v1/alerts/stats ───────────────────────────────────────────────────────

@router.get("/stats", response_model=AlertStatsResponse)
@limiter.limit("30/minute")
async def get_alert_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertStatsResponse:
    """Retrieve aggregated alert counts, 24-hour velocity, and deduplication ratio."""
    try:
        return await alert_service.get_alert_stats(
            session=db,
            current_user=current_user,
        )
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── GET /v1/alerts/{alert_uuid} ───────────────────────────────────────────────

@router.get("/{alert_uuid}", response_model=AlertResponse)
@limiter.limit("120/minute")
async def get_alert_detail(
    request: Request,
    alert_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Retrieve complete details for a single alert (tenant-scoped)."""
    try:
        alert = await alert_service.get_alert_by_uuid(
            session=db,
            alert_uuid=alert_uuid,
            current_user=current_user,
        )
        return AlertResponse.model_validate(alert)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except AlertAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/alerts/{alert_uuid}/acknowledge ──────────────────────────────────

@router.post("/{alert_uuid}/acknowledge", response_model=AlertResponse)
@limiter.limit("30/minute")
async def acknowledge_alert(
    request: Request,
    alert_uuid: str,
    payload: AlertAcknowledgeRequest | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Acknowledge/claim an alert for active investigation."""
    ip = request.client.host if request.client else None
    notes = payload.notes if payload else None
    try:
        alert = await alert_service.acknowledge_alert(
            session=db,
            alert_uuid=alert_uuid,
            current_user=current_user,
            notes=notes,
            ip_address=ip,
        )
        return AlertResponse.model_validate(alert)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except AlertInvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except AlertAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/alerts/{alert_uuid}/resolve ──────────────────────────────────────

@router.post("/{alert_uuid}/resolve", response_model=AlertResponse)
@limiter.limit("30/minute")
async def resolve_alert(
    request: Request,
    alert_uuid: str,
    payload: AlertResolveRequest | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Transition an alert to RESOLVED with optional resolution notes."""
    ip = request.client.host if request.client else None
    notes = payload.resolution_notes if payload else None
    try:
        alert = await alert_service.resolve_alert(
            session=db,
            alert_uuid=alert_uuid,
            current_user=current_user,
            notes=notes,
            ip_address=ip,
        )
        return AlertResponse.model_validate(alert)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except AlertInvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except AlertAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/alerts/{alert_uuid}/dismiss ──────────────────────────────────────

@router.post("/{alert_uuid}/dismiss", response_model=AlertResponse)
@limiter.limit("30/minute")
async def dismiss_alert(
    request: Request,
    alert_uuid: str,
    payload: AlertDismissRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Dismiss an alert as false positive or accepted benign risk."""
    ip = request.client.host if request.client else None
    try:
        alert = await alert_service.dismiss_alert(
            session=db,
            alert_uuid=alert_uuid,
            current_user=current_user,
            reason=payload.dismiss_reason,
            notes=payload.triage_notes or payload.notes,
            ip_address=ip,
        )
        return AlertResponse.model_validate(alert)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except AlertInvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except AlertValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except AlertAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


# ── POST /v1/alerts/{alert_uuid}/reopen ───────────────────────────────────────

@router.post("/{alert_uuid}/reopen", response_model=AlertResponse)
@limiter.limit("30/minute")
async def reopen_alert(
    request: Request,
    alert_uuid: str,
    payload: AlertReopenRequest | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Reopen a resolved, dismissed, or acknowledged alert back to OPEN."""
    ip = request.client.host if request.client else None
    notes = payload.reopen_notes if payload else None
    try:
        alert = await alert_service.reopen_alert(
            session=db,
            alert_uuid=alert_uuid,
            current_user=current_user,
            notes=notes,
            ip_address=ip,
        )
        return AlertResponse.model_validate(alert)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except AlertInvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except AlertAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except AlertServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )
