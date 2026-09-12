"""
backend/api/routers/incidents.py
──────────────────────────────────
Sprint 5 Phase 4: Incident Management API Endpoints.

Endpoints:
  POST   /v1/incidents                       — Create a new Incident
  GET    /v1/incidents                       — List Incidents (paginated, tenant-isolated)
  GET    /v1/incidents/{incident_id}         — Get Incident details by ID or UUID
  PATCH  /v1/incidents/{incident_id}         — Update Incident (status transition, severity, etc.)
  POST   /v1/incidents/{incident_id}/alerts  — Attach Alerts to Incident
  DELETE /v1/incidents/{incident_id}/alerts/{alert_id} — Detach Alert from Incident
  GET    /v1/incidents/{incident_id}/alerts  — List Alerts attached to Incident
"""

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.core.rate_limit import limiter
from backend.database.models import User
from backend.schemas.soc import (
    AlertResponse,
    AttachAlertsRequest,
    EventSeverity,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
    IncidentUpdate,
)
from backend.services.incident_service import (
    IncidentAccessDeniedError,
    IncidentConflictError,
    IncidentNotFoundError,
    IncidentServiceError,
    IncidentValidationError,
    incident_service,
)

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


def _format_incident_response(incident) -> IncidentResponse:
    summary = incident_service.build_summary(incident)
    alerts_resp = [
        AlertResponse.model_validate(a) for a in (incident.alerts or [])
    ]
    return IncidentResponse(
        id=incident.id,
        incident_uuid=incident.incident_uuid,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        assigned_to_user_id=incident.assigned_to_user_id,
        created_by_user_id=incident.created_by_user_id,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        closed_at=incident.closed_at,
        resolution_notes=incident.resolution_notes,
        alert_count=len(alerts_resp),
        alerts=alerts_resp,
        summary=summary,
    )


# ── POST /v1/incidents ─────────────────────────────────────────────────────────

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def create_incident(
    request: Request,
    payload: IncidentCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentResponse:
    """Create a new Security Incident."""
    try:
        ip = request.client.host if request.client else None
        incident = await incident_service.create_incident(
            session=db,
            data=payload,
            current_user=current_user,
            ip_address=ip,
        )
        return _format_incident_response(incident)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except IncidentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except IncidentValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except IncidentConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except IncidentServiceError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


# ── GET /v1/incidents ──────────────────────────────────────────────────────────

@router.get("", response_model=list[IncidentResponse])
@limiter.limit("60/minute")
async def list_incidents(
    request: Request,
    status_filter: IncidentStatus | None = Query(None, alias="status", description="Filter by status"),
    severity_filter: EventSeverity | None = Query(None, alias="severity", description="Filter by severity"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[IncidentResponse]:
    """List incidents with multi-tenant isolation and pagination."""
    try:
        offset = (page - 1) * size
        incidents, _ = await incident_service.list_incidents(
            session=db,
            current_user=current_user,
            status=status_filter.value if status_filter else None,
            severity=severity_filter.value if severity_filter else None,
            limit=size,
            offset=offset,
        )
        return [_format_incident_response(inc) for inc in incidents]
    except IncidentServiceError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


# ── GET /v1/incidents/{incident_id} ─────────────────────────────────────────────

@router.get("/{incident_id}", response_model=IncidentResponse)
@limiter.limit("60/minute")
async def get_incident(
    request: Request,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentResponse:
    """Retrieve an incident by integer ID or UUID."""
    try:
        incident = await incident_service.get_incident(
            session=db,
            incident_id_or_uuid=incident_id,
            current_user=current_user,
        )
        return _format_incident_response(incident)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except IncidentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except IncidentValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# ── PATCH /v1/incidents/{incident_id} ───────────────────────────────────────────

@router.patch("/{incident_id}", response_model=IncidentResponse)
@limiter.limit("30/minute")
async def update_incident(
    request: Request,
    incident_id: str,
    payload: IncidentUpdate = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentResponse:
    """Update an incident (title, description, severity, status transition, assignment)."""
    try:
        ip = request.client.host if request.client else None
        incident = await incident_service.update_incident(
            session=db,
            incident_id_or_uuid=incident_id,
            update_data=payload,
            current_user=current_user,
            ip_address=ip,
        )
        return _format_incident_response(incident)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except IncidentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except IncidentValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except IncidentConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


# ── POST /v1/incidents/{incident_id}/alerts ─────────────────────────────────────

@router.post("/{incident_id}/alerts", response_model=IncidentResponse)
@limiter.limit("30/minute")
async def attach_alerts(
    request: Request,
    incident_id: str,
    payload: AttachAlertsRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentResponse:
    """Attach one or more Alert IDs to an incident."""
    try:
        ip = request.client.host if request.client else None
        incident = await incident_service.attach_alerts(
            session=db,
            incident_id_or_uuid=incident_id,
            alert_ids=payload.alert_ids,
            current_user=current_user,
            ip_address=ip,
        )
        return _format_incident_response(incident)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except IncidentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except IncidentValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except IncidentConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


# ── DELETE /v1/incidents/{incident_id}/alerts/{alert_id} ───────────────────────

@router.delete("/{incident_id}/alerts/{alert_id}", response_model=IncidentResponse)
@limiter.limit("30/minute")
async def detach_alert(
    request: Request,
    incident_id: str,
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentResponse:
    """Detach a single Alert from an Incident."""
    try:
        ip = request.client.host if request.client else None
        incident = await incident_service.detach_alert(
            session=db,
            incident_id_or_uuid=incident_id,
            alert_id=alert_id,
            current_user=current_user,
            ip_address=ip,
        )
        return _format_incident_response(incident)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except IncidentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


# ── GET /v1/incidents/{incident_id}/alerts ─────────────────────────────────────

@router.get("/{incident_id}/alerts", response_model=list[AlertResponse])
@limiter.limit("60/minute")
async def get_incident_alerts(
    request: Request,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AlertResponse]:
    """Retrieve all alerts attached to a specific Incident."""
    try:
        incident = await incident_service.get_incident(
            session=db,
            incident_id_or_uuid=incident_id,
            current_user=current_user,
        )
        return [AlertResponse.model_validate(a) for a in (incident.alerts or [])]
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except IncidentAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
