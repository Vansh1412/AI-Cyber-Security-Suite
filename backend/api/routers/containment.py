"""
backend/api/routers/containment.py
──────────────────────────────────
Sprint 5 Phase 5F: REST API for Automated Threat Containment & SOAR Playbooks.

Endpoints:
  POST  /v1/soc/actions/contain         — Manually invoke containment action
  GET   /v1/soc/actions                 — List paginated containment actions
  GET   /v1/soc/actions/{action_uuid}   — Get containment action details (anti-enumeration 404)
  POST  /v1/soc/actions/{action_uuid}/revert — Idempotently rollback containment action
  GET   /v1/soc/playbooks/runs          — List paginated playbook runs
  GET   /v1/soc/containment/policy      — Get tenant containment policy
  PUT   /v1/soc/containment/policy      — Update tenant containment policy (optimistic locking)
"""

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.core.rate_limit import limiter
from backend.database.models import SOCContainmentAction, SOCPlaybookRun, User
from backend.schemas.containment import (
    ContainmentActionResponse,
    ContainmentPolicyResponse,
    ContainmentPolicyUpdate,
    ContainmentRequest,
    PaginatedContainmentActions,
    PaginatedPlaybookRuns,
    PlaybookRunResponse,
)
from backend.services.containment_service import containment_service
from src.utils.logger import logger

router = APIRouter(prefix="/soc", tags=["SOC Containment & SOAR"])


# ── POST /v1/soc/actions/contain ──────────────────────────────────────────────

@router.post(
    "/actions/contain",
    response_model=ContainmentActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invoke Containment Action",
    description="Manually invoke a typed containment action (e.g. BLACKLIST_INDICATOR, QUARANTINE_TARGET).",
)
@limiter.limit("20/minute")
async def contain_action(
    request: Request,
    body: ContainmentRequest = Body(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ContainmentActionResponse:
    try:
        action = await containment_service.execute_action(
            session=session,
            action_type=body.action_type,
            target_identifier=body.target_identifier,
            tenant_id=current_user.id,
            trigger_source="manual_analyst",
            alert_id=body.alert_id,
            actor_user_id=current_user.id,
            reason=body.reason,
        )
        await session.commit()
        return ContainmentActionResponse.model_validate(action)
    except HTTPException:
        raise
    except Exception as exc:
        await session.rollback()
        logger.error("[API] Containment action failed for user %d: %s", current_user.id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute containment action.",
        )


# ── GET /v1/soc/actions ───────────────────────────────────────────────────────

@router.get(
    "/actions",
    response_model=PaginatedContainmentActions,
    summary="List Containment Actions",
    description="Retrieve paginated list of containment actions scoped strictly to authenticated tenant.",
)
@limiter.limit("60/minute")
async def list_actions(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    action_type: str | None = Query(default=None, description="Filter by action type"),
    action_status: str | None = Query(default=None, alias="status", description="Filter by action status"),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> PaginatedContainmentActions:
    try:
        query = select(SOCContainmentAction).where(SOCContainmentAction.tenant_id == current_user.id)
        if action_type:
            query = query.where(SOCContainmentAction.action_type == action_type)
        if action_status:
            query = query.where(SOCContainmentAction.status == action_status)

        # Count total
        count_stmt = select(func.count()).select_from(query.subquery())
        total_res = await session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        # Fetch page
        offset = (page - 1) * page_size
        paged_query = query.order_by(SOCContainmentAction.created_at.desc()).offset(offset).limit(page_size)
        items_res = await session.execute(paged_query)
        items = items_res.scalars().all()

        return PaginatedContainmentActions(
            items=[ContainmentActionResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        logger.error("[API] Failed to list containment actions for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve containment actions.",
        )


# ── GET /v1/soc/actions/{action_uuid} ─────────────────────────────────────────

@router.get(
    "/actions/{action_uuid}",
    response_model=ContainmentActionResponse,
    summary="Get Containment Action Details",
    description="Retrieve details of a specific containment action. Returns 404 for foreign tenant actions.",
)
@limiter.limit("60/minute")
async def get_action(
    request: Request,
    action_uuid: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ContainmentActionResponse:
    stmt = select(SOCContainmentAction).where(SOCContainmentAction.action_uuid == action_uuid)
    res = await session.execute(stmt)
    action = res.scalar_one_or_none()

    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Containment action not found")

    # Anti-enumeration tenant boundary check
    if action.tenant_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Containment action not found")

    return ContainmentActionResponse.model_validate(action)


# ── POST /v1/soc/actions/{action_uuid}/revert ─────────────────────────────────

@router.post(
    "/actions/{action_uuid}/revert",
    response_model=ContainmentActionResponse,
    summary="Revert Containment Action",
    description="Idempotently revert an executed containment action. Only removes action-owned entries.",
)
@limiter.limit("20/minute")
async def revert_action(
    request: Request,
    action_uuid: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ContainmentActionResponse:
    try:
        action = await containment_service.revert_action(
            session=session,
            action_uuid=action_uuid,
            current_user=current_user,
        )
        return ContainmentActionResponse.model_validate(action)
    except HTTPException:
        raise
    except Exception as exc:
        await session.rollback()
        logger.error("[API] Failed to revert action %s: %s", action_uuid, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revert containment action.",
        )


# ── GET /v1/soc/playbooks/runs ────────────────────────────────────────────────

@router.get(
    "/playbooks/runs",
    response_model=PaginatedPlaybookRuns,
    summary="List Playbook Runs",
    description="Retrieve paginated list of playbook execution runs for the tenant.",
)
@limiter.limit("60/minute")
async def list_playbook_runs(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    run_status: str | None = Query(default=None, alias="status", description="Filter by run status"),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> PaginatedPlaybookRuns:
    try:
        query = select(SOCPlaybookRun).where(SOCPlaybookRun.tenant_id == current_user.id)
        if run_status:
            query = query.where(SOCPlaybookRun.status == run_status)

        count_stmt = select(func.count()).select_from(query.subquery())
        total_res = await session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        offset = (page - 1) * page_size
        paged_query = query.order_by(SOCPlaybookRun.started_at.desc()).offset(offset).limit(page_size)
        items_res = await session.execute(paged_query)
        items = items_res.scalars().all()

        return PaginatedPlaybookRuns(
            items=[PlaybookRunResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        logger.error("[API] Failed to list playbook runs for user %d: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve playbook runs.",
        )


# ── GET /v1/soc/containment/policy ────────────────────────────────────────────

@router.get(
    "/containment/policy",
    response_model=ContainmentPolicyResponse,
    summary="Get Containment Policy",
    description="Retrieve the current automated containment policy for the authenticated tenant.",
)
@limiter.limit("60/minute")
async def get_policy(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ContainmentPolicyResponse:
    policy = await containment_service.get_or_create_policy(session, current_user.id)
    return ContainmentPolicyResponse.model_validate(policy)


# ── PUT /v1/soc/containment/policy ────────────────────────────────────────────

@router.put(
    "/containment/policy",
    response_model=ContainmentPolicyResponse,
    summary="Update Containment Policy",
    description="Update the automated containment policy with optimistic concurrency control.",
)
@limiter.limit("20/minute")
async def update_policy(
    request: Request,
    body: ContainmentPolicyUpdate = Body(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ContainmentPolicyResponse:
    try:
        policy = await containment_service.update_policy(
            session=session,
            tenant_id=current_user.id,
            update_data=body,
            user_id=current_user.id,
        )
        return ContainmentPolicyResponse.model_validate(policy)
    except HTTPException:
        raise
    except Exception as exc:
        await session.rollback()
        logger.error("[API] Failed to update policy for user %d: %s", current_user.id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update containment policy.",
        )
