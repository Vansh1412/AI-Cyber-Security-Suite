"""
backend/api/routers/history.py
───────────────────────────────
GET /v1/history         — paginated scan history for current user
GET /v1/history/{id}   — single scan detail with SHAP reasons
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.database.models import ScanResult, User
from backend.schemas.payload import HistoryItem
from backend.api.dependencies import get_db, get_current_user
from backend.core.rate_limit import limiter

router = APIRouter(prefix="/history", tags=["History"])


@router.get("", response_model=list[HistoryItem])
@limiter.limit("30/minute")
async def get_history(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns the authenticated user's scan history (newest first)."""
    offset = (page - 1) * size
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .offset(offset)
        .limit(size)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=HistoryItem)
@limiter.limit("60/minute")
async def get_scan_detail(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns full detail of a single scan including SHAP top_reasons."""
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
