"""
backend/api/routers/stats.py
────────────────────────────
GET /v1/stats — Aggregated scan statistics for the current user.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, cast, Date

from backend.database.models import ScanResult, User
from backend.schemas.payload import StatsResponse
from backend.api.dependencies import get_db, get_current_user
from backend.core.rate_limit import limiter

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("", response_model=StatsResponse)
@limiter.limit("20/minute")
async def get_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns aggregated scan statistics for the authenticated user."""
    # 1. Total Scans
    total_result = await db.execute(
        select(func.count(ScanResult.id)).where(ScanResult.user_id == current_user.id)
    )
    total_scans = total_result.scalar() or 0

    # 2. Scans by class
    by_class_result = await db.execute(
        select(ScanResult.prediction, func.count(ScanResult.id))
        .where(ScanResult.user_id == current_user.id)
        .group_by(ScanResult.prediction)
    )
    by_class = {row[0]: row[1] for row in by_class_result.all()}

    # 3. Daily volume (cast datetime to Date for grouping)
    # Using SQLite/Postgres compatible date truncation
    daily_result = await db.execute(
        select(cast(ScanResult.created_at, Date).label('date'), func.count(ScanResult.id))
        .where(ScanResult.user_id == current_user.id)
        .group_by('date')
        .order_by('date')
    )
    daily_volume = [
        {"date": row.date.isoformat(), "count": row[1]} 
        for row in daily_result.all()
    ]

    return StatsResponse(
        total_scans=total_scans,
        by_class=by_class,
        daily_volume=daily_volume
    )
