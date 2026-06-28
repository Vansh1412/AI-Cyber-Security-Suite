"""
backend/api/routers/health.py
──────────────────────────────
Deep health check endpoint.
Verifies database, redis, model, and system memory.
"""

import psutil
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from backend.core.config import settings
from backend.services.cache import cache_service
from backend.api.dependencies import get_db, get_prediction_service
from backend.core.rate_limit import limiter

router = APIRouter()


@router.get("/health", tags=["Health"])
@limiter.limit("60/minute")
async def health_check(
    request: Request,
    db: AsyncSession = Depends(get_db),
    pred_svc = Depends(get_prediction_service)
):
    # 1. Database Check
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    # 2. Redis Check
    redis_status = "connected" if cache_service.available else "disconnected"

    # 3. Model Check
    model_status = "loaded" if getattr(pred_svc, "model", None) else "unloaded"

    # 4. System Memory
    mem = psutil.virtual_memory()
    memory_usage = f"{mem.percent}%"

    overall_status = "healthy" if db_status == "connected" and model_status == "loaded" else "degraded"

    return {
        "status": overall_status,
        "database": db_status,
        "redis": redis_status,
        "model": model_status,
        "version": settings.VERSION,
        "memory": memory_usage,
    }
