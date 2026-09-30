"""
backend/api/routers/health.py
──────────────────────────────
Tiered and deep health check endpoints.
Verifies liveness, readiness (database, redis with bounded timeouts), and system memory.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import psutil
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db, get_prediction_service
from backend.core.config import settings
from backend.core.rate_limit import limiter
from backend.services.cache import cache_service

router = APIRouter()


@router.get("/health/live", tags=["Health"])
async def liveness_probe():
    """
    Lightweight process liveness probe for container orchestrators.
    Returns HTTP 200 immediately without querying DB or cache.
    """
    return {
        "status": "live",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/ready", tags=["Health"])
async def readiness_probe(
    db: AsyncSession = Depends(get_db),
):
    """
    Deep readiness probe checking core dependencies (PostgreSQL & Redis)
    with bounded timeouts.
    """
    # 1. Database Check (Critical - 2.0s timeout)
    db_ok = False
    try:
        async with asyncio.timeout(2.0):
            await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    # 2. Redis Check (Non-critical fallback - 1.0s timeout)
    redis_ok = False
    if cache_service._client is not None:
        try:
            async with asyncio.timeout(1.0):
                await cache_service._client.ping()
            redis_ok = True
        except Exception:
            redis_ok = False

    db_status = "connected" if db_ok else "disconnected"
    redis_status = "connected" if redis_ok else "disconnected"

    if not db_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "database": db_status,
                "redis": redis_status,
                "message": "Critical dependency failure: PostgreSQL database is unreachable.",
            },
        )

    if not redis_ok:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "degraded",
                "database": db_status,
                "redis": redis_status,
                "message": "Running with in-memory fallback (Redis offline)",
            },
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ready",
            "database": db_status,
            "redis": redis_status,
            "message": "All systems operational",
        },
    )


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
