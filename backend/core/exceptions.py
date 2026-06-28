"""
backend/core/exceptions.py
───────────────────────────
Custom HTTP exception handlers.
"""

from fastapi import Request
from fastapi.responses import JSONResponse


async def validation_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc), "url": str(request.url)},
    )


async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )
