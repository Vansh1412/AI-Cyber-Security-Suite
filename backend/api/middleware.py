"""
backend/api/middleware.py
──────────────────────────
Request timing and CORS middleware.
"""

import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware


class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        process_time = round((time.perf_counter() - t0) * 1000, 2)
        response.headers["X-Process-Time-Ms"] = str(process_time)
        return response
