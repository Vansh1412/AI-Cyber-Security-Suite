"""
backend/main.py
────────────────
FastAPI application entry point.

Startup:
  - Initialises all singleton services
  - Configures OpenTelemetry, Request IDs, and Rate Limiting
  - Registers routers and middleware
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from asgi_correlation_id import CorrelationIdMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from backend.core.config import settings
from backend.core.rate_limit import limiter
from backend.core.exceptions import general_exception_handler
from backend.api.middleware import TimingMiddleware
from backend.api.routers import health, scan, explain, auth, history, stats
from backend.api.dependencies import (
    get_feature_service,
    get_prediction_service,
    get_explainer_service,
)
from backend.database.session import init_db
from backend.services.cache import cache_service
from src.utils.logger import logger



@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up AI Cyber Security Suite API v%s...", settings.VERSION)
    
    if "sqlite" in settings.DATABASE_URL:
        await init_db()
        logger.info("SQLite database tables verified/created.")

    await cache_service.connect()

    get_feature_service()
    get_prediction_service()
    get_explainer_service()
    logger.info("ML Services pre-warmed.")

    yield

    logger.info("Shutting down API...")
    await cache_service.disconnect()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Advanced Enterprise URL Threat Detection API.",
    docs_url=f"{settings.API_V1_STR}/docs",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# ── State / Rate Limiting ─────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(TimingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Observability ─────────────────────────────────────────────────────────────
Instrumentator().instrument(app).expose(app, endpoint="/metrics")
FastAPIInstrumentor.instrument_app(app)

# ── Exception Handlers ────────────────────────────────────────────────────────
app.add_exception_handler(Exception, general_exception_handler)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router,  prefix=settings.API_V1_STR)
app.include_router(auth.router,    prefix=settings.API_V1_STR)
app.include_router(scan.router,    prefix=settings.API_V1_STR)
app.include_router(explain.router, prefix=settings.API_V1_STR)
app.include_router(history.router, prefix=settings.API_V1_STR)
app.include_router(stats.router,   prefix=settings.API_V1_STR)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
