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

from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.api.dependencies import (
    get_explainer_service,
    get_feature_service,
    get_prediction_service,
)
from backend.api.middleware import TimingMiddleware
from backend.api.routers import (
    alerts,
    analytics,
    auth,
    download,
    explain,
    health,
    history,
    incidents,
    intel,
    investigate,
    mlops,
    monitor,
    notifications,
    scan,
    stats,
    streams,
)
from backend.core.config import settings
from backend.core.exceptions import general_exception_handler
from backend.core.rate_limit import limiter
from backend.database.session import init_db
from backend.services.cache import cache_service
from backend.services.event_broadcaster import event_broadcaster
from backend.services.monitoring_engine import monitoring_engine
from backend.services.notification_dispatcher import notification_dispatcher
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

    # Sprint 5 Phase 5B: Monitoring Engine Lifespan Integration
    await monitoring_engine.start()

    # Sprint 5 Phase 5D: Notification Dispatcher Lifespan Integration
    await notification_dispatcher.start()

    # Sprint 5 Phase 5E: Event Broadcaster Lifespan Integration
    await event_broadcaster.start()

    yield

    logger.info("Shutting down API...")
    await event_broadcaster.stop()
    await notification_dispatcher.stop()
    await monitoring_engine.stop()
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
app.include_router(health.router,       prefix=settings.API_V1_STR)
app.include_router(auth.router,         prefix=settings.API_V1_STR)
app.include_router(scan.router,         prefix=settings.API_V1_STR)
app.include_router(explain.router,      prefix=settings.API_V1_STR)
app.include_router(history.router,      prefix=settings.API_V1_STR)
app.include_router(stats.router,        prefix=settings.API_V1_STR)
app.include_router(download.router,     prefix=settings.API_V1_STR)
app.include_router(mlops.router,        prefix=settings.API_V1_STR)
# Sprint 4 routers
app.include_router(intel.router,        prefix=settings.API_V1_STR)
app.include_router(analytics.router,    prefix=settings.API_V1_STR)
app.include_router(investigate.router,  prefix=settings.API_V1_STR)
# Sprint 5 Phase 4 router
app.include_router(incidents.router,    prefix=settings.API_V1_STR)
# Sprint 5 Phase 5A router
app.include_router(monitor.router,      prefix=settings.API_V1_STR)
# Sprint 5 Phase 5E router (mounted before alerts/notifications to prevent /{uuid} capture)
app.include_router(streams.router,       prefix=settings.API_V1_STR)
# Sprint 5 Phase 5C router
app.include_router(alerts.router,        prefix=settings.API_V1_STR)
# Sprint 5 Phase 5D router
app.include_router(notifications.router, prefix=settings.API_V1_STR)




if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
