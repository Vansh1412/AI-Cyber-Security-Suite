"""
tests/integration/test_health_probes.py
───────────────────────────────────────
Phase 7 Plan 01: Tiered Health Check Probes Integration Tests.

Validates Decision D-11:
  - GET /v1/health/live: lightweight liveness probe (HTTP 200, no DB/Redis I/O).
  - GET /v1/health/ready: deep readiness probe with bounded timeouts:
      - HTTP 200 'ready' when both DB and Redis ping succeed.
      - HTTP 200 'degraded' when DB succeeds but Redis ping fails.
      - HTTP 503 'unhealthy' when DB fails or times out.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_db
from backend.database.models import Base
from backend.main import app
from backend.services.cache import cache_service


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(async_engine):
    return async_sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def client(session_factory):
    async def _get_db_override():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_liveness_probe_returns_200(client):
    """GET /v1/health/live returns HTTP 200 with status: 'live' and ISO timestamp."""
    response = await client.get("/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "live"
    assert "timestamp" in data
    assert "database" not in data
    assert "redis" not in data


@pytest.mark.anyio
async def test_readiness_probe_healthy(client):
    """GET /v1/health/ready returns HTTP 200 with status 'ready' when DB and Redis are responsive."""
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)

    with patch.object(cache_service, "_client", mock_redis):
        response = await client.get("/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["redis"] == "connected"
        assert data["message"] == "All systems operational"
        mock_redis.ping.assert_awaited_once()


@pytest.mark.anyio
async def test_readiness_probe_degraded_when_redis_offline(client):
    """GET /v1/health/ready returns HTTP 200 with status 'degraded' when Redis ping fails."""
    # Subtest 1: _client is None
    with patch.object(cache_service, "_client", None):
        response = await client.get("/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["database"] == "connected"
        assert data["redis"] == "disconnected"
        assert "fallback" in data["message"].lower()

    # Subtest 2: _client ping raises Exception
    mock_failing_redis = AsyncMock()
    mock_failing_redis.ping = AsyncMock(side_effect=ConnectionError("Redis connection refused"))
    with patch.object(cache_service, "_client", mock_failing_redis):
        response = await client.get("/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["database"] == "connected"
        assert data["redis"] == "disconnected"


@pytest.mark.anyio
async def test_readiness_probe_fails_503_when_db_down():
    """GET /v1/health/ready returns HTTP 503 when PostgreSQL DB is unreachable or times out."""
    async def _failing_db_override():
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute = AsyncMock(side_effect=TimeoutError("DB query timed out"))
        yield mock_session

    app.dependency_overrides[get_db] = _failing_db_override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as c:
            response = await c.get("/v1/health/ready")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["database"] == "disconnected"
            assert "unreachable" in data["message"].lower()
    finally:
        app.dependency_overrides.clear()
