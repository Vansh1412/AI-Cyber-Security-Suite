# Phase 07: Production Hardening & Staging Parity - Pattern Map

**Phase:** 07 - production-hardening-staging-parity  
**Generated:** 2026-09-30  

---

## 1. Component & File Analog Matrix

| Target File | Architectural Role | Closest Analog | Codebase Pattern / Excerpt Source |
|---|---|---|---|
| `backend/api/routers/health.py` | API Health Endpoints | `backend/api/routers/health.py` | Existing `/health` endpoint using `db.execute(text("SELECT 1"))` and `cache_service.available` |
| `docker-compose.prod.yml` | Production Orchestration | `docker-compose.yml`, `docker-compose.staging.yml` | Healthcheck definitions, environment mapping, dependency chaining (`condition: service_healthy`) |
| `nginx/nginx.conf` | Reverse Proxy & SSE Gateway | `docker/prometheus.yml`, `docs/DEPLOYMENT.md` | Stream routing to `http://api:8000/v1/streams/` with `proxy_buffering off;` |
| `requirements.txt` | Dependency Specification | `requirements.txt` | Sectioned pip requirements list; removing `pyarrow` while retaining all active core and ML libs |
| `tests/staging/test_postgres_staging_concurrency.py` | PostgreSQL Staging Concurrency | `tests/staging/test_postgres_staging_concurrency.py` | Existing `pg_engine` fixture with graceful `pytest.skip` on connection failure; advisory locks |
| `tests/staging/test_redis_failover_degradation.py` | Redis Failover Staging Test | `backend/services/cache.py`, `tests/integration/test_phase5c_concurrency.py` | Monkeypatching or stopping Redis connection and asserting API returns HTTP 200 degraded |
| `tests/integration/test_health_probes.py` | Integration Test: Tiered Probes | `tests/integration/test_containment_api.py` | `httpx.AsyncClient` with `ASGITransport(app=app)` and SQLite/mock session override |
| `tests/integration/test_multitenant_adversarial.py` | Cross-Tenant Isolation Suite | `tests/integration/test_containment_api.py` | Multi-tenant seeded users (`User A: id=1`, `User B: id=2`, `Admin: id=3`) asserting 403/404 |
| `tests/integration/test_soc_e2e_lifecycle.py` | Full SOC Lifecycle E2E Suite | `tests/integration/test_containment_api.py`, `tests/integration/test_sse_streams_api.py` | Scan execution -> Event bus -> Alert creation -> Incident escalation -> Containment action -> SSE stream verification |

---

## 2. Concrete Code Excerpts & Patterns

### Pattern A: Health Probe Structure
From `backend/api/routers/health.py`:
```python
# Existing:
@router.get("/health", tags=["Health"])
async def health_check(...):
    # db check via SELECT 1
    # redis check via cache_service.available

# Target Analog Pattern for /health/live and /health/ready:
@router.get("/health/live", tags=["Health"])
async def liveness():
    return {"status": "live", "timestamp": datetime.now(timezone.utc).isoformat()}

@router.get("/health/ready", tags=["Health"])
async def readiness(db: AsyncSession = Depends(get_db)):
    ...
```

### Pattern B: Staging Connection & Graceful Skip Fixture
From `tests/staging/test_postgres_staging_concurrency.py`:
```python
@pytest.fixture
async def pg_engine():
    engine = create_async_engine(STAGING_PG_URL, echo=False, pool_pre_ping=True)
    try:
        async with asyncio.timeout(1.5):
            async with engine.connect() as conn:
                res = await conn.execute(text("SELECT version();"))
                version_str = res.scalar()
                if not version_str or "PostgreSQL" not in version_str:
                    pytest.skip("Not connected to PostgreSQL database.")
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"PostgreSQL 16 staging container is not running ({exc}).")
    ...
```

### Pattern C: Multi-Tenant Adversarial Matrix Fixture
From `tests/integration/test_containment_api.py`:
```python
@pytest.fixture
async def seeded_session(session_factory):
    async with session_factory() as session:
        u1 = User(id=1, email="tenant1@soc.test", hashed_pw="pw1", role="user", is_active=True)
        u2 = User(id=2, email="tenant2@soc.test", hashed_pw="pw2", role="user", is_active=True)
        admin = User(id=3, email="admin@soc.test", hashed_pw="pwa", role="admin", is_active=True)
        session.add_all([u1, u2, admin])
        await session.commit()
```

### Pattern D: Nginx Location with SSE Buffering Disabled
```nginx
location /v1/streams/ {
    proxy_pass http://api:8000/v1/streams/;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_cache off;
    chunked_transfer_encoding off;
    proxy_read_timeout 86400s;
}
```
