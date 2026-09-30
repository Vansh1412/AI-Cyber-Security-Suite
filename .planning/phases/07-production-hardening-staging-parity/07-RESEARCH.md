# Phase 07: Production Hardening & Staging Parity - Research

**Researched:** 2026-09-30  
**Domain:** PostgreSQL 16 Concurrency, Redis Failover Degradation, E2E SOC Lifecycle Integration, Nginx Hardening, Multi-Compose Orchestration  
**Confidence:** HIGH  

## User Constraints

*(Copied verbatim from `07-CONTEXT.md`)*

### Implementation Decisions

#### PostgreSQL Staging & Concurrency Strategy
- **D-01:** Dual-mode provisioning: Ephemeral Docker container managed via `docker-compose.staging.yml` by default, with `TEST_DATABASE_URL` environment override for external staging instances.
- **D-02:** Database isolation: Session-level Alembic upgrade + per-test nested transaction rollback (`SAVEPOINT`s) for maximum test isolation and execution speed.
- **D-03:** Concurrency & race condition test suite: Targeting 100 concurrent alert attachments, parallel incident status transitions, distributed monitoring lease claims, and transactional outbox batch drains.
- **D-04:** Redis failover & graceful degradation: Automated verification of graceful degradation: simulate Redis disconnection and assert all scan, event, and monitoring endpoints continue operating without HTTP 500 errors.

#### End-to-End Integration & RBAC Scope
- **D-05:** Test architecture: Comprehensive API-level integration suite using FastAPI `AsyncClient` across multiple tenants simulating the full SOC lifecycle (Scan → Alert → Incident → Containment → SSE Stream).
- **D-06:** Multi-tenant isolation: Adversarial cross-tenant fixture matrix (`User A`, `User B`, `Admin`) verifying strict HTTP 404/403 isolation across alerts, incidents, targets, and SSE streams without credential leakage.
- **D-07:** Live SSE streaming verification: Live asynchronous SSE stream consumer acquiring stream tickets, connecting to `/v1/streams/events`, and asserting in-order envelope delivery with monotonic cursor IDs.
- **D-08:** Containment reversibility: Full containment lifecycle loop: trigger incident → execute dynamic blacklist action → assert blocked state → execute atomic revert action → assert unblocked state & audit trail.

#### Production Deployment Topology
- **D-09:** Docker Compose orchestration: Multi-compose overlay setup: `docker-compose.yml` (base backend/db/redis) extended by `docker-compose.staging.yml` (ephemeral staging/test ports) and `docker-compose.prod.yml` (hardened resource limits, health checks, `restart: always`, and logging).
- **D-10:** Nginx reverse proxy & SSE streaming: Dedicated SSE location block disabling proxy buffering (`proxy_buffering off;`, `chunked_transfer_encoding off;`, `proxy_read_timeout 86400s;`) for `/v1/streams/`, with rate-limiting zones and security headers (CSP, HSTS, X-Content-Type-Options) on root `/v1/` routes.
- **D-11:** Tiered health check probes: `/v1/health/live` (lightweight process responsiveness, returns HTTP 200) and `/v1/health/ready` (validates DB connection pool and Redis ping; returns HTTP 200 with `status: "degraded"` if Redis fails, but HTTP 503 if PostgreSQL is down).
- **D-12:** Artifact preservation & audit hygiene: Strict preservation with targeted dependency hygiene: keep all retrained model checkpoints (`ml/models/store/`), reports, and telemetry abstractions fully preserved; safely remove only confirmed unused dependencies (e.g., `pyarrow`) during staging validation while keeping all Sprint 6 and core code protected.

### The Agent's Discretion
- Exact port assignments in `docker-compose.staging.yml` (e.g. host mapping 5433 to avoid conflicts with local 5432).
- Specific pytest fixture naming and setup in `tests/integration/staging/`.
- Detailed Nginx rate-limiting parameters (e.g. `limit_req_zone` burst size and rate).

### Deferred Ideas
- Full browser-based synthetic UI monitoring (Playwright/Cypress end-to-end frontend tests against staging) — deferred to a subsequent frontend polish milestone.
- Full deprecation cleanup of legacy MLflow / ONNX / psutil audit items — deferred to dedicated post-v1 maintenance sprint.

---

## Summary

Phase 7 hardens the enterprise AI Cyber Security Suite for staging parity and production deployment. The system transitions from individual unit and mock-based component tests to a unified verification regime: validating real PostgreSQL 16 row-level concurrency (`FOR UPDATE SKIP LOCKED`, advisory locking, epoch fencing), automated Redis failover degradation, multi-tenant adversarial isolation, and full end-to-end SOC lifecycle flows (Scan → Alert → Incident → Containment → SSE delivery).

In addition to test hardening, Phase 7 establishes production topology artifacts: a production Docker Compose overlay (`docker-compose.prod.yml`) featuring resource constraints, health probes, and log rotation; an enterprise Nginx reverse proxy configuration with dedicated SSE unbuffered streaming (`proxy_buffering off;`) and security headers (CSP, HSTS, X-Frame-Options); tiered liveness (`/v1/health/live`) and readiness (`/v1/health/ready`) probes in FastAPI; and targeted cleanup of unreferenced dependencies (`pyarrow`) without impacting preserved ML checkpoints and telemetry assets.

**Primary recommendation:** Build Phase 7 across three focused waves: Wave 1 for Tiered Health Probes and Deployment Orchestration (FastAPI `/live` & `/ready`, `docker-compose.prod.yml`, `nginx/nginx.conf`, dependency cleanup); Wave 2 for Dual-Mode Staging & PostgreSQL Concurrency Harness (Savepoint fixture, 100-alert concurrency, Redis failover test); and Wave 3 for Adversarial Multi-Tenant & Full SOC Lifecycle Integration Suite (E2E Scan → Alert → Incident → Containment → SSE).

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Tiered Health Probes | `backend/api/routers/health.py` | `docker-compose.*.yml` | Kubernetes/Docker healthcheck consumers require sub-10ms `/live` and deep DB/Redis dependency checks on `/ready`. |
| Production Orchestration | `docker-compose.prod.yml` | `docker/Dockerfile` | Separates development/staging convenience from hardened production configurations (CPU/RAM limits, restart policies, json logging). |
| Reverse Proxy & SSE Streaming | `nginx/nginx.conf` | `backend/api/routers/streams.py` | Nginx must disable `proxy_buffering` and extend timeouts to prevent chunk accumulation and connection drops for SSE clients. |
| Staging Parity & Concurrency Harness | `tests/staging/` | `tests/conftest.py` | Dedicated harness targeting real PostgreSQL 16 and Redis instances with graceful local skips when Docker daemon is offline. |
| Multi-Tenant Adversarial E2E | `tests/integration/` | `backend/api/middleware.py` | Exercises full SOC engine across multiple tenant tokens to guarantee isolation and zero cross-tenant leakage. |
| Dependency Hygiene | `requirements.txt` | `docker/Dockerfile` | Removes verified unused packages (`pyarrow`) reducing image size and attack surface while safeguarding ML store checkpoints. |

---

## Standard Stack

### Core
| Library / Tool | Version | Purpose | Why Standard |
|----------------|---------|---------|--------------|
| `fastapi` | `>=0.110.0` [VERIFIED: pip] | REST API & Tiered Health Probes | Modern, high-performance async framework with native OpenAPI schema generation and dependency injection. |
| `sqlalchemy[asyncio]` | `>=2.0.0` [VERIFIED: pip] | Async ORM & Concurrency Controls | Standard Python async DB layer supporting `FOR UPDATE SKIP LOCKED` and advisory locks via `asyncpg`. |
| `asyncpg` | `>=0.29.0` [VERIFIED: pip] | PostgreSQL 16 Async Driver | Binary protocol async driver with high throughput under concurrent worker contention. |
| `redis[asyncio]` | `>=5.0.0` [VERIFIED: pip] | Cache & Pub/Sub Gateway | Async Redis client with connection pooling and failover disconnect handling. |
| `alembic` | `>=1.13.0` [VERIFIED: pip] | Schema Migrations | Declarative, version-controlled migrations for PostgreSQL and SQLite schema parity. |
| `nginx` | `1.25-alpine` [VERIFIED: Dockerfile] | Reverse Proxy & TLS/SSE Gateway | Industry standard reverse proxy for unbuffered SSE streaming and HTTP header hardening. |
| `pytest` / `pytest-asyncio` | `>=8.0.0` [VERIFIED: pip] | Asynchronous Testing Suite | De-facto Python testing framework with robust async fixtures and parameterized test matrices. |
| `httpx` | `>=0.27.0` [VERIFIED: pip] | Async HTTP Client | Used with `ASGITransport` for in-process async testing and external staging health checks. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `pydantic-settings` | `>=2.0.0` | Environment configuration | Resolving `TEST_DATABASE_URL`, `STAGING_REDIS_URL`, and production secrets. |
| `psutil` | `>=5.9.0` | System metrics in deep health check | Memory and process telemetry reporting in `/health`. |
| `prometheus-fastapi-instrumentator` | `>=6.1.0` | Metrics scraping | Exporting `/metrics` for Prometheus scraping in production compose. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Nginx Reverse Proxy | Traefik / Caddy | Nginx has deterministic SSE buffering controls (`proxy_buffering off`) and universal familiarity in SOC enterprise stacks. |
| Dual-mode Staging Fixtures | Testcontainers Python | Testcontainers requires a running Docker daemon on the test host; dual-mode allows local tests to gracefully skip or connect to external staging URLs when Docker CLI is absent. |

---

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `fastapi` | PyPI | 6 yrs | >30M/mo | github.com/fastapi/fastapi | [OK] | Approved |
| `sqlalchemy` | PyPI | 18 yrs | >50M/mo | github.com/sqlalchemy/sqlalchemy | [OK] | Approved |
| `asyncpg` | PyPI | 8 yrs | >15M/mo | github.com/MagicStack/asyncpg | [OK] | Approved |
| `redis` | PyPI | 14 yrs | >40M/mo | github.com/redis/redis-py | [OK] | Approved |
| `httpx` | PyPI | 5 yrs | >40M/mo | github.com/encode/httpx | [OK] | Approved |
| `pyarrow` | PyPI | - | - | - | - | **REMOVED** (Unused dependency identified for hygiene cleanup per D-12) |

---

## Architecture Patterns

### System Architecture Diagram

```
[ Client / Browser / SOC Dashboard ]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│               Nginx Reverse Proxy: 80/443              │
│  - Security Headers (HSTS, CSP, X-Frame-Options)       │
│  - Rate Limiting Zone: 60r/m on /v1/                   │
│  - Location /v1/streams/ -> proxy_buffering off;       │
└──────────────┬─────────────────────────┬───────────────┘
               │                         │
               ▼                         ▼
┌─────────────────────────────┐   ┌──────────────────────────────┐
│  FastAPI API Server (8000)  │   │  Prometheus Metrics (9090)   │
│  - /v1/health/live  (200)   │   │  Scrapes /metrics            │
│  - /v1/health/ready (DB/R)  │   └──────────────────────────────┘
│  - /v1/scan, /v1/soc/*      │
└──────┬───────────────┬──────┘
       │               │
       ▼               ▼
┌──────────────┐ ┌─────────────┐
│ PostgreSQL 16│ │   Redis 7   │
│ (Primary DB) │ │ (PubSub/TTL)│
└──────────────┘ └─────────────┘
```

### Recommended Project Structure
```
AI-Cyber-Security-Suite/
├── backend/
│   ├── api/
│   │   └── routers/
│   │       └── health.py          # Updated with /v1/health/live and /v1/health/ready
├── docker/
│   ├── Dockerfile                 # Hardened multi-stage/production Dockerfile
│   └── prometheus.yml
├── nginx/
│   ├── nginx.conf                 # Production reverse proxy config with SSE buffering disabled
│   └── conf.d/
│       └── soc_proxy.conf         # Location blocks, rate limits, and security headers
├── docker-compose.yml             # Base orchestration (api, db, redis, prometheus)
├── docker-compose.staging.yml     # Ephemeral staging database & redis ports (5433, 6380)
├── docker-compose.prod.yml        # Hardened production overlay (resource limits, health checks)
├── requirements.txt               # Cleaned requirements (pyarrow removed)
└── tests/
    ├── staging/
    │   ├── test_postgres_staging_concurrency.py  # 100-alert race conditions, advisory locks, skip locked
    │   └── test_redis_failover_degradation.py   # Redis disconnect simulation & graceful fallback
    └── integration/
        ├── test_soc_e2e_lifecycle.py            # E2E Scan -> Alert -> Incident -> Contain -> SSE
        └── test_multitenant_adversarial.py      # Cross-tenant isolation matrix (403/404 assertions)
```

### Key Implementation Patterns

#### Pattern 1: Tiered Health Check Probes (`/live` vs `/ready`)
**What:** Kubernetes/Docker orchestration requires lightweight probes to check process responsiveness without overwhelming databases, and separate readiness probes that check downstream connections.
**When to use:** Every containerized deployment.
**Specification:**
- `GET /v1/health/live` -> Returns HTTP 200 `{"status": "live", "timestamp": "..."}` immediately without I/O.
- `GET /v1/health/ready` -> Executes `SELECT 1` on PostgreSQL and `PING` on Redis. Returns HTTP 200 with `status: "ready"` if both connected. Returns HTTP 200 with `status: "degraded"` if Redis is offline (since app gracefully falls back). Returns HTTP 503 if PostgreSQL is disconnected.

#### Pattern 2: Dual-Mode Staging Fixture with Nested Savepoints
**What:** Connects to PostgreSQL staging container or external `TEST_DATABASE_URL`. Uses session-level Alembic upgrade and per-test `SAVEPOINT` rollbacks.
**When to use:** Staging concurrency testing.
**Specification:**
If PostgreSQL connection fails (e.g. Docker not running locally), tests emit `pytest.skip` with clear diagnostic instructions rather than failing hard.

#### Pattern 3: Nginx SSE Proxy Buffering Bypass
**What:** Default Nginx buffering holds SSE chunks in memory until buffers fill (~4KB-16KB), freezing real-time SOC updates.
**When to use:** Reverse proxy configuration for `/v1/streams/`.
**Specification:**
```nginx
location /v1/streams/ {
    proxy_pass http://api:8000/v1/streams/;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_cache off;
    chunked_transfer_encoding off;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Row Locking & Queue Concurrency | Custom Redis lock loops | `SELECT ... FOR UPDATE SKIP LOCKED` | PostgreSQL provides MVCC-native, transaction-bound concurrency guarantees without lock timeouts or orphan risks. |
| Distributed Leader Election | File-based lock / Heartbeat files | `pg_try_advisory_lock(int)` | PostgreSQL session-level advisory locks are automatically released when connections drop or process dies. |
| SSE Buffering Control | Custom flush payloads or padding bytes | `proxy_buffering off;` in Nginx | Application-level padding hacks waste bandwidth and fail if proxy buffers are configured larger. |
| Health Probes | Monolithic single endpoint | Tiered `/live` & `/ready` probes | Monolithic probes cause cascading restarts during transient DB latency spikes when liveness probes fail. |

---

## Common Pitfalls

### Pitfall 1: Docker CLI Absence in Local Environment
- **What goes wrong:** Running `docker compose up -d` fails if Docker is not installed on the developer's host PATH (e.g. Windows bare-metal without Docker Desktop).
- **Prevention:** Design tests with dual-mode detection: check if `STAGING_DATABASE_URL` or `TEST_DATABASE_URL` is reachable; if not, invoke `pytest.skip(...)` with instructions to start the staging container or supply the environment variable.

### Pitfall 2: Nginx Proxy Buffering Freezing SSE Events
- **What goes wrong:** Frontend `EventSource` connections appear connected but receive zero events until 4KB or 16KB of events accumulate.
- **Prevention:** Explicitly configure `proxy_buffering off;` and `chunked_transfer_encoding off;` in the Nginx location block for `/v1/streams/`.

### Pitfall 3: Cascading 500 Errors on Redis Failover
- **What goes wrong:** If Redis drops, unhandled `ConnectionError` crashes scan or event endpoints.
- **Prevention:** Ensure `cache_service` and `event_broadcaster` wrap Redis calls in fallback blocks, degrading to local in-memory processing and returning HTTP 200 with degraded state telemetry.

### Pitfall 4: Database Schema Drift Across Environments
- **What goes wrong:** Staging/Production containers run with stale schemas if migrations are not executed before the application server accepts traffic.
- **Prevention:** `CMD alembic upgrade head && uvicorn backend.main:app ...` in Dockerfile, and automated verification of `alembic upgrade head` in staging test setup.

---

## Code Examples

### Tiered Health Probes Implementation Pattern
```python
# backend/api/routers/health.py
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from backend.api.dependencies import get_db
from backend.services.cache import cache_service

router = APIRouter(tags=["Health"])

@router.get("/health/live")
async def liveness_probe():
    return {
        "status": "live",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.get("/health/ready")
async def readiness_probe(db: AsyncSession = Depends(get_db)):
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    redis_ok = cache_service.available

    if not db_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "database": "disconnected",
                "redis": "connected" if redis_ok else "disconnected",
                "message": "Critical dependency failure: PostgreSQL database is unreachable."
            }
        )

    return {
        "status": "ready" if redis_ok else "degraded",
        "database": "connected",
        "redis": "connected" if redis_ok else "disconnected",
        "message": "All systems operational" if redis_ok else "Running with in-memory fallback (Redis offline)"
    }
```

### Production Docker Compose Overlay Pattern
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api:
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2048M
        reservations:
          cpus: '0.5'
          memory: 512M
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/v1/health/live"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 15s

  db:
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2048M
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  nginx:
    image: nginx:1.25-alpine
    restart: always
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Monolithic `/health` probe | Split `/health/live` & `/health/ready` | Industry standard (K8s/Compose) | Prevents orchestrators from prematurely terminating healthy apps during transient external DB latency. |
| In-memory SQLite testing only | Dual-mode SQLite + real PostgreSQL 16 staging harness | Sprint 5/6 | Catches subtle dialect differences, advisory lock semantics, and row-level concurrency bugs before prod. |
| Ad-hoc container startup | Multi-compose overlay hierarchy (`base`, `staging`, `prod`) | Docker Compose v2+ | Clean separation of concerns without duplicating service definitions. |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Docker CLI is not guaranteed to be present on developer host environments. | Environment Availability | If tests strictly require `docker` command, test runner errors out; dual-mode fallback with `pytest.skip` mitigates this risk completely. |
| A2 | `pyarrow` is completely unused across `backend/` and `src/`. | Package Legitimacy Audit | Verified via recursive codebase grep; removal reduces Docker build size and dependency footprint. |

---

## Open Questions

1. **Port conflicts on staging PostgreSQL:**
   - Default host port mapped in `docker-compose.staging.yml` is `5433:5432` to avoid colliding with local PostgreSQL instances on `5432`.
   - Redis staging mapped to `6380:6379`.
   - Configured cleanly via `STAGING_DATABASE_URL` and `STAGING_REDIS_URL`.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python | Backend API & Tests | ✓ | 3.13.9 | None (Primary runtime) |
| Pytest | Test Execution | ✓ | 8.4.2 | None |
| Docker | Local Staging Containers | ✗ (Not on PATH) | — | External `STAGING_DATABASE_URL` / `TEST_DATABASE_URL`, or skip with diagnostic instructions |
| PostgreSQL 16 | Concurrency Staging Tests | Optional / Staging | — | `pytest.skip` when staging instance is unreachable |
| Redis 7 | Cache & PubSub Staging | Optional / Staging | — | In-memory fallback and test simulation |

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `pytest` 8.4.2 + `pytest-asyncio` |
| Config file | `pytest.ini` |
| Quick run command | `pytest tests/unit/ -x -q` |
| Staging suite command | `pytest tests/staging/ tests/integration/ -v` |
| Full suite command | `pytest tests/ -v` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-PROD-01 | PostgreSQL Concurrency & Row Locks (100 alerts, advisory locks, skip locked) | Staging | `pytest tests/staging/test_postgres_staging_concurrency.py -v` | ✅ Exists (expand to 100 alerts) |
| REQ-PROD-01 | Redis Disconnection & Graceful Degradation | Staging / Unit | `pytest tests/staging/test_redis_failover_degradation.py -v` | ❌ Wave 0 |
| REQ-PROD-01 | Tiered Health Probes (`/health/live` & `/health/ready`) | Integration | `pytest tests/integration/test_health_probes.py -v` | ❌ Wave 0 |
| REQ-PROD-01 | Full End-to-End SOC Lifecycle (Scan → Alert → Incident → Contain → SSE) | Integration | `pytest tests/integration/test_soc_e2e_lifecycle.py -v` | ❌ Wave 0 |
| REQ-PROD-01 | Multi-Tenant Adversarial Cross-Tenant Isolation Matrix | Integration | `pytest tests/integration/test_multitenant_adversarial.py -v` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/unit/ -q`
- **Per wave merge:** `pytest tests/integration/ tests/staging/ -v`
- **Phase gate:** Full test suite passes without unhandled exceptions or regressions.

### Wave 0 Gaps
- [ ] `tests/integration/test_health_probes.py` — Covers tiered `/health/live` and `/health/ready`
- [ ] `tests/staging/test_redis_failover_degradation.py` — Covers automated Redis failover verification
- [ ] `tests/integration/test_soc_e2e_lifecycle.py` — Covers full E2E lifecycle
- [ ] `tests/integration/test_multitenant_adversarial.py` — Covers cross-tenant adversarial matrix

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Yes | Bearer JWT validation on all SOC endpoints; single-use stream tickets for SSE. |
| V4 Access Control | Yes | Strict tenant isolation via `user_id` filtering; admin privilege gating; 403/404 cross-tenant rejection. |
| V5 Input Validation | Yes | Pydantic model schemas for all payloads; indicator value length constraints. |
| V14 Configuration & Architecture | Yes | Nginx reverse proxy with security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`); container resource limits in `docker-compose.prod.yml`. |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Cross-Tenant Data Leakage | Information Disclosure | Filter all database queries by authenticated user's `tenant_id` / `user_id`; return 404 for resources owned by other tenants. |
| SSE Denial of Service / Connection Starvation | Denial of Service | Dedicated Nginx rate limits and ephemeral single-use stream tickets with 30s TTL. |
| Unbuffered Proxy Memory Exhaustion | Denial of Service | Strict Nginx `client_max_body_size` and bounded event payloads (16 KB). |
| Docker Privileged Escalation | Elevation of Privilege | Run containers as non-root user; apply resource limits (CPU/memory caps). |

---

## Sources

### Primary (HIGH confidence)
- Codebase inspection: `backend/main.py`, `backend/core/config.py`, `backend/api/routers/health.py`, `docker-compose.staging.yml`, `requirements.txt`
- Existing staging test: `tests/staging/test_postgres_staging_concurrency.py`
- Architectural decisions: `.planning/intel/decisions.md`, `07-CONTEXT.md`

### Secondary (MEDIUM confidence)
- Nginx Reverse Proxy documentation for EventSource / SSE buffering controls (`proxy_buffering off;`)
- PostgreSQL 16 documentation on `FOR UPDATE SKIP LOCKED` and advisory locks

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — Verified directly against installed packages and active codebase.
- Architecture: HIGH — Concrete designs matching Sprint 6 specifications and existing patterns.
- Pitfalls: HIGH — Identified critical environment realities (e.g. Docker CLI not on host PATH) and proven mitigations.

**Research date:** 2026-09-30  
**Valid until:** 2026-10-30
