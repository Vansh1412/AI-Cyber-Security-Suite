# Phase 7: Production Hardening & Staging Parity - Context

**Gathered:** 2026-09-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Validates multi-tenant PostgreSQL concurrency, end-to-end integration, and production deployment readiness. Specifically focuses on staging parity against real PostgreSQL/Redis instances, full SOC lifecycle API integration testing (Scan → Alert → Incident → Containment → SSE), race-condition verification, failover degradation, tiered health checks, Nginx SSE buffering and security hardening, multi-compose orchestration, and non-destructive dependency hygiene.
</domain>

<decisions>
## Implementation Decisions

### PostgreSQL Staging & Concurrency Strategy
- **D-01:** Dual-mode provisioning: Ephemeral Docker container managed via `docker-compose.staging.yml` by default, with `TEST_DATABASE_URL` environment override for external staging instances.
- **D-02:** Database isolation: Session-level Alembic upgrade + per-test nested transaction rollback (`SAVEPOINT`s) for maximum test isolation and execution speed.
- **D-03:** Concurrency & race condition test suite: Targeting 100 concurrent alert attachments, parallel incident status transitions, distributed monitoring lease claims, and transactional outbox batch drains.
- **D-04:** Redis failover & graceful degradation: Automated verification of graceful degradation: simulate Redis disconnection and assert all scan, event, and monitoring endpoints continue operating without HTTP 500 errors.

### End-to-End Integration & RBAC Scope
- **D-05:** Test architecture: Comprehensive API-level integration suite using FastAPI `AsyncClient` across multiple tenants simulating the full SOC lifecycle (Scan → Alert → Incident → Containment → SSE Stream).
- **D-06:** Multi-tenant isolation: Adversarial cross-tenant fixture matrix (`User A`, `User B`, `Admin`) verifying strict HTTP 404/403 isolation across alerts, incidents, targets, and SSE streams without credential leakage.
- **D-07:** Live SSE streaming verification: Live asynchronous SSE stream consumer acquiring stream tickets, connecting to `/v1/streams/events`, and asserting in-order envelope delivery with monotonic cursor IDs.
- **D-08:** Containment reversibility: Full containment lifecycle loop: trigger incident → execute dynamic blacklist action → assert blocked state → execute atomic revert action → assert unblocked state & audit trail.

### Production Deployment Topology
- **D-09:** Docker Compose orchestration: Multi-compose overlay setup: `docker-compose.yml` (base backend/db/redis) extended by `docker-compose.staging.yml` (ephemeral staging/test ports) and `docker-compose.prod.yml` (hardened resource limits, health checks, `restart: always`, and logging).
- **D-10:** Nginx reverse proxy & SSE streaming: Dedicated SSE location block disabling proxy buffering (`proxy_buffering off;`, `chunked_transfer_encoding off;`, `proxy_read_timeout 86400s;`) for `/v1/streams/`, with rate-limiting zones and security headers (CSP, HSTS, X-Content-Type-Options) on root `/v1/` routes.
- **D-11:** Tiered health check probes: `/v1/health/live` (lightweight process responsiveness, returns HTTP 200) and `/v1/health/ready` (validates DB connection pool and Redis ping; returns HTTP 200 with `status: "degraded"` if Redis fails, but HTTP 503 if PostgreSQL is down).
- **D-12:** Artifact preservation & audit hygiene: Strict preservation with targeted dependency hygiene: keep all retrained model checkpoints (`ml/models/store/`), reports, and telemetry abstractions fully preserved; safely remove only confirmed unused dependencies (e.g., `pyarrow`) during staging validation while keeping all Sprint 6 and core code protected.

### The Agent's Discretion
- Exact port assignments in `docker-compose.staging.yml` (e.g. host mapping 5433 to avoid conflicts with local 5432).
- Specific pytest fixture naming and setup in `tests/integration/staging/`.
- Detailed Nginx rate-limiting parameters (e.g. `limit_req_zone` burst size and rate).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Architecture & Database
- `docs/architecture/postgres_redis_migration.md` — Defines PostgreSQL connection pooling, asyncpg driver requirements, Alembic migration standards, and Redis Pub/Sub failover architecture.
- `docs/architecture/concurrency_model.md` — Outlines row locking (`SELECT FOR UPDATE`), optimistic concurrency controls, and lease acquisition protocols.

### Specifications & Production Readiness
- `docs/specs/sprint_6_production_readiness.md` — Comprehensive specifications for Sprint 6 staging verification, E2E SOC integration, and deployment checklists.
- `docs/specs/containment_service.md` — Defines reversible playbooks, containment states, and atomic revert protocols.
- `docs/specs/sse_streaming.md` — Defines SSE event envelope format, ticket acquisition, cursor monotonicity, and pod fanout rules.

### Planning Intel & Decisions
- `.planning/intel/decisions.md` — Architectural decision log (`DEC-001` through `DEC-006`) covering PostgreSQL, Redis, SSE, RBAC, and containment.
- `.planning/intel/SYNTHESIS.md` — High-level technical architecture synthesis across ML, SOC engine, and web consoles.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `src/db/session.py`: Async engine and session factory with connection pooling.
- `src/services/containment_service.py`: Dynamic blacklist and atomic rollback mechanisms.
- `src/services/event_engine.py`: Event normalization, payload bounding (16KB), and outbox queuing.
- `src/api/v1/endpoints/stream.py`: SSE ticket generation and streaming connection handling.
- `src/core/config.py`: Environment configuration management and secret resolution.

### Established Patterns
- Multi-tenancy enforcement via tenant ID filtering on all SQLAlchemy queries.
- Redis Pub/Sub with local in-memory fallback pattern on connection errors.
- Alembic migration tracking in `alembic/`.
- Pydantic response models and centralized exception handling.

### Integration Points
- `src/api/v1/endpoints/health.py`: Integration point for adding `/live` and `/ready` tiered probes.
- `docker-compose.yml`: Base orchestration definition to be extended by staging and production overlays.
- `tests/integration/`: Target directory for staging-parity and multi-tenant adversarial test suites.
- `nginx/nginx.conf`: Reverse proxy configuration for buffering overrides and header security.

</code_context>

<specifics>
## Specific Ideas

- Ensure staging tests can execute without requiring pre-existing cloud or host infrastructure by leveraging ephemeral containers.
- Staging test run should provide clear test coverage reporting for multi-tenant isolation scenarios.
- Verify that disconnecting Redis during active load triggers automatic fallbacks without causing 500 Internal Server Errors in any client API responses.

</specifics>

<deferred>
## Deferred Ideas

- Full browser-based synthetic UI monitoring (Playwright/Cypress end-to-end frontend tests against staging) — deferred to a subsequent frontend polish milestone.
- Full deprecation cleanup of legacy MLflow / ONNX / psutil audit items — deferred to dedicated post-v1 maintenance sprint.

</deferred>

---

*Phase: 7-Production Hardening & Staging Parity*  
*Context gathered: 2026-09-30*
