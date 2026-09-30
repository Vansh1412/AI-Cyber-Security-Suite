---
phase: 07
reviewers:
  - architect-peer-review
reviewed_at: 2026-09-30T15:15:00Z
plans_reviewed:
  - .planning/phases/07-production-hardening-staging-parity/07-01-PLAN.md
  - .planning/phases/07-production-hardening-staging-parity/07-02-PLAN.md
  - .planning/phases/07-production-hardening-staging-parity/07-03-PLAN.md
---

# Cross-AI Plan Review — Phase 07: Production Hardening & Staging Parity

## Reviewer: Senior Cyber Security & Distributed Systems Architect

### 1. Summary — Executive Assessment

The Phase 7 implementation plans provide a solid and comprehensive blueprint for moving the AI Cyber Security Suite from unit/mock testing into full staging parity and production deployment hardening. The 3-wave architecture aligns with Sprint 6 and satisfies Decisions D-01 through D-12.

However, an adversarial audit against the active codebase revealed critical discrepancies, race condition blind spots, and deployment flaws that would cause test failures, false positives, and container boot-loops if executed verbatim:
1. **Container Boot-Loop:** The production Docker Compose healthcheck calls `curl`, but `curl` is not installed in `docker/Dockerfile` (`python:3.10-slim`).
2. **Reverse Proxy SSE Buffering Bypass Failure:** `nginx/nginx.conf` configures `proxy_buffering off` for `location /v1/streams/`, but actual SSE endpoints in FastAPI are mounted at `/v1/soc/stream`, `/v1/alerts/stream`, etc.
3. **Route & Schema Mismatches in Integration Tests:** Plan 07-03 tests non-existent routes (`/v1/soc/incidents`, `/v1/soc/alerts`, `/v1/streams/events`) and invalid enums (`BLACKLIST_IP`, status `COMPLETED`).
4. **PostgreSQL 16 Lost Updates & Pool Exhaustion:** `incident_service.attach_alerts` does not acquire a row-level lock (`with_for_update()`) on the `Incident` row, causing lost update anomalies during 100 concurrent alert attachments. In addition, 100 simultaneous async sessions exhaust SQLAlchemy's default pool (`pool_size=5, max_overflow=10`).
5. **Multi-Connection Test Isolation Assumption:** Nested transactions (`connection.begin_nested()`) cannot isolate or roll back transactions executed across separate connection pool instances in `asyncio.gather`.

---

### 2. Strengths

- **Decoupled Tiered Health Probes (D-11):** Separating `/v1/health/live` (lightweight process responsiveness) from `/v1/health/ready` (deep DB and Redis dependency validation) prevents cascading restarts during transient downstream database latency.
- **Dual-Mode Staging Architecture (D-01):** Supporting ephemeral Docker staging containers while allowing graceful skips with actionable startup commands prevents developer environment lockouts on machines without active Docker daemons.
- **Adversarial Multi-Tenant Matrix Design (D-06):** Structuring adversarial cross-tenant fixtures (`User A`, `User B`, `Admin`) specifically asserting anti-enumeration HTTP 404/403 responses guarantees zero cross-tenant leakage for SOC alerts, incidents, and streaming events.
- **Closed-Loop Containment Reversibility (D-08):** Testing the full containment lifecycle (trigger -> dynamic blacklist -> assert blocked -> atomic revert -> assert unblocked with audit trail) enforces operational safety against automated SOAR false positives.
- **Non-Destructive Dependency Hygiene (D-12):** Clean removal of unreferenced `pyarrow` reduces the container image footprint without disturbing retrained model artifacts in `ml/models/store/`.
- **PostgreSQL 16 Distributed Concurrency Patterns:** Retaining and verifying advisory lock leader election (`pg_try_advisory_lock`), `FOR UPDATE SKIP LOCKED` outbox claiming, and monotonic epoch fencing directly validates high-throughput enterprise durability.

---

### 3. Key Concerns & Gaps

#### High Severity
- **C-01 (High):** `curl` missing in `docker/Dockerfile` causing healthcheck exit 127 in `docker-compose.prod.yml`, preventing `nginx` from starting.
- **C-02 (High):** `nginx/nginx.conf` SSE location block path mismatch (`/v1/streams/` vs actual `/v1/soc/stream`), causing all SSE traffic to fall into buffered, rate-limited `/v1/` route.
- **C-03 (High):** Non-canonical API route paths in Plan 07-03 (`/v1/soc/alerts` instead of `/v1/alerts`, `/v1/soc/incidents` instead of `/v1/incidents`, `/v1/streams/events` instead of `/v1/soc/stream`).
- **C-04 (High):** Containment enum and status mismatch (`BLACKLIST_IP` vs `BLACKLIST_INDICATOR`, `COMPLETED` vs `EXECUTED`).
- **C-05 (High):** PostgreSQL 16 lost update anomaly in `incident_service.attach_alerts` without `with_for_update()`, plus SQLAlchemy connection pool exhaustion when launching 100 concurrent sessions without a semaphore.
- **C-06 (High):** Savepoint rollback isolation limitation across concurrent database connections in staging tests.

#### Medium Severity
- **C-07 (Med):** `/v1/health/ready` probe inspecting `cache_service.available` rather than executing an active `await client.ping()` with timeout.
- **C-08 (Med):** Unbounded timeout on database `SELECT 1` in health probe risking orchestrator check timeouts.
- **C-09 (Med):** Host port `8000:8000` remaining bound from base compose, allowing clients to bypass Nginx proxy.
- **C-10 (Med):** Infinite stream hang risk in live SSE client test without bounded event reading or timeout.

---

### 4. Required Plan Revisions

1. **Plan 07-01 Revisions:**
   - Update `docker-compose.prod.yml` healthcheck to use standard Python `urllib`:
     `test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health/live')"]`
   - Update `nginx/nginx.conf` location matching to use regex covering all stream routes:
     `location ~* ^/v1/(soc|alerts|notifications|admin/soc)/stream$ { proxy_buffering off; chunked_transfer_encoding off; proxy_read_timeout 86400s; ... }`
   - Update `/v1/health/ready` in `backend/api/routers/health.py` to wrap DB query with `asyncio.timeout(2.0)` and execute active `await cache_service._client.ping()` with `asyncio.timeout(1.0)`.

2. **Plan 07-02 Revisions:**
   - Add `backend/services/incident_service.py` to `files_modified`.
   - Update `incident_service.attach_alerts` to use `with_for_update()` on incident row queries under PostgreSQL to prevent lost update race conditions.
   - In `tests/staging/test_postgres_staging_concurrency.py`, bound concurrent execution with `asyncio.Semaphore(15)` or configure engine with `pool_size=25, max_overflow=85` to prevent QueuePool timeouts.
   - Implement explicit table cleanup in staging test teardown to guarantee multi-connection test isolation.

3. **Plan 07-03 Revisions:**
   - Update test endpoint URLs to canonical routes:
     - Alerts: `GET /v1/alerts`, `GET /v1/alerts/{alert_uuid}`, `POST /v1/alerts/{alert_uuid}/acknowledge`
     - Incidents: `POST /v1/incidents`, `GET /v1/incidents/{id_or_uuid}`, `POST /v1/incidents/{id_or_uuid}/alerts`
     - Streams: `POST /v1/streams/ticket`, `GET /v1/soc/stream?ticket={ticket}`
   - Use correct containment enums: `ContainmentActionType.BLACKLIST_INDICATOR` and `ContainmentActionStatus.EXECUTED`.
   - In SSE live consumption test, use `async for line in response.aiter_lines():` with a timeout or break condition upon receiving the envelope to prevent test hangs.

---

## Consensus Summary

### Agreed Strengths
- Decoupled `/v1/health/live` and `/v1/health/ready` tiered architecture prevents orchestrator thrashing.
- Dual-mode staging harness preserves developer velocity and handles missing local Docker gracefully.
- Adversarial multi-tenant matrix reliably exercises 403/404 boundaries without data exposure.
- Dynamic containment reversibility and audit tracking deliver operational safety.

### Agreed Concerns
- Route, enum, and schema naming mismatches between test assertions and existing backend implementations must be reconciled to avoid false-positive passes or 422 errors.
- Reverse proxy SSE buffering rules must align with actual FastAPI streaming routes (`/v1/soc/stream`).
- PostgreSQL concurrency requires row-level locking (`with_for_update()`) and bounded connection pooling to handle 100 concurrent alert attachments cleanly.

### Divergent Views
- None. The findings and remediations are concrete, code-verified, and directly applicable.
