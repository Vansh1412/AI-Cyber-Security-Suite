---
phase: 07-production-hardening-staging-parity
plan: "01"
subsystem: infra
tags: [fastapi, docker, nginx, healthcheck, sse, pyarrow, redis, postgresql]

requires:
  - phase: 06-containment-actions-playbooks
    provides: SOC streaming endpoints, incident containment models, and multi-tenant security architecture
provides:
  - Tiered health check probes (/v1/health/live and /v1/health/ready) with active Redis ping and DB timeout enforcement
  - Production Docker Compose configuration (docker-compose.prod.yml) with hardened CPU/memory limits, JSON logging limits, and Python urllib health probes
  - Diagnostic curl packaging in production Dockerfile
  - Hardened Nginx reverse proxy configuration (nginx/nginx.conf) with regex-matched unbuffered SSE stream proxying
  - Dependency hygiene cleanup removing unused pyarrow
  - Integration test suite validating tiered health probes (tests/integration/test_health_probes.py)
affects: [07-02, 07-03, deployment, monitoring]

tech-stack:
  added: [nginx:1.25-alpine, docker-compose.prod.yml]
  patterns: [liveness vs readiness decoupling, unbuffered reverse-proxy SSE streaming, bounded timeout probes]

key-files:
  created:
    - docker-compose.prod.yml
    - nginx/nginx.conf
    - tests/integration/test_health_probes.py
  modified:
    - backend/api/routers/health.py
    - docker/Dockerfile
    - requirements.txt

key-decisions:
  - "D-11: Decoupled /v1/health/live (lightweight process liveness) from /v1/health/ready (deep dependency checks with 2.0s DB and 1.0s Redis timeouts)."
  - "D-09: Hardened production Docker Compose topology with explicit CPU/memory limits, loopback API port binding (127.0.0.1:8000:8000), and Python urllib healthchecks."
  - "D-10: Configured Nginx with regex location ~* ^/v1/(soc|alerts|notifications|admin/soc)/stream$ for unbuffered SSE streaming and standard security headers."
  - "D-12: Removed unused pyarrow dependency from requirements.txt while preserving all core ML and data dependencies."

patterns-established:
  - "Probes: Liveness returns 200 without I/O; readiness evaluates DB as critical (503 if down) and Redis as degraded fallback (200 degraded if offline)."
  - "Reverse Proxy: Dedicated unbuffered SSE proxy rules with proxy_buffering off and chunked_transfer_encoding off."

requirements-completed:
  - REQ-PROD-01

duration: 15min
completed: 2026-09-30
---

# Phase 07: Plan 01 Summary

**Tiered health check probes (/v1/health/live and /v1/health/ready) with active Redis ping and DB timeouts, production Docker Compose overlay, hardened Nginx SSE proxy configuration, and pyarrow removal.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-09-30T18:15:00Z
- **Completed:** 2026-09-30T18:30:00Z
- **Tasks:** 6 completed
- **Files modified:** 6

## Accomplishments

- Implemented `/v1/health/live` (lightweight process liveness returning 200 immediately) and `/v1/health/ready` (evaluating PostgreSQL with 2.0s timeout and active Redis ping with 1.0s timeout, returning degraded 200 if Redis is down and 503 if PostgreSQL fails).
- Built `docker-compose.prod.yml` specifying container memory limits (2048M for api and db, 512M for redis), CPU caps, json-file log rotation, loopback binding on port 8000, and standard-library Python health probes.
- Added `curl` to `docker/Dockerfile` system dependencies for production diagnostics.
- Configured `nginx/nginx.conf` with regex-matched unbuffered proxying for `/v1/soc/stream`, `/v1/alerts/stream`, `/v1/notifications/stream`, and `/v1/admin/soc/stream`, plus rate limiting and security headers (CSP, X-Frame-Options, X-Content-Type-Options).
- Removed unused `pyarrow` dependency from `requirements.txt`.
- Created comprehensive integration test suite `tests/integration/test_health_probes.py` with 4 passing tests covering live, ready-healthy, ready-degraded, and ready-db-down.

## Task Commits

1. **Task 1: Implement Tiered Health Check Probes in FastAPI with Active Ping** - `ddec026` (feat)
2. **Task 2: Build Production Docker Compose Overlay & Fix Healthcheck** - `58b3440` (feat)
3. **Task 3: Update Dockerfile to Package curl for Production Diagnostics** - `fa8dcd8` (feat)
4. **Task 4: Configure Hardened Nginx Reverse Proxy with Regex-Matched SSE Streaming** - `ccb966c` (feat)
5. **Task 5: Safely Clean Unused pyarrow Dependency** - `87b5672` (chore)
6. **Task 6: Add Comprehensive Integration Tests for Tiered Health Probes** - `2a281d9` (feat)

## Files Created/Modified

- `backend/api/routers/health.py` - Added `/v1/health/live` and `/v1/health/ready` with active ping and timeouts.
- `docker-compose.prod.yml` - Production overlay with resource constraints, logging limits, and healthcheck.
- `docker/Dockerfile` - Installed `curl` for container diagnostics.
- `nginx/nginx.conf` - Reverse proxy with unbuffered SSE routing and security headers.
- `requirements.txt` - Removed `pyarrow`.
- `tests/integration/test_health_probes.py` - 4 integration tests for tiered health probe endpoints.

## Decisions Made

- None - followed plan and review specifications as specified.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. All tests passed with zero errors across integration and regression suites.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Ready for Plan 07-02 (PostgreSQL row-level locking with `with_for_update()`, PostgreSQL 16 staging concurrency harness, and automated Redis failover degradation suite).

---
*Phase: 07-production-hardening-staging-parity*
*Completed: 2026-09-30*
