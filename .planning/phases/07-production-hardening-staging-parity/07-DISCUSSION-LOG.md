# Phase 7: Production Hardening & Staging Parity - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-09-30  
**Phase:** 7-Production Hardening & Staging Parity  
**Areas discussed:** PostgreSQL Staging & Concurrency Strategy, End-to-End Integration & RBAC Scope, Production Deployment Topology  

---

## PostgreSQL Staging & Concurrency Strategy

### Question 1: Staging/Test Instance Provisioning
| Option | Description | Selected |
|--------|-------------|----------|
| Dual-mode (Recommended) | Ephemeral Docker container managed via docker-compose.staging.yml by default, with TEST_DATABASE_URL environment override for external staging instances. | ✓ |
| Dedicated staging container only | Always expect a long-running PostgreSQL service on localhost:5432. | |
| Mock/SQLite fallback | Keep using SQLite or in-memory mocks for tests and reserve PostgreSQL for deployment scripts. | |

**User's choice:** Dual-mode: Ephemeral Docker container managed via docker-compose.staging.yml by default, with TEST_DATABASE_URL environment override for external staging instances.  
**Notes:** Provides local self-containment for CI/CD and developer machines while supporting real external staging clusters when configured.

### Question 2: Database Isolation & Test Cleanup
| Option | Description | Selected |
|--------|-------------|----------|
| Session-level Alembic upgrade + SAVEPOINT rollback (Recommended) | Session-level Alembic upgrade + per-test nested transaction rollback (SAVEPOINTs) for maximum speed and clean state. | ✓ |
| Truncate tables after each test | Run Alembic migrations once, then execute TRUNCATE on all tables between test cases. | |
| Recreate database per run | Drop and recreate database and run all Alembic migrations on every test session. | |

**User's choice:** Session-level Alembic upgrade + per-test nested transaction rollback (SAVEPOINTs) for maximum speed and clean state.  
**Notes:** Minimizes migration overhead while ensuring zero cross-test state leakage.

### Question 3: Concurrency Scenarios & Race Condition Coverage
| Option | Description | Selected |
|--------|-------------|----------|
| Core concurrency suite (Recommended) | 100 concurrent alert attachments, parallel incident status transitions, distributed monitoring lease claims, and transactional outbox batch drains. | ✓ |
| Lightweight concurrency | 10-20 concurrent requests per endpoint checking basic locking. | |
| Stress testing only | Locust or k6 load test against running staging server rather than pytest fixtures. | |

**User's choice:** Core concurrency suite: 100 concurrent alert attachments, parallel incident status transitions, distributed monitoring lease claims, and transactional outbox batch drains.  
**Notes:** Directly targets PostgreSQL row locking (`SELECT FOR UPDATE`) and lease fencing mechanisms under heavy simulated load.

### Question 4: Redis Failover & Graceful Degradation
| Option | Description | Selected |
|--------|-------------|----------|
| Automated graceful degradation verification (Recommended) | Simulate Redis disconnection and assert all scan, event, and monitoring endpoints continue operating without HTTP 500 errors. | ✓ |
| Healthcheck assertion only | Verify /v1/health reports Redis unhealthy while app stays up. | |
| Strict failure | Treat Redis disconnect as fatal service failure returning HTTP 503. | |

**User's choice:** Automated verification of graceful degradation: simulate Redis disconnection and assert all scan, event, and monitoring endpoints continue operating without HTTP 500 errors.  
**Notes:** Guarantees critical SOC ingestion and scan workflows remain operational when Redis pub/sub fails over to memory buffers.

---

## End-to-End Integration & RBAC Scope

### Question 1: Test Architecture & Lifecycle Breadth
| Option | Description | Selected |
|--------|-------------|----------|
| Comprehensive API-level integration suite (Recommended) | FastAPI AsyncClient across multiple tenants simulating the full SOC lifecycle (Scan → Alert → Incident → Containment → SSE Stream). | ✓ |
| Playwright/Cypress end-to-end browser tests | Testing frontend UI against mock backend. | |
| Isolated service integration tests | Verifying individual router/service pairs against staging database. | |

**User's choice:** Comprehensive API-level integration suite using FastAPI AsyncClient across multiple tenants simulating the full SOC lifecycle (Scan → Alert → Incident → Containment → SSE Stream).  
**Notes:** Complete real-world pipeline simulation without browser overhead.

### Question 2: Multi-Tenant Cross-Isolation & RBAC Boundaries
| Option | Description | Selected |
|--------|-------------|----------|
| Adversarial cross-tenant fixture matrix (Recommended) | User A, User B, Admin verifying strict HTTP 404/403 isolation across alerts, incidents, targets, and SSE streams without credential leakage. | ✓ |
| Role-only matrix | Test Admin vs Analyst vs Viewer within a single tenant. | |
| Schema-separated isolation | Test PostgreSQL search_path multi-tenancy. | |

**User's choice:** Adversarial cross-tenant fixture matrix (User A, User B, Admin) verifying strict HTTP 404/403 isolation across alerts, incidents, targets, and SSE streams without credential leakage.  
**Notes:** Validates defense against horizontal and vertical privilege escalation.

### Question 3: Live SSE Streaming Verification
| Option | Description | Selected |
|--------|-------------|----------|
| Live asynchronous SSE stream consumer (Recommended) | Acquiring stream tickets, connecting to /v1/streams/events, and asserting in-order envelope delivery with monotonic cursor IDs. | ✓ |
| Polling fallback test | Verify SSE ticket generation and fallback polling endpoint without persistent connections. | |
| Mock generator test | Test EventEngine formatting functions in isolation without network streaming. | |

**User's choice:** Live asynchronous SSE stream consumer acquiring stream tickets, connecting to /v1/streams/events, and asserting in-order envelope delivery with monotonic cursor IDs.  
**Notes:** Verifies genuine ticket handoff and message ordering under real streaming conditions.

### Question 4: Containment Action Reversibility & Execution Safety
| Option | Description | Selected |
|--------|-------------|----------|
| Full containment lifecycle loop (Recommended) | Trigger incident → execute dynamic blacklist action → assert blocked state → execute atomic revert action → assert unblocked state & audit trail. | ✓ |
| Dry-run execution only | Validate containment payload generation without triggering actual block/unblock states. | |
| Mock-only containment | Test ContainmentService methods using MagicMock. | |

**User's choice:** Full containment lifecycle loop: trigger incident → execute dynamic blacklist action → assert blocked state → execute atomic revert action → assert unblocked state & audit trail.  
**Notes:** Validates two-way idempotency and audit logs for all remediation playbooks.

---

## Production Deployment Topology

### Question 1: Docker Compose Orchestration Topology
| Option | Description | Selected |
|--------|-------------|----------|
| Multi-compose overlay (Recommended) | docker-compose.yml (base backend/db/redis) extended by docker-compose.staging.yml (ephemeral staging/test ports) and docker-compose.prod.yml (hardened resource limits, health checks, restart: always, and logging). | ✓ |
| Unified compose with profiles | Single docker-compose.yml leveraging compose profiles (--profile staging, --profile prod) to toggle services and configurations. | |
| Standalone compose files | Completely independent docker-compose.staging.yml and docker-compose.prod.yml with no inheritance or overrides. | |

**User's choice:** Multi-compose overlay: docker-compose.yml (base backend/db/redis) extended by docker-compose.staging.yml (ephemeral staging/test ports) and docker-compose.prod.yml (hardened resource limits, health checks, restart: always, and logging).  
**Notes:** Clean separation of concerns with shared common service configuration.

### Question 2: Nginx Reverse-Proxy & SSE Streaming
| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated SSE location block (Recommended) | Disable proxy buffering (proxy_buffering off, chunked_transfer_encoding off, proxy_read_timeout 86400s) on /v1/streams/, with rate-limiting zones and security headers (CSP, HSTS, X-Content-Type-Options) on root /v1/ routes. | ✓ |
| Global streaming configuration | Disable proxy buffering globally across all backend API proxy locations with long read timeouts. | |
| App-driven header control | Rely strictly on backend response headers (X-Accel-Buffering: no) with standard default Nginx proxy directives. | |

**User's choice:** Dedicated SSE location block: Disable proxy buffering (proxy_buffering off, chunked_transfer_encoding off, proxy_read_timeout 86400s) on /v1/streams/, with rate-limiting zones and security headers (CSP, HSTS, X-Content-Type-Options) on root /v1/ routes.  
**Notes:** Prevents SSE proxy buffering deadlocks while maintaining standard reverse proxy caching and rate limiting elsewhere.

### Question 3: Health Check & Probe Strategy
| Option | Description | Selected |
|--------|-------------|----------|
| Tiered probes (Recommended) | /v1/health/live (lightweight process responsiveness, returns HTTP 200) and /v1/health/ready (validates DB pool and Redis; returns HTTP 200 with status: degraded if Redis fails, but HTTP 503 if PostgreSQL is down). | ✓ |
| Single unified /v1/health endpoint | Comprehensive JSON payload checking all dependencies, returning HTTP 200 with component health states unless PostgreSQL fails. | |
| Strict fail-fast probes | Return HTTP 503 immediately if either PostgreSQL, Redis, or ML model services report any degradation. | |

**User's choice:** Tiered probes: /v1/health/live (lightweight process responsiveness, returns HTTP 200) and /v1/health/ready (validates DB pool and Redis; returns HTTP 200 with status: degraded if Redis fails, but HTTP 503 if PostgreSQL is down).  
**Notes:** Distinguishes container liveness from dependency readiness and supports graceful degraded operation.

### Question 4: Model Artifacts & Audit Hygiene
| Option | Description | Selected |
|--------|-------------|----------|
| Strict preservation with targeted dependency hygiene (Recommended) | Keep all retrained model checkpoints (ml/models/store/), reports, and telemetry abstractions fully preserved; safely remove only confirmed unused dependencies (e.g. pyarrow) during staging validation while keeping all Sprint 6 and core code protected. | ✓ |
| Full audit cleanup execution | Purge untracked retrained checkpoints, prune obsolete reports/confusion matrices, and remove all low-risk audit items during Phase 7 hardening. | |
| Defer all cleanup | Freeze all artifacts and dependencies in their current state; defer all removals and cleanup to a future post-launch cleanup sprint. | |

**User's choice:** Strict preservation with targeted dependency hygiene: Keep all retrained model checkpoints (ml/models/store/), reports, and telemetry abstractions fully preserved; safely remove only confirmed unused dependencies (e.g. pyarrow) during staging validation while keeping all Sprint 6 and core code protected.  
**Notes:** Zero risk to ML checkpoints and Sprint 6 code, with safe hygiene for dead dev dependencies.

---

## The Agent's Discretion

- Exact port mapping conventions in `docker-compose.staging.yml` (e.g., mapping port 5433).
- Pytest fixture naming and organization within `tests/integration/staging/`.
- Detailed rate limiting token-bucket rates and burst counts for Nginx proxy rules.

## Deferred Ideas

- Full browser-based synthetic UI monitoring (Playwright/Cypress end-to-end frontend tests against staging) — deferred to a subsequent frontend polish milestone.
- Full deprecation cleanup of legacy MLflow / ONNX / psutil audit items — deferred to dedicated post-v1 maintenance sprint.
