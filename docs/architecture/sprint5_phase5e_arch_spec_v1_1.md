# SPRINT 5 — PHASE 5E ARCHITECTURE & SECURITY SPECIFICATION v1.1
## Real-Time SOC Alert Streaming Gateway (Server-Sent Events / SSE), Durable Event Sourcing & Distributed Staging Hardening

### Document: `docs/architecture/sprint5_phase5e_arch_spec_v1_1.md`
### Status: ARCHITECTURAL SPECIFICATION v1.1 — READ-ONLY — NO IMPLEMENTATION AUTHORIZED
### Authoritative Baseline: Commit `c9765d57c876113f94cce7b4ac041f8e03b66830` (CI Run `34770209223`, GREEN)

---

> [!IMPORTANT]
> **READ-ONLY MANDATE ENFORCED (v1.1)**
> - Baseline Commit: `c9765d57c876113f94cce7b4ac041f8e03b66830` (`feat(soc): implement sprint 5 phase 5d notification dispatch and secure webhooks`).
> - Sprints 5A, 5B, 5C, and 5D are 100% verified, committed, pushed, and passing all CI checks.
> - All 8 protected infrastructure files (`backend/services/incident_service.py`, `backend/services/monitoring_probe.py`, `backend/services/scheduler_service.py`, `backend/core/security_network.py`, `backend/services/threat_intel.py`, `backend/services/intel_enrichment.py`, `backend/schemas/soc.py`, `ml/**`) remain untouched.
> - The 5 pre-existing working-tree files remain untouched and unstaged.
> - Phase 5D completed files are frozen against behavioral regression.
> - NO source code, migrations, tests, or configurations are modified during this architecture gate.
> - Implementation authorization is strictly reserved for a subsequent authorized task.

---

# Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Phase 5A–5D Verified Baseline](#2-phase-5a5d-verified-baseline)
3. [Problem Statement](#3-problem-statement)
4. [Threat Model](#4-threat-model)
5. [Goals](#5-goals)
6. [Non-Goals](#6-non-goals)
7. [Final Architecture Diagram](#7-final-architecture-diagram)
8. [Distributed Deployment Model](#8-distributed-deployment-model)
9. [Authentication Model](#9-authentication-model)
10. [Tenant Isolation Model](#10-tenant-isolation-model)
11. [SSE Protocol](#11-sse-protocol)
12. [Event Schema](#12-event-schema)
13. [Event Ordering Guarantees](#13-event-ordering-guarantees)
14. [Replay / Last-Event-ID Protocol](#14-replay--last-event-id-protocol)
15. [Durable Source of Truth](#15-durable-source-of-truth)
16. [Redis / Distributed Fan-Out Behavior](#16-redis--distributed-fan-out-behavior)
17. [Queue Limits and Overflow Policy](#17-queue-limits-and-overflow-policy)
18. [Connection Limits](#18-connection-limits)
19. [Disconnect Handling](#19-disconnect-handling)
20. [Heartbeat](#20-heartbeat)
21. [Lifecycle / Shutdown](#21-lifecycle--shutdown)
22. [Admin Stream Security](#22-admin-stream-security)
23. [Reverse Proxy & Infrastructure Requirements](#23-reverse-proxy--infrastructure-requirements)
24. [PostgreSQL Staging Harness (AC24 Resolution)](#24-postgresql-staging-harness-ac24-resolution)
25. [Acceptance Criteria](#25-acceptance-criteria)
26. [Security Gates](#26-security-gates)
27. [Test Strategy](#27-test-strategy)
28. [Deployment Requirements](#28-deployment-requirements)
29. [File-Level Implementation Plan](#29-file-level-implementation-plan)
30. [Protected Files & Invariants](#30-protected-files--invariants)
31. [Risks](#31-risks)
32. [Explicit Resolved Ambiguities](#32-explicit-resolved-ambiguities)
33. [Human Approval Gate](#33-human-approval-gate)

---

## 1. Executive Summary

Sprint 5 Phase 5E delivers the authoritative, real-time push streaming gateway and distributed staging verification for the AI-Cyber-Security-Suite. 

While Phases 5A through 5D built autonomous target scheduling, SSRF-safe scanning, alert triage lifecycles, and transactional outbox webhook egress, human analysts and web dashboards currently possess no push notification mechanism. Users are forced to poll REST endpoints (`GET /v1/alerts`, `GET /v1/notifications`), creating database connection exhaustion and unacceptable alert latency under multi-tenant scale.

Phase 5E v1.1 rigorously resolves every architectural ambiguity identified in v1.0:
- **Mandatory Redis Pub/Sub**: Eliminates multi-pod event loss; Redis Pub/Sub is strictly REQUIRED for multi-pod production deployment.
- **Durable Event Sourcing (`soc_event_stream`)**: Abandons the fragile "zero schema migration" premise. Phase 5E introduces an append-only `soc_event_stream` table written inside the originating business transaction. This guarantees zero event loss even if a process crashes immediately after commit.
- **Monotonic 64-bit Cursors (`cursor_id`)**: Replaces random UUIDs with monotonic integer cursors, enabling deterministic, O(1) indexed `Last-Event-ID` replay.
- **Single-Use Stream Tickets**: Eliminates reusable JWT exposure in URL query parameters, protecting against proxy log leaks and shoulder surfing.
- **Turnkey PostgreSQL Staging Harness**: Provides an automated Docker Compose environment to definitively verify and certify AC24 (`SKIP LOCKED`, advisory lock leader election, and lease recovery) under live PostgreSQL 16.

---

## 2. Phase 5A–5D Verified Baseline

The Phase 5E design builds upon the verified foundation of Sprints 5A through 5D:

| Phase | Git Commit | Key Architectural Properties Verified in Baseline |
|---|---|---|
| **Phase 5A** | `43225b6` | Target CRUD, SSRF pre-registration validation (`security_network.py`), per-user quota (`MAX_TARGETS_PER_USER=20`), `scheduler_state` table. |
| **Phase 5B** | `3624207` | PostgreSQL advisory lock leader election, SQLite dev parity, monotonic epoch fencing, worker lease fencing (`WORKER_LEASE_SECONDS=45`), SSRF DNS-pinned probe, frozen 59-feature ML threat inference, triple-predicate atomic writeback fencing. |
| **Phase 5C** | `43d94a6` | Authoritative 4-state alert triage (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`), forbidden terminal flips (HTTP 400), recurrence semantics (new scan hit on terminal alert creates new `OPEN` alert), operational target controls (`pause`, `resume`, `reactivate`, `check-now`), diagnostics, 24h telemetry. |
| **Phase 5D** | `c9765d5` | Transactional outbox table (`notification_outbox`), background `NotificationDispatcher`, SSRF DNS-pinned egress via `security_network.py`, AES-256-GCM secret encryption with `v1$` envelope, canonical HMAC-SHA256 signing with 300s replay tolerance, 5-failure atomic circuit breaker, 524 passing tests suite-wide. |

**Current Repository State**: Clean working tree on `origin/main` except for five pre-existing unrelated files (`src/data/clean.py`, `src/data/inspect.py`, `src/data/merge.py`, `tests/integration/test_analytics_api.py`, `tests/unit/test_intel_enrichment.py`).

---

## 3. Problem Statement

1. **Client Polling Overhead**: Connected security analysts must repeatedly poll `/v1/alerts` and `/v1/notifications` every 2–5 seconds. Across 500 active analysts, this generates 100–250 queries/sec of redundant database read traffic.
2. **Multi-Pod Fan-Out Blindness**: If User A's browser connects to Pod 1, and Pod 2's scheduler detects a zero-day phishing attack on User A's target, an in-memory broadcast on Pod 2 will never reach Pod 1. User A remains blind to the active compromise.
3. **Crash-After-Commit Event Loss**: In naive async broadcasting, if a worker commits an alert to PostgreSQL and crashes before `publish()` completes, the alert exists in the DB but is never emitted to live clients.
4. **Non-Durable Replay with UUIDs**: Using UUID primary keys as SSE `Last-Event-ID` prevents efficient range queries (`WHERE id > :cursor`). Reconnecting clients cannot recover missed events deterministically.
5. **AC24 Unverified Debt**: Staging multi-pod row locking (`SKIP LOCKED`) and leader failover under real PostgreSQL remain unverified on the Windows development environment.

---

## 4. Threat Model

| ID | Threat Vector | Impact | Mitigation in Phase 5E v1.1 |
|---|---|---|---|
| **T1** | **Cross-Tenant Stream Interception** | Analyst B receives alerts/notifications belonging to Analyst A. | Strict tenant-partitioned Redis channels (`soc:events:tenant:{user_id}`) and memory registry keyed by `user_id`. Non-admin subscription to foreign channels is cryptographically and logically impossible. |
| **T2** | **JWT Query-String Leaks** | Reusable JWT exposed in reverse proxy access logs, browser history, or Referer headers. | Deprecated reusable JWT in query params. Standard Bearer headers enforced; for native EventSource, an authenticated single-use, 30-second stream ticket (`st_...`) is exchanged and burned on first use. |
| **T3** | **SSE Connection Exhaustion (DoS)** | Attacker opens 10,000 idle SSE streams, exhausting server file descriptors and worker memory. | Enforce hard limits: max 5 concurrent streams globally per user via distributed Redis counters; max 1,000 streams per pod. Excess connections rejected with HTTP 429. |
| **T4** | **Event Queue Flooding / Memory Depletion** | Slow client fails to read events; server memory grows unbounded buffering thousands of events. | Strict bounded queues (`maxsize=100`). Eviction of oldest non-critical events. If queue fills with critical events, connection is terminated with a reconnect signal forcing clean database catchup. |
| **T5** | **Privilege Escalation via Admin Stream** | Standard user connects to `/v1/admin/soc/stream` to view global enterprise threats. | Enforce strict RBAC dependency requiring `current_user.role == "admin"`. Non-admin requests immediately rejected with HTTP 403 Forbidden. Full audit logging on admin stream access. |
| **T6** | **Silent Security Event Loss on Pod Crash** | Process crashes between DB commit and network broadcast. | Transactional Event Outbox: Event is written to `soc_event_stream` table inside the originating database transaction. Reconnection with `Last-Event-ID` guarantees zero event loss. |
| **T7** | **Zombie / Hung Connections** | Dead client connections remain open after network drops, leaking pod memory. | 15-second heartbeat ping (`: ping\n\n`). If TCP socket write fails, generator immediately aborts and executes clean `finally:` unregistration. |

---

## 5. Goals

1. **Deterministic Real-Time Delivery**: Sub-500ms push delivery of new alerts, triage updates, notifications, and target state changes to connected browser clients.
2. **Authoritative Multi-Pod Fan-Out**: Mandatory Redis Pub/Sub integration ensuring events originating on any backend pod reach clients connected to any other pod.
3. **Guaranteed At-Least-Once Delivery**: Monotonic 64-bit cursor (`cursor_id`) enabling exact `Last-Event-ID` replay from durable PostgreSQL storage.
4. **Zero Event Loss on Crash**: Atomic commit of domain changes and event stream rows within the same database transaction.
5. **Robust Degraded Mode**: If Redis fails, local in-pod delivery continues, metric alerts trip, and clients catch up via database replay upon reconnect.
6. **Hard Memory Safety**: Upper bound of 1.6 MB memory per client queue and 1.6 GB per pod under maximum load.
7. **Complete AC24 Verification**: Turnkey Docker Compose staging harness providing reproducible verification of all Phase 5B/5D concurrency invariants under PostgreSQL 16.

---

## 6. Non-Goals

1. **Full-Duplex WebSockets**: Unidirectional SSE strictly fulfills push requirements. Client mutations (acknowledge, resolve, pause) continue using standard REST endpoints with HTTP semantics.
2. **Frontend UI Implementation**: React 19 UI components (Alert Center dashboard, notification bell drawer) belong strictly to Sprint 6. Phase 5E delivers the backend API and streaming engine.
3. **External Message Brokers (Kafka / RabbitMQ)**: Redis Pub/Sub combined with PostgreSQL durable storage satisfies all distributed scale requirements; heavyweight external messaging brokers are excluded.
4. **Email / SMS Direct Transport**: Outbound communication is restricted to SSE client push and existing Phase 5D webhooks. Direct SMTP/SMS is deferred.

---

## 7. Final Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                CLIENT TIER (Browser / API Client)                                │
│                                                                                                  │
│   Primary: @microsoft/fetch-event-source with Authorization: Bearer <JWT>                        │
│   Legacy Fallback: Native EventSource with ?ticket=st_<uuid> (Single-use, 30s TTL)               │
│                                                                                                  │
│   GET /v1/alerts/stream            GET /v1/notifications/stream        GET /v1/soc/stream        │
└────────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                 │ Persistent HTTP/1.1 or HTTP/2
                                                 ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 FASTAPI POD 1 (or POD N)                                         │
│                                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Streams Router (`backend/api/routers/streams.py`)                                          │  │
│  │ • Authenticate via Bearer JWT or Burn Single-Use Stream Ticket                             │  │
│  │ • Enforce Global Per-User Stream Cap (Redis INCR, Max 5) & Local Pod Cap (Max 1,000)      │  │
│  │ • Negotiate Headers: `text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no│  │
│  │ • Yield SSE frames from Client's local `asyncio.Queue` (maxsize=100)                       │  │
│  └─────────────────────────────────────────────┬──────────────────────────────────────────────┘  │
│                                                │                                                 │
│  ┌─────────────────────────────────────────────┴──────────────────────────────────────────────┐  │
│  │ Event Broadcaster Engine (`backend/services/event_broadcaster.py`)                         │  │
│  │ • Registry: `dict[user_id, set[asyncio.Queue]]`                                            │  │
│  │ • Background Redis Subscriber Task (`soc:events:tenant:{user_id}`)                          │  │
│  │ • 15s Periodic Heartbeat Generator (`: ping\n\n`)                                         │  │
│  │ • Queue Overflow Controller (Evicts non-critical; triggers catch-up on critical overflow)  │  │
│  └──────────────────────────────────▲──────────────────▲─────────────────────────────────────┘  │
└─────────────────────────────────────┼──────────────────┼─────────────────────────────────────────┘
                                      │                  │
                Publish to Redis      │                  │ Receive from Redis
                ┌─────────────────────┘                  └──────────────────────┐
                ▼                                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                          REDIS PUB/SUB BUS (Mandatory Multi-Pod Egress)                          │
│                                                                                                  │
│   Channels:                                                                                      │
│   • `soc:events:tenant:{user_id}`  (Tenant-isolated stream)                                      │
│   • `soc:events:admin`             (Global admin stream)                                         │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
                                      ▲
                                      │ Publish cross-pod events
┌─────────────────────────────────────┴────────────────────────────────────────────────────────────┐
│                             PRIMARY TRANSACTION & DURABILITY LAYER                               │
│                                                                                                  │
│  Inside AlertService / NotificationService / MonitoringWorker:                                   │
│  BEGIN TRANSACTION                                                                               │
│    1. INSERT / UPDATE domain table (`alerts`, `notifications`, `monitoring_targets`)            │
│    2. INSERT into `soc_event_stream` (tenant_id, event_type, payload_json)                       │
│       -> Assigns monotonic 64-bit `cursor_id`                                                    │
│  COMMIT TRANSACTION                                                                              │
│                                                                                                  │
│  POST-COMMIT (Async / Non-blocking):                                                             │
│    `event_broadcaster.publish(cursor_id, tenant_id, event_type, payload)`                        │
│    -> Dispatches to Local Queues AND Publishes to Redis Pub/Sub Bus                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Distributed Deployment Model

1. **Authoritative Choice: Redis Pub/Sub (Option A)**:
   - Redis Pub/Sub is **REQUIRED** for multi-pod production deployments.
   - Every FastAPI pod runs an internal `RedisSubscriptionManager` task that manages subscriptions for all locally connected users.
2. **Channel Topology**:
   - `soc:events:tenant:{user_id}`: Dedicated channel per tenant. Pods only subscribe to channels corresponding to users currently connected to that specific pod.
   - `soc:events:admin`: Dedicated channel for system administrators subscribed to the global feed.
3. **Local vs Cross-Pod Delivery**:
   - When an event is committed on Pod 2:
     1. Pod 2 immediately delivers the event to any local clients in `_local_subscribers[user_id]`.
     2. Pod 2 publishes the event payload to Redis channel `soc:events:tenant:{user_id}`.
     3. Pod 1, which holds an active connection for User A, receives the Redis message.
     4. Pod 1 checks `producer_pod_id != self.pod_id` to prevent duplicate delivery, then places the event into User A's local queues.
4. **Development Single-Process Mode**:
   - When running locally without Redis (`settings.REDIS_ENABLED = False`), the system operates entirely on in-memory queues with local delivery.

---

## 9. Authentication Model

To resolve the critical security vulnerability of long-lived JWT exposure in URL query parameters, Phase 5E enforces a dual-authentication model:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ METHOD 1: STANDARD BEARER HEADER (Primary / Recommended)                    │
│                                                                             │
│ Client (@microsoft/fetch-event-source)                                      │
│ Headers: {"Authorization": "Bearer <jwt>"}                                  │
│ -> Validated via standard `get_current_user` dependency.                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      OR
┌─────────────────────────────────────────────────────────────────────────────┐
│ METHOD 2: SINGLE-USE STREAM TICKET (For Native Browser EventSource)         │
│                                                                             │
│ Step 1: POST /v1/streams/ticket                                             │
│ Headers: {"Authorization": "Bearer <jwt>"}                                  │
│ Response: {"ticket": "st_550e8400e29b41d4a716446655440000", "ttl": 30}     │
│                                                                             │
│ Step 2: GET /v1/soc/stream?ticket=st_550e8400e29b41d4a716446655440000       │
│ Server validates ticket in Redis/Cache, burns it immediately (single-use),   │
│ extracts bound user_id, and upgrades connection to SSE.                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Required Security Controls for Stream Tickets:
- **Maximum Lifetime**: Exactly 30 seconds.
- **Single-Use Burn**: The ticket is deleted from Redis atomically upon connection attempt (`GETDEL` or Lua script). Replay attempts return HTTP 401.
- **Purpose & Scope Binding**: The ticket payload binds strictly to `user_id` and purpose `sse_stream`. It cannot be used as an API Bearer token.
- **No Refresh Token Acceptance**: Stream tickets can only be minted by valid, unexpired access tokens.
- **URL Redaction Middleware**: FastAPI middleware strips `ticket=st_*` from query strings before logging HTTP access requests.
- **Referrer Policy**: Responses set `Referrer-Policy: no-referrer` to prevent ticket leakage in outgoing links.

---

## 10. Tenant Isolation Model

1. **Tenant-Partitioned Channels**:
   - Redis channels are strictly partitioned by tenant: `soc:events:tenant:{user_id}`.
   - Cross-tenant subscription is impossible: Pods subscribe only to channels matching `current_user.id` of active connections.
2. **Local Registry Partitioning**:
   - Local in-memory registry is defined as `dict[int, set[asyncio.Queue]]` where the key is the integer `user_id`.
   - Broadcasting iterates strictly through the subscriber set for the matching `user_id`.
3. **Data Redaction in Multi-Tenant Payloads**:
   - All events emitted over tenant channels contain strictly sanitized fields. Foreign tenant identifiers, other users' alerts, and system-wide monitoring targets are filtered at the SQL query level before insertion into `soc_event_stream`.

---

## 11. SSE Protocol

The streaming gateway complies strictly with the W3C Server-Sent Events specification:

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream; charset=utf-8
Cache-Control: no-cache, no-transform
Connection: keep-alive
X-Accel-Buffering: no

: connected (pod_id: worker-pod-3)

event: alert_created
id: 10042
data: {"cursor_id":10042,"event_type":"alert_created","timestamp":"2026-09-15T21:00:00Z","data":{"id":"a1b2c3d4-0000-0000-0000-000000000001","target_id":"t1","severity":"CRITICAL","threat_type":"PHISHING","status":"OPEN"}}

: ping

event: alert_updated
id: 10043
data: {"cursor_id":10043,"event_type":"alert_updated","timestamp":"2026-09-15T21:00:15Z","data":{"id":"a1b2c3d4-0000-0000-0000-000000000001","status":"ACKNOWLEDGED","notes":"Investigating"}}
```

- **Chunked Transfer**: Uses chunked transfer encoding (`Transfer-Encoding: chunked`) over HTTP/1.1 or native HTTP/2 stream frames.
- **Buffering Disabled**: `X-Accel-Buffering: no` ensures reverse proxies (Nginx, Traefik, AWS ALB) flush bytes immediately.

---

## 12. Event Schema

All SSE payloads conform to a strict Pydantic envelope (`SSEEventEnvelope`):

```python
class SSEEventEnvelope(BaseModel):
    cursor_id: int          # Monotonically increasing 64-bit sequence
    event_id: str           # Unique UUID v4 for client-side deduplication
    event_type: str         # alert_created | alert_updated | notification_dispatched | target_status_changed | stream_reset
    timestamp: datetime     # ISO-8601 UTC creation time
    tenant_id: int          # Owning tenant user_id
    data: dict[str, Any]    # Sanitized event payload (max 16 KB)
```

### Supported Event Types:
1. `alert_created`: High/Critical/Medium/Low security alert generated by monitoring probe.
2. `alert_updated`: Alert state transition (`ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`, `REOPENED`).
3. `notification_dispatched`: New in-app alert notification dispatched, including updated `unread_count`.
4. `target_status_changed`: Monitoring target operational status changed (`ACTIVE`, `PAUSED`, `SUSPENDED`).
5. `stream_reset`: Signal emitted when client cursor is too old, instructing client to perform full REST resynchronization.

---

## 13. Event Ordering Guarantees

| Scope | Ordering Guarantee | Mechanism |
|---|---|---|
| **Within One Tenant** | **Strict Total Order** | Monotonic 64-bit integer cursor (`cursor_id`) generated by database sequence (`BIGSERIAL`). |
| **Within One Alert** | **Strict Total Order** | State transitions commit sequentially (`created` < `acknowledged` < `resolved`). `cursor_id` strictly reflects commit order. |
| **Across Tenants** | **Causal / Sequence Order** | Global ordering across tenants is monotonic by `cursor_id`, but tenants only observe their own subsequence. |
| **Across Pods** | **Strict Total Order** | All pods serialize events through the central database `soc_event_stream`. Redis Pub/Sub preserves message order per tenant channel. |
| **On Reconnect / Replay** | **Strict Total Order** | Replay queries `ORDER BY cursor_id ASC`, guaranteeing identical chronological delivery. |

---

## 14. Replay / Last-Event-ID Protocol

1. **Client Reconnection Request**:
   - The browser automatically sends the header `Last-Event-ID: <cursor_id>` upon reconnecting.
   - Example: `Last-Event-ID: 10042`
2. **Replay Query Engine**:
   - The server inspects `Last-Event-ID`. If present:
     ```sql
     SELECT cursor_id, event_id, event_type, payload_json, created_at
     FROM soc_event_stream
     WHERE tenant_id = :user_id AND cursor_id > :last_event_id
     ORDER BY cursor_id ASC
     LIMIT 100;
     ```
   - All missed events are yielded immediately to the client before the stream switches to live Redis listening.
3. **Replay Window Limit & Expiry**:
   - The durable event table retains events for **7 days** (or max 50,000 events per tenant).
   - If the requested `Last-Event-ID` is older than the oldest available cursor in the database (or older than 7 days):
     - The server emits `event: stream_reset` with `data: {"action": "resync_required", "reason": "cursor_expired"}`.
     - The client catches this event, clears its local cache, and fetches baseline state via REST (`GET /v1/alerts`, `GET /v1/notifications`).

---

## 15. Durable Source of Truth: `soc_event_stream`

Phase 5E **formally introduces an append-only event stream table** (`soc_event_stream`) to replace the flawed "zero migration" assumption.

### Database Schema Definition:
```sql
CREATE TABLE soc_event_stream (
    cursor_id       BIGSERIAL PRIMARY KEY,           -- Monotonically increasing 64-bit sequence
    event_id        VARCHAR(36) NOT NULL UNIQUE,     -- UUID v4 for deduplication
    tenant_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel         VARCHAR(64) NOT NULL,            -- 'alerts', 'notifications', 'monitor'
    event_type      VARCHAR(64) NOT NULL,            -- 'alert_created', etc.
    aggregate_id    VARCHAR(64) NOT NULL,            -- Associated Alert UUID or Target UUID
    payload_json    TEXT NOT NULL,                   -- Sanitized JSON string (max 16KB)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_soc_events_tenant_cursor ON soc_event_stream (tenant_id, cursor_id);
CREATE INDEX idx_soc_events_created_at ON soc_event_stream (created_at);
```

### Atomic Transactional Boundary:
To eliminate the crash-after-commit event loss vulnerability:
1. `AlertService` or `NotificationService` performs business logic.
2. In the **SAME database transaction**:
   - Insert/Update domain model (`Alert`, `Notification`).
   - Insert corresponding event row into `soc_event_stream`.
3. `session.commit()` executes.
4. If the process crashes at this exact instant, **the event is safely committed to disk**. Upon pod restart or client reconnect, the event is replayed from `soc_event_stream`.
5. After successful commit, `event_broadcaster.publish_event_nowait(...)` is invoked to notify in-memory queues and Redis.

---

## 16. Redis / Distributed Fan-Out Behavior

1. **Redis Pub/Sub Architecture**:
   - When `publish_event_nowait(...)` runs, it enqueues the event to an internal in-process queue.
   - A dedicated async worker task (`RedisPublisherTask`) pops from the queue and executes:
     `await redis_client.publish(f"soc:events:tenant:{tenant_id}", serialized_event)`
   - The primary database transaction never awaits Redis network I/O.
2. **Redis Outage / Degraded Mode (Option B: Degrade Locally with DB Recovery)**:
   - If Redis crashes or experiences a network partition:
     1. Local in-process delivery continues normally for clients connected to the originating pod.
     2. Cross-pod publishing logs a WARNING and trips the Prometheus metric `soc_redis_pubsub_healthy{status="0"}`.
     3. No database transactions fail (Redis is non-blocking post-commit).
     4. Because all events are durable in `soc_event_stream`, any client on another pod that reconnects or queries `Last-Event-ID` immediately recovers the missed events.
     5. When Redis reconnects, the background subscriber automatically resubscribes with exponential backoff.

---

## 17. Queue Limits and Overflow Policy

1. **Per-Stream Queue Capacity**: Exactly 100 events (`asyncio.Queue(maxsize=100)`).
2. **Event Criticality Classification**:
   - **Critical Events**: `alert_created` (for `HIGH` or `CRITICAL` severity), `target_status_changed` (`SUSPENDED`).
   - **Non-Critical Events**: `unread_count_updated`, `alert_updated` (`RESOLVED`, `DISMISSED`), `alert_created` (`INFO`, `LOW`).
3. **Overflow Policy**:
   - When a slow client's queue reaches 100 items:
     - **Step 1**: If any non-critical event exists in the queue, evict the oldest non-critical event to accommodate the new event. Coalesce duplicate `unread_count_updated` events into the latest count.
     - **Step 2**: If ALL 100 events in the queue are critical, **NEVER silently discard a critical security event**.
     - **Step 3**: The server marks the client connection as compromised by lag, sends a terminal SSE control frame:
       `event: stream_overflow\ndata: {"reconnect": true, "last_delivered_id": 10042}\n\n`
     - **Step 4**: The server closes the socket. The client's `fetch-event-source` automatically reconnects with `Last-Event-ID: 10042`, cleanly replaying the events from `soc_event_stream` at the client's own reading pace.

---

## 18. Connection Limits

1. **Global Per-User Limit (Max 5 Streams Globally)**:
   - Enforced across all pods using an atomic Redis counter:
     Key: `soc:connections:user:{user_id}`
   - When a client connects on any pod:
     `count = await redis.incr(f"soc:connections:user:{user_id}")`
     `await redis.expire(f"soc:connections:user:{user_id}", 120)` (Refreshed every 15s heartbeat).
   - If `count > 5`:
     `await redis.decr(f"soc:connections:user:{user_id}")`
     Raise `HTTPException(status_code=429, detail="Maximum concurrent streaming connections (5) exceeded.")`
   - When connection closes: `await redis.decr(f"soc:connections:user:{user_id}")`.
   - In SQLite dev mode: In-memory atomic integer per `user_id`.
2. **Per-Pod Process Limit (Max 1,000 Streams)**:
   - Each FastAPI worker process maintains an atomic connection counter. If active local streams reach 1,000, new connections receive `HTTP 503 Service Unavailable` with `Retry-After: 30`.

---

## 19. Disconnect Handling

1. **Immediate Cleanup**:
   - When a client disconnects, drops network, or navigates away, Starlette's `StreamingResponse` raises `asyncio.CancelledError`.
   - The generator catches `CancelledError` in a `finally:` block:
     1. Removes client's `asyncio.Queue` from `_local_subscribers[user_id]`.
     2. Decrements `soc:connections:user:{user_id}` in Redis.
     3. Decrements local active stream counter.
     4. If `len(_local_subscribers[user_id]) == 0`, cancels the Redis subscription task for that tenant channel to save network bandwidth.
2. **Zero Memory Leaks**:
   - Proven by automated leak tests: 50 open connections abruptly terminated must leave 0 orphaned queues and 0 lingering subscriber tasks.

---

## 20. Heartbeat

1. **Interval**: Exactly **15 seconds** (`HEARTBEAT_INTERVAL_SECONDS = 15`).
2. **Payload**: SSE comment format:
   ```
   : ping
   ```
3. **Reverse Proxy Keep-Alive**:
   - Reverse proxies and cloud firewalls (ALB, Cloudflare, Nginx) drop idle TCP streams after 30–60 seconds. A 15s ping guarantees continuous traffic, preventing dropped connections.
4. **Dead Socket Detection**:
   - If a client experiences a silent network drop (e.g. WiFi cut without TCP FIN), the next 15s ping write raises `BrokenPipeError` / `ConnectionResetError`, triggering instant cleanup.

---

## 21. Lifecycle / Shutdown

1. **FastAPI Lifespan Teardown**:
   - During server shutdown (`lifespan` context exit in `backend/main.py`):
     1. `EventBroadcaster.stop()` is invoked.
     2. Broadcasts a clean terminal frame to all active streams:
        `event: server_shutdown\ndata: {"reconnect_after": 5}\n\n`
     3. Closes all client queues and cancels background Redis subscription tasks.
     4. Awaits stream task cancellation with a hard **3.0-second timeout**.
     5. Disconnects Redis client cleanly.

---

## 22. Admin Stream Security

The system exposes a single, canonical admin endpoint: `GET /v1/admin/soc/stream`.

1. **Canonical Route**: `/v1/admin/soc/stream` strictly. The legacy alias `/v1/admin/streams/soc` is removed.
2. **RBAC Gate**: Requires `current_user.role == "admin"`. Standard users receive `HTTP 403 Forbidden`.
3. **Payload Sanitization**:
   - Admin stream receives cross-tenant threat alerts, but sensitive fields (hashed passwords, webhook secrets, customer encryption keys, PII headers) are strictly redacted.
4. **Connection Cap**: Max 2 concurrent admin streams per admin account; max 10 admin streams globally.
5. **Audit Logging**: Every admin stream connection is logged to `audit_events` with admin ID, timestamp, client IP, and connection duration.

---

## 23. Reverse Proxy & Infrastructure Requirements

To prevent buffering and timeouts across enterprise reverse proxies:

| Infrastructure Layer | Mandatory Configuration | Rationale |
|---|---|---|
| **FastAPI Response Headers** | `X-Accel-Buffering: no`<br>`Cache-Control: no-cache, no-transform`<br>`Connection: keep-alive` | Disables Nginx/proxy buffer accumulation. |
| **Nginx Ingress** | `proxy_buffering off;`<br>`proxy_cache off;`<br>`proxy_read_timeout 300s;`<br>`proxy_http_version 1.1;` | Prevents Nginx from holding 4KB chunks before flushing to client. |
| **AWS Application Load Balancer** | Idle timeout >= 60s | 15s ping safely prevents ALB 60s idle disconnection. |
| **Cloudflare** | Proxy buffering disabled for `/v1/*/stream` | Prevents Cloudflare Error 524 (100s timeout). |
| **Traefik** | `respondingTimeouts.idleTimeout: 300s` | Maintains open HTTP/2 multiplexed streams. |

---

## 24. PostgreSQL Staging Harness (AC24 Resolution)

Phase 5D left AC24 as `NOT VERIFIED`. Phase 5E delivers the complete, turnkey staging harness to **execute, verify, and resolve AC24**.

### Turnkey Staging Environment: `docker-compose.staging.yml`
```yaml
version: '3.8'
services:
  staging_postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: cyber_soc_staging
      POSTGRES_USER: soc_admin
      POSTGRES_PASSWORD: staging_secure_password_123!
    ports:
      - "5433:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U soc_admin -d cyber_soc_staging"]
      interval: 3s
      timeout: 3s
      retries: 5

  staging_redis:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 3s
      retries: 5
```

### Staging Verification Test Suite: `tests/staging/test_postgres_staging_concurrency.py`
Executes against the live staging PostgreSQL container to verify all 8 distributed invariants:
1. **Advisory Lock Leader Election**: 5 concurrent scheduler instances race for leader lock; exactly 1 acquires leader; remaining 4 stand by; leader termination triggers immediate failover.
2. **SKIP LOCKED Outbox Claiming**: 5 concurrent worker processes claim jobs from `notification_outbox` simultaneously; zero jobs claimed twice; zero deadlock exceptions.
3. **Monotonic Epoch Fencing**: Stale workers with expired lease or superseded epoch attempt writes; database rejects writes with 0 rows affected.
4. **Multi-Pod SSE Fanout**: Event created on Worker 1 via PostgreSQL commit publishes to Redis; Worker 2 picks up event and delivers to listening client within 200ms.
5. **`soc_event_stream` Monotonicity**: 50 concurrent transactions insert alerts; all generated `cursor_id` values are strictly gapless and monotonic.
6. **Lease Guard Recovery**: Expired execution lease (`execution_expires_at < NOW()`) reclaimed by active scheduler.

---

## 25. Acceptance Criteria

Acceptance criteria are strictly categorized with unique, non-overlapping prefixes:

### Functional Correctness (`AC-FUNC`):
- [ ] **AC-FUNC-01**: `GET /v1/alerts/stream` establishes a valid HTTP 200 `text/event-stream` connection with valid JWT Bearer token.
- [ ] **AC-FUNC-02**: `GET /v1/notifications/stream` streams live in-app notifications and unread badge counts immediately upon outbox creation.
- [ ] **AC-FUNC-03**: `GET /v1/soc/stream` multiplexes alerts, notifications, and monitor target state changes in a single connection.
- [ ] **AC-FUNC-04**: When an alert status changes (`OPEN` → `ACKNOWLEDGED` → `RESOLVED` → `DISMISSED`), an `alert_updated` event is received by the client within 500ms.
- [ ] **AC-FUNC-05**: Reconnection with `Last-Event-ID: <cursor_id>` replays all missed events from `soc_event_stream` in exact chronological order (`ORDER BY cursor_id ASC`).
- [ ] **AC-FUNC-06**: When a client requests a `Last-Event-ID` older than retention TTL, server emits `event: stream_reset` requiring client REST resynchronization.
- [ ] **AC-FUNC-07**: Query parameter `?min_severity=HIGH` filters out `LOW` and `MEDIUM` alerts from the delivered SSE stream.
- [ ] **AC-FUNC-08**: Idle streams emit a `: ping\n\n` heartbeat comment every 15 seconds (±1s).

### Security & DoS Protection (`AC-SEC`):
- [ ] **AC-SEC-01**: Unauthenticated requests to `/v1/*/stream` without token return HTTP 401 Unauthorized.
- [ ] **AC-SEC-02**: Single-Use Stream Ticket endpoint (`POST /v1/streams/ticket`) validates JWT, generates a 30s ticket, and burns it upon connection handshake (`GETDEL`). Replay returns HTTP 401.
- [ ] **AC-SEC-03**: Strict Multi-Tenant Isolation: User A connected to `/v1/alerts/stream` receives 0 events for targets or alerts owned by User B.
- [ ] **AC-SEC-04**: Global per-user connection limit of 5 is strictly enforced via Redis; a 6th concurrent stream returns HTTP 429 Too Many Requests.
- [ ] **AC-SEC-05**: Non-admin requesting `/v1/admin/soc/stream` is rejected with HTTP 403 Forbidden.
- [ ] **AC-SEC-06**: Every admin stream connection and disconnection is recorded in `audit_events` with admin user ID and IP address.
- [ ] **AC-SEC-07**: Payloads serialized to SSE streams contain zero sensitive credentials (passwords, webhook secrets, DB connection strings).
- [ ] **AC-SEC-08**: User account deactivation immediately disconnects active SSE streams within 60 seconds.

### Concurrency & Performance (`AC-CONC`):
- [ ] **AC-CONC-01**: 50 concurrent SSE streams receive simultaneous broadcast events with zero event loop starvation.
- [ ] **AC-CONC-02**: Client disconnect cleanly unregisters listener queue and decrements Redis counter within 500ms (zero memory leak).
- [ ] **AC-CONC-03**: Slow client queue overflow: when queue hits 100 items, oldest non-critical events are evicted. If all 100 are critical, connection closes with reconnect frame to trigger database catchup.
- [ ] **AC-CONC-04**: Local pod capacity limit (1,000 streams) rejects additional connections with HTTP 503 and `Retry-After: 30`.
- [ ] **AC-CONC-05**: Database transactions never await Redis I/O; `publish_event_nowait()` executes via non-blocking async queue.
- [ ] **AC-CONC-06**: FastAPI lifespan shutdown cleanly terminates all open streams with `: server_shutdown\n\n` within 3.0 seconds.

### PostgreSQL Distributed Staging (`AC-STAG`):
- [ ] **AC-STAG-01**: `docker-compose.staging.yml` spins up clean PostgreSQL 16 and Redis 7 containers.
- [ ] **AC-STAG-02**: `tests/staging/test_postgres_staging_concurrency.py` verifies 5-worker `SELECT ... FOR UPDATE SKIP LOCKED` outbox claiming with zero duplicates.
- [ ] **AC-STAG-03**: Verifies multi-pod PostgreSQL advisory lock leader election and immediate failover upon leader termination.
- [ ] **AC-STAG-04**: Verifies worker lease expiry and monotonic epoch write-back fencing on live PostgreSQL.
- [ ] **AC-STAG-05**: Verifies cross-pod event fan-out: event committed on Pod 1 reaches client connected to Pod 2 via Redis Pub/Sub within 300ms.
- [ ] **AC-STAG-06**: Automated test execution produces reproducible JUnit XML and markdown verification report.

### Quality & Regression (`AC-QUAL`):
- [ ] **AC-QUAL-01**: All 8 protected infrastructure files remain 100% untouched.
- [ ] **AC-QUAL-02**: The 5 pre-existing working-tree files remain untouched.
- [ ] **AC-QUAL-03**: Phase 5D notification dispatcher and webhook outbox logic suffer zero behavioral regression.
- [ ] **AC-QUAL-04**: Ruff linter passes with 0 errors and 0 warnings on all new files.
- [ ] **AC-QUAL-05**: Complete test suite passes (all 524 existing tests + new Phase 5E tests).

---

## 26. Security Gates

Implementation authorization must pass the following sequence of quality gates:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   GATE 1    │────▶│   GATE 2    │────▶│   GATE 3    │────▶│   GATE 4    │────▶│   GATE 5    │
│ Human Lead  │     │ Static Lint │     │ Unit & API  │     │ PostgreSQL  │     │ CodeRabbit  │
│ Arch v1.1   │     │  & Typing   │     │ Integration │     │   Staging   │     │ Independent │
│  Approval   │     │ (Ruff 100%) │     │ (550+ tests)│     │ Harness AC24│     │   Review    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

## 27. Test Strategy

1. **Unit Tests (`tests/unit/test_event_broadcaster.py`)**:
   - Broadcaster queue lifecycle (register, unregister, duplicate prevention).
   - Queue overflow eviction logic (evicting non-critical vs tripping overflow on critical).
   - Monotonic cursor sequencing and envelope serialization.
   - Heartbeat generator timing and cancellation.
2. **API Integration Tests (`tests/integration/test_sse_streams_api.py`)**:
   - Streaming HTTP client tests using `httpx.AsyncClient`.
   - Bearer token authentication and ticket exchange handshake.
   - Reconnection with `Last-Event-ID` asserting exact event replay.
   - Multi-tenant boundary tests asserting zero cross-tenant leak.
   - Admin RBAC tests asserting 403 for non-admin users.
3. **Concurrency & Load Tests (`tests/integration/test_sse_concurrency.py`)**:
   - 50 concurrent SSE streams receiving 500 interleaved events.
   - Abrupt socket disconnect tests asserting zero memory leaks.
   - Per-user connection limit stress tests asserting HTTP 429 on the 6th stream.
4. **Staging Harness Execution (`tests/staging/test_postgres_staging_concurrency.py`)**:
   - Executes under `docker-compose.staging.yml` to definitively certify AC24.

---

## 28. Deployment Requirements

1. **Environment Variables (`backend/core/config.py`)**:
   - `SSE_HEARTBEAT_INTERVAL_SECONDS`: Default `15`.
   - `SSE_MAX_CONCURRENT_STREAMS_PER_USER`: Default `5`.
   - `SSE_MAX_LOCAL_STREAMS_PER_POD`: Default `1000`.
   - `SSE_EVENT_RETENTION_DAYS`: Default `7`.
   - `REDIS_PUBSUB_ENABLED`: Default `True` (auto-falls back to in-process for dev).
2. **Reverse Proxy Rules**:
   - Ensure Nginx/Traefik disables buffering for `/v1/*/stream`.

---

## 29. File-Level Implementation Plan

### New Files to Create:
1. `backend/database/models.py` [EXTEND] — Declare `SOCEventStream` SQLAlchemy model.
2. `migrations/versions/f8a9b0c1d2e3_sprint5_phase5e_soc_event_stream.py` [NEW] — Migration creating `soc_event_stream` table and indexes.
3. `backend/schemas/stream.py` [NEW] — Pydantic models for SSE events, stream ticket exchange, and payload envelopes.
4. `backend/services/event_broadcaster.py` [NEW] — Core `EventBroadcaster` singleton managing local queues, Redis Pub/Sub subscriber/publisher, connection counters, and heartbeats.
5. `backend/api/routers/streams.py` [NEW] — FastAPI router exposing `/v1/alerts/stream`, `/v1/notifications/stream`, `/v1/soc/stream`, `/v1/admin/soc/stream`, and `POST /v1/streams/ticket`.
6. `tests/unit/test_event_broadcaster.py` [NEW] — Broadcaster unit tests.
7. `tests/integration/test_sse_streams_api.py` [NEW] — API integration tests.
8. `tests/integration/test_sse_concurrency.py` [NEW] — Concurrency and leak tests.
9. `tests/staging/test_postgres_staging_concurrency.py` [NEW] — AC24 staging test suite.
10. `docker-compose.staging.yml` [NEW] — Staging PostgreSQL and Redis compose environment.

### Existing Files to Modify (Minimal & Non-Breaking):
1. `backend/main.py` [MODIFY] — Mount `streams.router` under `/v1`; initialize and cleanly stop `event_broadcaster` in lifespan context.
2. `backend/services/alert_service.py` [MODIFY] — In `create_alert` and triage state transitions, insert row to `soc_event_stream` inside the commit transaction, and call `event_broadcaster.publish_event_nowait()` post-commit.
3. `backend/services/notification_service.py` [MODIFY] — In notification creation, insert row to `soc_event_stream` and call `event_broadcaster.publish_event_nowait()`.

---

## 30. Protected Files & Invariants

The 8 authoritative protected files must NEVER be modified:
1. `backend/services/incident_service.py`
2. `backend/services/monitoring_probe.py`
3. `backend/services/scheduler_service.py`
4. `backend/core/security_network.py`
5. `backend/services/threat_intel.py`
6. `backend/services/intel_enrichment.py`
7. `backend/schemas/soc.py`
8. `ml/**`

The 5 pre-existing working-tree files must remain untouched:
1. `src/data/clean.py`
2. `src/data/inspect.py`
3. `src/data/merge.py`
4. `tests/integration/test_analytics_api.py`
5. `tests/unit/test_intel_enrichment.py`

Phase 5D completed files (`notification_dispatcher.py`, `migrations/versions/e7f8a9b0c1d2_...`) are frozen.

---

## 31. Risks

| Risk | Likelihood | Impact | Mitigation Strategy |
|---|---|---|---|
| **Reverse Proxy Chunk Buffering** | Medium | High | Enforce `X-Accel-Buffering: no`, emit `: connected` comment immediately on connection, and maintain 15s heartbeats. |
| **Redis Network Partition** | Low | Medium | Degrade to local pod delivery, alert via metrics, and rely on durable `soc_event_stream` replay on client reconnect. |
| **High Connection Volume in Multi-Tab Browsing** | Medium | Medium | Provide multiplexed `/v1/soc/stream` combining alerts, notifications, and monitor events in 1 stream, respecting the 5-stream limit. |
| **Long-Running DB Bloat** | Low | Low | Bounded 7-day TTL index on `soc_event_stream` with periodic pruning. |

---

## 32. Explicit Resolved Ambiguities

1. **Multi-Pod Delivery**: Resolved. Redis Pub/Sub is strictly required for multi-pod production. In-memory queues are used strictly as the local delivery layer.
2. **Crash-After-Commit Event Loss**: Resolved. An append-only `soc_event_stream` table is committed atomically with the domain transaction.
3. **Replay Cursor Semantics**: Resolved. Random UUIDs are abandoned as cursors; monotonic 64-bit integer `cursor_id` values drive O(1) indexed `Last-Event-ID` replay.
4. **JWT in Query String**: Resolved. Deprecated. Bearer headers are primary; a 30s single-use burned stream ticket (`POST /v1/streams/ticket`) is provided for native EventSource.
5. **Admin Route Canonical Name**: Resolved. Canonical route is `/v1/admin/soc/stream` exclusively.
6. **Acceptance Criteria Numbering**: Resolved. Rewritten into disjoint prefix groups (`AC-FUNC`, `AC-SEC`, `AC-CONC`, `AC-STAG`, `AC-QUAL`).
7. **Connection Limit Scope**: Resolved. Per-user cap (5) is globally enforced via Redis; per-pod cap (1,000) is locally enforced per process.
8. **Queue Overflow Policy**: Resolved. Non-critical events are evicted; critical events trigger a clean stream reconnect frame, guaranteeing zero silent alert drops.
9. **Zero Schema Migration Claim**: Resolved. Formally corrected; migration `f8a9b0c1d2e3` introduced for durable `soc_event_stream`.
10. **AC24 Staging Status**: Resolved. Phase 5E delivers `docker-compose.staging.yml` and `test_postgres_staging_concurrency.py` to definitively execute and certify AC24.

---

## 33. Human Approval Gate

Implementation is strictly blocked until human review and authorization of this specification are granted.

---

STATUS: AWAITING HUMAN APPROVAL — NO IMPLEMENTATION AUTHORIZED
