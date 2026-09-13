# SPRINT 5 — PHASE 5D ARCHITECTURE & SECURITY SPECIFICATION v1.1
## Durable SOC Alert Delivery, Outbox Protocol, Secure Webhook Egress & Notification Infrastructure
### Document: `docs/architecture/sprint5_phase5d_arch_spec_v1_1.md`
### Status: ARCHITECTURE SPECIFICATION v1.1 — NO IMPLEMENTATION AUTHORIZED
### Baseline: `43d94a6c970de64c077ecc136a40ca04a135df2d` (CI: SUCCESS, 497 passed, 2 skipped)

---

> [!IMPORTANT]
> **READ-ONLY ARCHITECTURE REFINEMENT SPECIFICATION (v1.1).**
> This specification resolves all critical vulnerabilities and operational risks identified in the v1.0 discovery cycle:
> - Replaces fire-and-forget `asyncio.create_task` with a **durable database Outbox pattern**.
> - Enforces **At-Least-Once delivery** with deterministic **Idempotency Keys**.
> - Resolves webhook secret security, defining **AES-256-GCM / PBKDF2 encryption at rest**, 32-byte entropy minimum, and write-only semantics.
> - Specifies the **exact canonical HMAC-SHA256 signing contract** and 300s replay window.
> - Specifies deterministic **retry/backoff mechanics**, distinguishing 2xx, 3xx, 4xx, 5xx, and SSRF aborts.
> - Establishes an **atomic database circuit breaker** safe under 50-way concurrency.
> - Formulates an authoritative **Alert-to-Notification matrix**.
> - Proves **delivery-time SSRF security** with DNS pinning and redirect blocking, reusing [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py) without modification.
>
> NO source code, migrations, tests, or configurations are modified during this task.
> Implementation authorization is strictly reserved for a subsequent authorized phase.

---

# Table of Contents
1. [Executive Summary](#executive-summary)
2. [Current State](#current-state)
3. [Problem Statement](#problem-statement)
4. [Goals](#goals)
5. [Non-Goals](#non-goals)
6. [Component Architecture](#component-architecture)
7. [Durable Delivery Architecture](#durable-delivery-architecture)
8. [Notification Lifecycle](#notification-lifecycle)
9. [Outbox Lifecycle](#outbox-lifecycle)
10. [Webhook Security](#webhook-security)
11. [HMAC Contract](#hmac-contract)
12. [Retry Model](#retry-model)
13. [Circuit Breaker](#circuit-breaker)
14. [Idempotency Model](#idempotency-model)
15. [Alert-to-Notification Matrix](#alert-to-notification-matrix)
16. [Database Design](#database-design)
17. [Transaction Boundaries](#transaction-boundaries)
18. [PostgreSQL Concurrency](#postgresql-concurrency)
19. [SQLite Test Strategy](#sqlite-test-strategy)
20. [API Contract](#api-contract)
21. [Authentication and RBAC](#authentication-and-rbac)
22. [Tenant Isolation](#tenant-isolation)
23. [Resource Limits](#resource-limits)
24. [Observability](#observability)
25. [Audit Model](#audit-model)
26. [Threat Model](#threat-model)
27. [Security Gates](#security-gates)
28. [Test Strategy](#test-strategy)
29. [Acceptance Criteria](#acceptance-criteria)
30. [File-Level Change Plan](#file-level-change-plan)
31. [Protected Files](#protected-files)
32. [Dependency Impact](#dependency-impact)
33. [CI/CD Impact](#cicd-impact)
34. [Staging Verification](#staging-verification)
35. [Rollback Plan](#rollback-plan)
36. [Risks](#risks)
37. [Open Questions](#open-questions)
38. [Implementation Order](#implementation-order)
39. [Human Approval Gate](#human-approval-gate)

---

# Executive Summary

Sprint 5 established autonomous threat monitoring, probe execution, scheduler fencing, and alert triage across Sprints 5A, 5B, and 5C. However, the system currently lacks any mechanism to push detected security events to human analysts or external orchestration platforms (SIEM, SOAR, Slack, PagerDuty).

Sprint 5 Phase 5D delivers the **authoritative notification and alert delivery arm** of the suite. It activates the existing `Notification` and `NotificationPreference` database schemas and introduces a **durable, transactional Outbox dispatcher**.

By integrating an Outbox pattern directly into PostgreSQL/SQLAlchemy, Phase 5D achieves:
- **Zero Loss of High-Severity Alerts**: Even across process crashes, container deployments, and event-loop terminations.
- **Fail-Closed Outbound Security**: Complete immunity against outbound SSRF, DNS rebinding, and metadata theft via strict reuse of [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py).
- **Cryptographic Trust**: HMAC-SHA256 signature verification and timestamped anti-replay headers.
- **Decoupled Performance**: Non-blocking delivery that guarantees detection worker loops and alert triage transactions are never held hostage to external network latencies.

---

# Current State

- **Sprint 5A**: Targets created, validated, and quota-controlled.
- **Sprint 5B**: Autonomous worker pool, SSRF-safe probe execution, PG advisory leader election, epoch fencing, 59-feature inference, and stale-worker writeback fencing.
- **Sprint 5C**: Authoritative 4-state alert triage (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`), threat recurrence, target operations (`pause`, `resume`, `reactivate`, `check-now`), execution diagnostics, and 24-hour telemetry.
- **Baseline Commit**: `43d94a6c970de64c077ecc136a40ca04a135df2d` (Full repo: 497 passed, 2 skipped, 0 failures; CI: GREEN).
- **Existing Models**: `Notification` and `NotificationPreference` models already defined in [`backend/database/models.py`](file:///E:/AI-Cyber-Security-Suite/backend/database/models.py) and migrated in `c5e6f7a8b9c0_sprint5_soc_monitoring_tables.py`.

---

# Problem Statement

In the v1.0 architecture draft, notifications were dispatched via in-memory `asyncio.create_task()` fire-and-forget routines. In production:
1. **Durable Delivery Failure**: A pod restart, unhandled error, or deployment immediately drops in-flight tasks, permanently losing critical zero-day notifications.
2. **Secret Compromise Risk**: Storing plaintext webhook secrets creates database credential leakage risks.
3. **SSRF Vector**: Poorly protected outbound webhooks can be abused to attack internal cloud metadata (`169.254.169.254`) or internal VPC services.
4. **Replay & Amplification**: Alert storms could turn the platform into a DDoS vector against third-party endpoints.
5. **Concurrency Races**: Naive failure-counter increments lead to lost updates or flapping circuit breakers under concurrent load.

Phase 5D v1.1 comprehensively resolves all of these challenges.

---

# Goals

1. **Transactional Durability (Outbox Pattern)**: Write notification jobs atomically within the same database transaction that commits the alert or incident.
2. **At-Least-Once Delivery with Idempotency**: Provide guaranteed delivery for high-priority security notifications with a deterministic `X-SOC-Delivery-ID` idempotency key.
3. **Hardened Egress SSRF Defense**: Guarantee zero outbound requests reach private, loopback, or cloud-metadata IPs by enforcing pre-flight validation and delivery-time DNS pinning via [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py).
4. **Cryptographic Integrity & Anti-Replay**: Implement canonical HMAC-SHA256 signature calculation with a 300-second timestamp tolerance window.
5. **Atomic Multi-Pod Circuit Breaker**: Prevent alert storms and denial-of-service against third-party endpoints through an atomic consecutive-failure tripwire.
6. **Zero Regression on Existing Pipelines**: Ensure zero modification to frozen ML pipelines, scheduler leadership, probe networking, or incident services.

---

# Non-Goals

1. **External Message Brokers**: No Celery, RabbitMQ, Kafka, or Redis Streams. The outbox is implemented natively via PostgreSQL (`SKIP LOCKED`) and SQLAlchemy.
2. **SMTP / Direct Email Transport**: Dedicated email delivery (SendGrid/SES) is deferred to enterprise integrations.
3. **Frontend UI Implementation**: All React 18 UI components, notification drawers, and settings pages belong strictly to Sprint 6.
4. **Real-time WebSockets / SSE**: Push streams to browser clients belong to Sprint 6.
5. **Inbound Webhook Handlers**: Egress dispatch only; no external command ingestion.

---

# Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION & TRIAGE CORE                            │
│                                                                             │
│   MonitoringWorker ──▶ AlertService.process_event()                         │
│                                │                                            │
│                                ▼                                            │
│                     [PRIMARY DB TRANSACTION]                                │
│                     - INSERT/UPDATE Alert row                               │
│                     - INSERT Notification (In-App)                          │
│                     - INSERT NotificationOutbox (Pending Webhook)           │
│                     COMMIT TRANSACTION                                      │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 │ DB Polling / SKIP LOCKED
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 NOTIFICATION DISPATCHER (Background Engine)                 │
│                                                                             │
│   1. Claim Job: UPDATE ... SET locked_at = NOW() SKIP LOCKED                │
│   2. SSRF Guard: resolve_and_validate_host(webhook_url)                     │
│   3. DNS Pinning: Connect directly to validated IP with Host header         │
│   4. Cryptographic Signing: HMAC-SHA256(secret, t + "." + raw_body)         │
│   5. Dispatch: HTTP POST (timeout 3.0s, follow_redirects=False)             │
│   6. Outcome:                                                               │
│      - 2xx: DELIVERED (reset circuit breaker counter)                       │
│      - 3xx/4xx/SSRF: FAILED (permanent, trip circuit breaker)               │
│      - 5xx/Timeout: PENDING (increment attempt, compute backoff)            │
│   7. Update Outbox row & AuditEvent                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# Durable Delivery Architecture

### Why In-Memory Dispatch is Banned
Using `asyncio.create_task()` decouples execution from persistence. If the container crashes or scales down 50ms after the alert commits, the notification task vanishes forever.

### The Outbox Protocol
1. **Atomic Enqueue**: When `AlertService.process_event()` or `MonitoringWorker` creates a qualifying alert, it writes an entry into `notification_outbox` **within the same database transaction**. If the alert commit rolls back, the notification rolls back. If the alert commits, the notification is durably on disk.
2. **Decoupled Polling Dispatcher**: A lightweight background asyncio task (`NotificationDispatcher`) periodically queries `notification_outbox` for eligible jobs (`status = 'PENDING' AND next_attempt_at <= NOW() AND (locked_at IS NULL OR locked_at < NOW() - INTERVAL '60 seconds')`).
3. **Zero Lock Contention**: The worker claims jobs using `SELECT ... FOR UPDATE SKIP LOCKED` (PostgreSQL), allowing multiple application replicas to process outbox entries concurrently without blocking each other.

---

# Notification Lifecycle

In-App notifications (`notifications` table) represent user-facing inbox entries:
1. **Creation**: Inserted synchronously with status `is_read = False`.
2. **Active State**: Displayed in `GET /v1/notifications`; counted in `GET /v1/notifications/unread-count`.
3. **Read State**: Transitioned to `is_read = True` via `POST /v1/notifications/{uuid}/read` or `POST /v1/notifications/mark-all-read`.
4. **Archival & Purge**: Read notifications older than 30 days are purged by an automated background sweep. `AuditEvent` records are **never** touched by this purge.

---

# Outbox Lifecycle

Outbox jobs (`notification_outbox` table) represent external webhook delivery tasks:

```
                  ┌──────────────┐
                  │   PENDING    │◀──────────────────┐
                  └──────┬───────┘                   │
                         │ worker claims             │ retryable 5xx / timeout
                         ▼                           │ attempt < 3
                  ┌──────────────┐                   │
                  │  PROCESSING  │───────────────────┘
                  └──────┬───────┘
                         │
         ┌───────────────┴───────────────┐
         │ 2xx response                  │ 4xx / 3xx / SSRF / attempt >= 3
         ▼                               ▼
  ┌──────────────┐                ┌──────────────┐
  │  DELIVERED   │                │    FAILED    │
  └──────────────┘                └──────────────┘
```

- `PENDING`: Waiting for initial dispatch or scheduled for retry.
- `PROCESSING`: Claimed by a worker; locked with `locked_at = NOW()`.
- `DELIVERED`: Terminal success (2xx HTTP response received).
- `FAILED`: Terminal failure (permanent client error, SSRF violation, or 3 failed retry attempts).

---

# Webhook Security

### Secret Entropy & Generation
- Webhook signing secrets **MUST have at least 32 bytes of cryptographically secure randomness** (256 bits).
- Auto-generated via `secrets.token_hex(32)`.
- User-provided secrets must be at least 32 characters long. Short secrets are rejected with **HTTP 422 Unprocessable Entity**.

### Storage Encryption at Rest
To prevent database credential dumps from compromising webhook authentication:
- Webhook secrets are encrypted at rest using **AES-256-GCM**.
- The encryption key is derived from the master `SECRET_KEY` using PBKDF2-HMAC-SHA256 (salt derived from tenant ID).
- Stored as `encrypted_webhook_secret` (base64 string containing nonce + ciphertext + auth tag).
- The plaintext secret is decrypted in memory strictly at the instant of HMAC signature generation.

### Masking & Write-Only Semantics
- The API **NEVER returns plaintext secrets**.
- `GET /v1/notifications/preferences` returns `webhook_secret_preview: "wh_sec_...[last 4 chars]"` and `has_webhook_secret: true`.
- In `PUT /v1/notifications/preferences`:
  - Omitting `webhook_secret` preserves the existing secret.
  - Sending `webhook_secret: null` does **NOT** clear an existing secret unless `webhook_enabled` is explicitly set to `false`.
  - Passing a new secret re-encrypts and updates it.

---

# HMAC Contract

Every outbound webhook delivery includes cryptographic headers allowing the destination to authenticate the sender and prevent replay attacks:

### Canonical Signing String
```
canonical_string = f"{timestamp}.{raw_json_body}"
```
- `timestamp`: Unix epoch seconds as a string (e.g. `"1741891200"`).
- `raw_json_body`: Exact, unformatted, canonical UTF-8 bytes sent in the HTTP POST body.

### Signature Generation
```python
signature = hmac.new(
    key=raw_secret_bytes,
    msg=canonical_string.encode("utf-8"),
    digestmod=hashlib.sha256
).hexdigest()
```

### Outbound HTTP Headers
```http
POST /webhook-receiver HTTP/1.1
Host: api.partner.com
Content-Type: application/json; charset=utf-8
X-SOC-Delivery-ID: 550e8400-e29b-41d4-a716-446655440000
X-SOC-Event-Type: ALERT_TRIGGERED
X-SOC-Timestamp: 1741891200
X-SOC-Signature-256: t=1741891200,v1=9b74c9897bac770ffc029102a200c5de4c07152b...
User-Agent: AI-Cyber-Security-Suite-Webhook/1.0
```

### Verification Requirements for Receivers
1. Extract `t` and `v1` from `X-SOC-Signature-256`.
2. Check timestamp freshness: `abs(NOW() - t) <= 300` (reject replay if older than 5 minutes).
3. Compute expected signature using shared secret.
4. Verify signature using constant-time comparison (`hmac.compare_digest`).

---

# Retry Model

| Response / Failure Mode | Classification | Retryable? | Immediate Action |
|---|---|---|---|
| **2xx (e.g. 200, 201, 204)** | Success | NO | Mark `DELIVERED`; reset consecutive failure counter to 0. |
| **3xx (Redirect)** | Security Violation | NO | Mark `FAILED`; log `REDIRECT_FORBIDDEN`. Egress redirects are strictly forbidden to prevent SSRF bypass. |
| **4xx (e.g. 400, 401, 404)** | Client Error | NO | Mark `FAILED`; increment consecutive failure counter. Client configuration is invalid; retrying will not help. |
| **5xx (e.g. 500, 502, 503)** | Transient Server Error | YES | Increment `attempt_count`. If `attempt_count < 3`, schedule retry; otherwise mark `FAILED`. |
| **Connection Timeout (> 3.0s)** | Transient Network Error | YES | Increment `attempt_count`. If `attempt_count < 3`, schedule retry; otherwise mark `FAILED`. |
| **DNS Resolution Failure** | Transient Network Error | YES | Retryable up to 2 times (in case of transient DNS glitch), then mark `FAILED`. |
| **SSRF Security Block** | Critical Security Violation | NO | Mark `FAILED` immediately. Emit `SECURITY_ALERT` audit event. **NEVER RETRY.** |

### Backoff Formula
For retryable errors, the next attempt is calculated using exponential backoff with full jitter:
```
backoff_seconds = min(60.0, 5.0 * (2 ** (attempt - 1))) + uniform(0.5, 2.0)
next_attempt_at = NOW() + timedelta(seconds=backoff_seconds)
```
- **Attempt 1**: Immediate.
- **Attempt 2**: ~5–7 seconds delay.
- **Attempt 3**: ~10–12 seconds delay.
- Max attempts: **3**.

---

# Circuit Breaker

To protect external receiver systems and preserve backend resources during alert storms:
- **Threshold**: **5 consecutive delivery failures** for a given user automatically trips the circuit breaker.
- **Trip Action**:
  - Sets `NotificationPreference.webhook_enabled = False`.
  - Sets `NotificationPreference.circuit_broken = True`.
  - Sets `NotificationPreference.circuit_broken_at = NOW()`.
  - Emits an In-App Notification: `"Webhook delivery disabled: 5 consecutive delivery failures encountered. Please verify your endpoint and secret."`
  - Emits an `AuditEvent`: `WEBHOOK_CIRCUIT_BROKEN`.
- **Atomic Counter Synchronization**:
  - PostgreSQL: Handled atomically via `UPDATE notification_preferences SET consecutive_failures = consecutive_failures + 1 WHERE user_id = :uid RETURNING consecutive_failures`.
  - If returned failures >= 5, atomically flip `webhook_enabled = False`.
- **Reset Mechanics**:
  - On any **2xx success**: `consecutive_failures` is reset to 0.
  - On **User Configuration Update**: Saving `PUT /v1/notifications/preferences` with `webhook_enabled: true` resets `consecutive_failures = 0` and clears `circuit_broken = False`.
  - **No Automatic Reset**: The circuit breaker **NEVER resets automatically** over time; human intervention is required to re-enable after an outage.

---

# Idempotency Model

### At-Least-Once Delivery Reality
In distributed HTTP networking, true exactly-once delivery across untrusted networks is mathematically impossible (the Two Generals' Problem). If a worker POSTs to an external webhook, the receiver processes the payload, but the TCP ACK drops before the worker records success, the worker will retry.

Therefore, Phase 5D guarantees **At-Least-Once Delivery** paired with a **Deterministic Idempotency Key**:
```
X-SOC-Delivery-ID: <UUIDv4>
X-SOC-Event-ID: sha256(f"{alert_uuid}:{channel}:{event_type}:{occurrence_count}")
```
Receivers can safely deduplicate inbound events using `X-SOC-Event-ID`.

### Outbox Enqueue Idempotency
To prevent internal duplication during retries or concurrent worker runs:
- `idempotency_key` is stored on `notification_outbox` with a `UNIQUE` constraint.
- Key format: `f"wh:{alert_uuid}:{event_type}:{severity}"`.
- Duplicate trigger attempts on the same alert state hit `ON CONFLICT DO NOTHING` and return the existing job.

---

# Alert-to-Notification Matrix

| Trigger Event | Target Severity | In-App Notification? | Webhook Dispatched? | Deduplication & Filtering Rules |
|---|---|---|---|---|
| **New Alert Created (`OPEN`)** | `CRITICAL`, `HIGH` | YES | YES | Dispatched if `severity >= preference.min_severity`. |
| **New Alert Created (`OPEN`)** | `MEDIUM`, `LOW`, `INFO` | YES | Optional | Only if user explicitly lowered `min_severity`. Default is `HIGH`. |
| **Monotonic Severity Escalation** | e.g. `MEDIUM` → `CRITICAL` | YES | YES | Dispatched because threat escalated to a higher critical tier. |
| **Alert Recurrence (Terminal)** | Any | YES | YES | Since recurrence on terminal alert spawns a brand new `Alert` entity, fresh notifications fire naturally. |
| **Alert Recurrence (Within Dedup)** | Any | NO | NO | Increments `occurrence_count` on existing open alert; no notification storm. |
| **Target Auto-Suspended** | `MEDIUM` (Operational) | YES | YES | Dispatched to alert owner of infrastructure outage (5 consecutive probe failures). |
| **SSRF Probe Aborted** | `CRITICAL` (Security) | YES | YES | Dispatched immediately as high-priority security finding. |
| **Alert Acknowledged** | `OPEN` → `ACKNOWLEDGED` | NO | NO | Internal triage operation; no webhook noise. |
| **Alert Resolved** | `*` → `RESOLVED` | Optional | NO | Internal resolution; recorded in audit log. |
| **Alert Dismissed** | `*` → `DISMISSED` | NO | NO | False positive suppression; zero notifications emitted. |
| **Alert Reopened** | `*` → `OPEN` | YES | Optional | Emitted as an investigation-resumed event if configured. |

---

# Database Design

### 1. `notification_preferences` Table Updates (Migration `e7f8a9b0c1d2`)
```sql
ALTER TABLE notification_preferences
  ADD COLUMN encrypted_webhook_secret TEXT NULL,
  ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN circuit_broken BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN circuit_broken_at TIMESTAMP WITH TIME ZONE NULL;

CREATE INDEX idx_notif_pref_user ON notification_preferences(user_id);
```

### 2. `notifications` Table Updates
```sql
CREATE INDEX idx_notifications_user_created 
  ON notifications(user_id, created_at DESC);

CREATE INDEX idx_notifications_user_unread 
  ON notifications(user_id, is_read) 
  WHERE is_read = FALSE;
```

### 3. `notification_outbox` Table (NEW)
```sql
CREATE TABLE notification_outbox (
    id SERIAL PRIMARY KEY,
    outbox_uuid VARCHAR(36) NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel VARCHAR(32) NOT NULL DEFAULT 'WEBHOOK',
    destination_url TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMP WITH TIME ZONE NULL,
    locked_by VARCHAR(64) NULL,
    delivered_at TIMESTAMP WITH TIME ZONE NULL,
    last_error VARCHAR(512) NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_outbox_claim 
  ON notification_outbox(status, next_attempt_at) 
  WHERE status = 'PENDING';

CREATE INDEX idx_outbox_stale_lock 
  ON notification_outbox(locked_at) 
  WHERE status = 'PROCESSING';
```

---

# Transaction Boundaries

### Boundary 1: Alert Ingestion & Outbox Enqueue (Atomic)
```python
async with session.begin():
    # 1. Create or update Alert
    alert = alert_service.create_alert(...)
    
    # 2. Check user preference
    pref = get_user_notification_preference(alert.user_id)
    if should_notify(alert, pref):
        # 3. Insert In-App Notification
        session.add(Notification(...))
        
        # 4. Insert Outbox Job (if webhook enabled)
        if pref.webhook_enabled and not pref.circuit_broken:
            session.add(NotificationOutbox(
                destination_url=pref.webhook_url,
                payload_json=serialize_alert(alert),
                idempotency_key=compute_idempotency_key(alert),
                status="PENDING",
                next_attempt_at=now
            ))
# DB TRANSACTION COMMITS DURABLY HERE
```

### Boundary 2: Outbox Job Claim (Atomic & Lockless)
```python
async with session.begin():
    stmt = (
        select(NotificationOutbox)
        .where(
            NotificationOutbox.status == "PENDING",
            NotificationOutbox.next_attempt_at <= func.now(),
            or_(
                NotificationOutbox.locked_at.is_(None),
                NotificationOutbox.locked_at < func.now() - text("INTERVAL '60 seconds'")
            )
        )
        .with_for_update(skip_locked=True)
        .limit(10)
    )
    jobs = (await session.execute(stmt)).scalars().all()
    for job in jobs:
        job.status = "PROCESSING"
        job.locked_at = func.now()
        job.locked_by = worker_pod_id
# CLAIM COMMITS; LOCK RESERVED
```

### Boundary 3: HTTP Delivery & Status Writeback
```python
# Executed completely OUTSIDE database transaction:
result = await execute_ssrf_safe_webhook(job.destination_url, job.payload_json, secret)

# Separate Writeback Transaction:
async with session.begin():
    reloaded_job = await session.get(NotificationOutbox, job.id)
    if result.is_success:
        reloaded_job.status = "DELIVERED"
        reloaded_job.delivered_at = func.now()
        await reset_circuit_breaker(session, job.user_id)
    elif result.is_retryable and job.attempt_count < 3:
        reloaded_job.status = "PENDING"
        reloaded_job.attempt_count += 1
        reloaded_job.next_attempt_at = compute_backoff(job.attempt_count)
        reloaded_job.last_error = result.error_msg
    else:
        reloaded_job.status = "FAILED"
        reloaded_job.last_error = result.error_msg
        await increment_circuit_breaker(session, job.user_id)
```

---

# PostgreSQL Concurrency

- **`FOR UPDATE SKIP LOCKED`**: Enables horizontal scaling across $N$ worker pods without deadlock or claim collision.
- **Monotonic Clocks**: All scheduling uses `NOW()` from the PostgreSQL database engine to avoid host clock drift.
- **Advisory Fencing**: Optional per-tenant advisory locks during circuit-breaker transitions prevent concurrent increment races.

---

# SQLite Test Strategy

Since SQLite in-memory does not support `SKIP LOCKED`:
- The test harness emulates lockless claiming using an in-process `asyncio.Lock` per user.
- Emulates `NOW()` using UTC timestamps.
- Explicit concurrency tests verify that 50 concurrent dispatch workers process 50 jobs with zero duplicate executions and zero dropped jobs.
- Tests marked with `@pytest.mark.skipif(not _is_postgres_available(), ...)` will test live PostgreSQL behavior when a real database is available.

---

# API Contract

### 1. `GET /v1/notifications`
- **Auth**: Bearer User / Admin
- **Query**: `page: int = 1`, `page_size: int = 20 (max 100)`, `is_read: bool | None`, `severity: str | None`
- **Response** (`NotificationListResponse`):
  ```json
  {
    "items": [
      {
        "notification_uuid": "c9a0f44e-7db2-4e08-8e68-0fa986950275",
        "title": "CRITICAL Threat Detected: malicious-domain.com",
        "message": "Automated probe detected high-confidence phishing campaign.",
        "severity": "CRITICAL",
        "is_read": false,
        "link_url": "/alerts/c9a0f44e-7db2-4e08-8e68-0fa986950275",
        "created_at": "2026-09-13T12:00:00Z"
      }
    ],
    "total": 1,
    "unread_count": 1,
    "page": 1,
    "page_size": 20,
    "has_next": false
  }
  ```
- **Rate Limit**: 60/minute

### 2. `GET /v1/notifications/unread-count`
- **Auth**: Bearer User / Admin
- **Response**: `{"unread_count": int}`
- **Rate Limit**: 120/minute

### 3. `POST /v1/notifications/{notification_uuid}/read`
- **Auth**: Bearer User / Admin
- **Response**: `NotificationResponse` (HTTP 200)
- **Error**: HTTP 404 (anti-enumeration for foreign tenants)
- **Rate Limit**: 60/minute

### 4. `POST /v1/notifications/mark-all-read`
- **Auth**: Bearer User / Admin
- **Response**: `{"updated_count": int}`
- **Rate Limit**: 30/minute

### 5. `GET /v1/notifications/preferences`
- **Auth**: Bearer User / Admin
- **Response**:
  ```json
  {
    "in_app_enabled": true,
    "webhook_enabled": true,
    "webhook_url": "https://siem.partner.com/webhook",
    "has_webhook_secret": true,
    "webhook_secret_preview": "wh_sec_...f4a1",
    "min_severity": "HIGH",
    "circuit_broken": false,
    "circuit_broken_at": null,
    "updated_at": "2026-09-13T10:00:00Z"
  }
  ```
- **Rate Limit**: 30/minute

### 6. `PUT /v1/notifications/preferences`
- **Auth**: Bearer User / Admin
- **Payload** (`NotificationPreferenceUpdate`):
  ```json
  {
    "in_app_enabled": true,
    "webhook_enabled": true,
    "webhook_url": "https://siem.partner.com/webhook",
    "webhook_secret": "long_secure_secret_with_at_least_32_characters_here",
    "min_severity": "HIGH"
  }
  ```
- **Validation**:
  - `webhook_secret`: Must be null or >= 32 characters.
  - `webhook_url`: Must pass scheme validation and fail-closed SSRF hostname resolution.
- **Rate Limit**: 15/minute

---

# Authentication and RBAC

- Reuses authoritative `get_current_user` JWT Bearer dependency.
- Standard users can only view, read, and configure their own notifications.
- Admins can query system-wide alerts but notification preferences remain strictly tenant-scoped.
- Knowing a `notification_uuid` belonging to another user unconditionally returns **HTTP 404 Not Found**.

---

# Tenant Isolation

Every database query in `NotificationService` and `NotificationDispatcher` contains:
```python
stmt = stmt.where(Notification.user_id == current_user.id)
```
Foreign tenant lookups match zero rows and raise `NotificationNotFoundError` (HTTP 404), completely closing UUID enumeration attack surfaces.

---

# Resource Limits

1. **Max Payload Size**: 64 KB (JSON payload truncated if oversized).
2. **Max Response Reading Limit**: 16 KB (Response stream severed after 16 KB).
3. **Hard Delivery Timeout**: 3.0 seconds.
4. **Max Outbox Batch Size**: 50 jobs per cycle.
5. **Max Webhook Concurrency**: 20 global concurrent requests across worker pool; max 2 concurrent per tenant.
6. **Unread In-App Cap**: Max 1,000 unread notifications per tenant.

---

# Observability

### Structured Logging
All dispatcher events emit structured JSON:
```json
{
  "event": "webhook_delivery_attempt",
  "outbox_uuid": "3a01-41a7-...",
  "tenant_id": 42,
  "attempt": 1,
  "status_code": 200,
  "latency_ms": 142.5,
  "circuit_broken": false
}
```

### Metrics (Prometheus `/metrics`)
- `soc_notifications_created_total{channel="in_app|webhook",severity="..."}`
- `soc_webhook_delivery_attempts_total{status="delivered|retry|failed"}`
- `soc_webhook_delivery_latency_seconds` (Histogram)
- `soc_webhook_circuit_breaker_trips_total`

---

# Audit Model

Security audit records (`AuditEvent`) are immutable and strictly separate from transient notifications:
- `NOTIFICATION_PREFERENCES_UPDATED`: Emitted when preferences change. Secret is never logged.
- `WEBHOOK_CIRCUIT_BROKEN`: Emitted when 5 consecutive failures disable a webhook.
- `WEBHOOK_SSRF_ABORTED`: Emitted when an outbound webhook attempts to contact a restricted IP.
- `NOTIFICATION_DELIVERY_PERMANENT_FAILURE`: Emitted when all 3 retries fail.

---

# Threat Model

| ID | Attack Vector | Severity | Mitigation |
|---|---|---|---|
| **TM-01** | Outbound SSRF via Webhook URL | CRITICAL | Dual validation via `security_network.py` (pre-flight + delivery-time DNS pinning). Disallow redirects. |
| **TM-02** | DNS Rebinding (TOCTOU) | CRITICAL | Pin resolved IP immediately before connection; connect to IP literal with `Host` header intact. |
| **TM-03** | Webhook DoS / Egress Amplification | HIGH | 10 req/min tenant rate limit; 3.0s timeout; 5-failure circuit breaker. |
| **TM-04** | Webhook Secret Leakage | HIGH | AES-256-GCM encryption at rest; write-only API; preview masking. |
| **TM-05** | Payload Forgery & Replay | HIGH | Canonical HMAC-SHA256 signature; 300s timestamp window; constant-time check. |
| **TM-06** | Cross-Tenant Notification Access | HIGH | Mandatory server-side `user_id == current_user.id`; HTTP 404 anti-enumeration. |
| **TM-07** | Database Bloat | MEDIUM | 30-day read purge; max 1,000 unread cap; outbox retention purge after 7 days. |

---

# Security Gates

1. **SSRF Gate**: Zero outbound requests permitted to private/loopback/cloud metadata CIDRs.
2. **Secret Non-Leakage**: Zero plaintext secrets in logs, responses, or exceptions.
3. **Transaction Safety**: Notification delivery network calls must **never** run inside the primary alert transaction.
4. **Signature Integrity**: HMAC signature must match byte-for-byte with independent verification tools.
5. **Protected Files**: Zero modifications permitted to protected infrastructure files.

---

# Test Strategy

The test suite must prove the following 21 behaviors:
1. **Tenant Isolation**: Foreign tenant notification lookups return 404.
2. **RBAC**: Standard users cannot modify other users' preferences.
3. **SSRF Prevention**: `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `localhost`, and `::1` rejected.
4. **DNS Rebinding Resistance**: Dynamic DNS flipping from public to private IP aborted at dispatch time.
5. **Redirect Blocking**: 301/302 redirects rejected without following.
6. **HMAC Correctness**: Independent HMAC-SHA256 calculation matches byte-for-byte.
7. **Replay Window**: Timestamps older than 300 seconds rejected.
8. **Secret Non-Leakage**: API responses contain only masked previews.
9. **Severity Filtering**: Alerts below `min_severity` do not trigger notifications.
10. **Outbox Idempotency**: Duplicate event processing generates exactly 1 outbox job.
11. **Retry Backoff**: 5xx responses trigger exponential retry; 4xx responses do not.
12. **Circuit Breaker**: 5 consecutive failures disable webhook and emit in-app alert.
13. **Concurrent Dispatch**: 50 concurrent outbox jobs claimed without duplicate delivery.
14. **Stale Job Recovery**: Jobs locked > 60s automatically reclaimed by active workers.
15. **Crash Recovery**: Uncommitted alert drops outbox job; committed alert persists outbox job across simulated restart.
16. **Alert Recurrence**: Terminal recurrence generates new notification.
17. **Severity Escalation**: Alert escalation generates update notification.
18. **SQLite Parity**: In-memory test suite passes 100%.
19. **PostgreSQL Compatibility**: Dialect-specific `FOR UPDATE SKIP LOCKED` syntax verified.
20. **Zero Regression**: All existing 497 repository tests continue to pass.
21. **Clean-Checkout CI**: Passes in GitHub Actions without local dependencies.

---

# Acceptance Criteria

- [ ] **AC-01**: `notification_outbox` table stores delivery jobs atomically with alert creation.
- [ ] **AC-02**: `NotificationDispatcher` claims outbox jobs using `SKIP LOCKED` and dispatches asynchronously.
- [ ] **AC-03**: Webhook egress validates IP addresses and enforces DNS pinning via `security_network.py`.
- [ ] **AC-04**: Webhook egress strictly forbids HTTP redirects (`follow_redirects=False`).
- [ ] **AC-05**: Outbound requests include `X-SOC-Signature-256`, `X-SOC-Timestamp`, and `X-SOC-Delivery-ID`.
- [ ] **AC-06**: Secrets < 32 characters rejected with HTTP 422. Plaintext secrets encrypted at rest.
- [ ] **AC-07**: Transient 5xx/timeout errors retried up to 3 times with exponential backoff.
- [ ] **AC-08**: 5 consecutive failures trip the circuit breaker and disable the webhook.
- [ ] **AC-09**: `GET /v1/notifications` returns paginated, tenant-isolated notifications.
- [ ] **AC-10**: `POST /v1/notifications/{uuid}/read` and `mark-all-read` update read states idempotently.
- [ ] **AC-11**: `GET/PUT /v1/notifications/preferences` manages preferences with masked secrets.
- [ ] **AC-12**: Full test suite passes with 0 failures, 0 regressions, and 0 Ruff lint errors.

---

# File-Level Change Plan

### Files to CREATE:
1. `backend/schemas/notification.py`: Pydantic request/response schemas.
2. `backend/services/notification_service.py`: In-app notification management and outbox enqueueing.
3. `backend/services/notification_dispatcher.py`: Background worker claiming outbox rows and dispatching webhooks.
4. `backend/api/routers/notifications.py`: REST API router.
5. `migrations/versions/e7f8a9b0c1d2_sprint5_phase5d_outbox_circuit_breaker.py`: Schema additions (`notification_outbox`, preference fields, indexes).
6. `tests/unit/test_notification_service.py`: Service, HMAC, and SSRF unit tests.
7. `tests/integration/test_notifications_api.py`: REST endpoint and multi-tenancy integration tests.
8. `tests/integration/test_notification_concurrency.py`: 50-way concurrent dispatch and claiming tests.

### Files to MODIFY:
1. `backend/main.py`: Include `notifications.router` under `/v1`; register `NotificationDispatcher` lifespan.
2. `backend/services/alert_service.py`: Enqueue outbox job inside alert transaction.
3. `backend/services/monitoring_worker.py`: Enqueue outbox job on target auto-suspension or SSRF abort.

### Protected Files (MUST NOT BE TOUCHED):
- `backend/services/incident_service.py`
- `backend/services/monitoring_probe.py`
- `backend/services/scheduler_service.py`
- `backend/core/security_network.py`
- `backend/services/threat_intel.py`
- `backend/services/intel_enrichment.py`
- `backend/schemas/soc.py`
- `ml/**`

---

# Dependency Impact

- **External Dependencies Reused**: `httpx`, `pydantic`, `sqlalchemy`, `hashlib`, `hmac`, `secrets`, `cryptography` (for AES-256-GCM).
- **New External Dependencies**: **ZERO (0)**. Everything implemented with existing stack.

---

# CI/CD Impact

- Runs cleanly on standard GitHub Actions runners.
- Existing CI configuration remains 100% green.

---

# Staging Verification

- Automated SQLite concurrency tests run in standard CI.
- Real multi-container PostgreSQL row locking (`SKIP LOCKED`) must be verified on staging deployment.

---

# Rollback Plan

1. **Feature Flag**: `ENABLE_NOTIFICATIONS=false` immediately stops the background dispatcher and skips outbox enqueueing.
2. **Database Migration**: Reversible Alembic downgrade script (`downgrade()`) drops `notification_outbox` table and added columns safely.
3. **Zero Impact on Core**: Detection, monitoring probes, and alert triage continue running unimpeded if notifications are rolled back.

---

# Risks

1. **Webhook Target Flapping (Mitigated)**: Solved by circuit breaker tripping at 5 failures.
2. **SSRF via DNS Rebinding (Mitigated)**: Solved by pre-flight check + delivery-time IP pinning.
3. **Database Outbox Table Bloat (Mitigated)**: Solved by background job purging delivered jobs older than 7 days.

---

# Open Questions

- **OQ-01**: Should webhook delivery support custom headers (e.g. `Authorization: Bearer <token>`)?
  - *Recommendation*: Defer to enterprise integrations sprint; HMAC-SHA256 signature is industry standard and sufficient for Phase 5D.
- **OQ-02**: Should notification retention be configurable per-tenant?
  - *Recommendation*: Use global 30-day read / 90-day total retention for Phase 5D.

---

# Implementation Order

1. **Stage 1 (Architecture & Approval)**: Human review of this v1.1 specification.
2. **Stage 2 (Database Migration & Models)**: Implement migration `e7f8a9b0c1d2` and ORM models.
3. **Stage 3 (Core Service Layer)**: Implement `NotificationService` (outbox enqueueing, HMAC signing, AES encryption).
4. **Stage 4 (Dispatcher Engine)**: Implement `NotificationDispatcher` with SSRF-safe pinned egress and retry loop.
5. **Stage 5 (REST API Router)**: Implement `notifications.py` router and mount in `backend/main.py`.
6. **Stage 6 (Pipeline Wiring)**: Connect outbox enqueueing in `alert_service.py` and `monitoring_worker.py`.
7. **Stage 7 (Verification & Review)**: Execute Ralph test loop (unit, integration, concurrency) -> CodeRabbit Review -> Commit.

---

# Human Approval Gate

Implementation is strictly blocked until explicit human approval is granted.

---

# Final Recommendation

### **GO WITH CONDITIONS**

**Conditions**:
1. **Durable Outbox Mandate**: Implementation must use the transactional outbox pattern. In-memory fire-and-forget dispatch is strictly prohibited.
2. **SSRF & DNS Pinning**: All webhook network requests must strictly reuse `backend/core/security_network.py` with DNS pinning and zero redirects.
3. **Cryptographic Protection**: Secrets must be AES-256-GCM encrypted at rest and HMAC-SHA256 signatures must follow the canonical contract.
4. **Zero Protected File Changes**: All core monitoring, ML, and incident infrastructure must remain read-only.
