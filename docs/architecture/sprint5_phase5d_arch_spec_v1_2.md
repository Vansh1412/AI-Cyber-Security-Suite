# SPRINT 5 — PHASE 5D ARCHITECTURE & SECURITY SPECIFICATION v1.2
## Durable SOC Alert Delivery, Outbox Protocol, Secure Webhook Egress & Notification Infrastructure
### Document: `docs/architecture/sprint5_phase5d_arch_spec_v1_2.md`
### Status: ARCHITECTURE SPECIFICATION v1.2 — FINAL ARCHITECTURE GATE (READ-ONLY)
### Baseline: `43d94a6c970de64c077ecc136a40ca04a135df2d` (CI: SUCCESS, 497 passed, 2 skipped, 0 failures)

---

> [!IMPORTANT]
> **READ-ONLY FINAL ARCHITECTURE SPECIFICATION (v1.2).**
> This specification represents the final architecture gate for Sprint 5 Phase 5D prior to implementation authorization:
> - **Webhook Secret Entropy**: Explicitly separates 32 cryptographically random bytes (64 hex characters) from user string lengths; defines unambiguous entropy and validation rules.
> - **AES-256-GCM Key Management**: Establishes an authoritative cryptographic contract (versioned envelope `v1:`, salt, 96-bit nonce, 128-bit tag, PBKDF2-HMAC-SHA256 with 600,000 iterations, zero plaintext leakage, corruption handling). Verified that no pre-existing symmetric encryption exists in the repository.
> - **At-Least-Once Delivery**: Formally acknowledges that exactly-once delivery over untrusted HTTP networks is impossible; defines `X-SOC-Delivery-ID`, `X-SOC-Event-ID`, and receiver deduplication expectations.
> - **Outbox Lease Protocol**: Defines a 4-state finite state machine (`PENDING`, `PROCESSING`, `DELIVERED`, `FAILED`), lease ownership (`locked_by`), 60s lease expiry, and stale worker recovery.
> - **Circuit Breaker Atomicity**: Verifies atomic single-statement SQL updates for `consecutive_failures` preventing lost updates under 50-way concurrent worker execution, and prevents racing successes from reopening tripped circuits.
> - **Notification Idempotency**: Resolves all lifecycle transitions (OPEN, duplicate, escalation, ACK, RESOLVED, DISMISSED, reopen, recurrence) with deterministic keys.
> - **SSRF Contract**: Reuses [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py) without modification, enforcing pre-flight validation, delivery-time DNS pinning, `follow_redirects=False`, and 3.0s timeout.
> - **PostgreSQL Staging Gate**: Establishes mandatory multi-container staging tests (row-locking `SKIP LOCKED`, concurrent dispatch, worker crash recovery) distinguishing staging from SQLite test emulation.
> - **Behavioral Acceptance Criteria**: Replaces arbitrary test counts with 24 rigorous behavioral gates (AC01–AC24).
> - **Protected Files**: Formally preserves all 8 protected modules and paths.
>
> NO source code, migrations, tests, or configurations are modified during this task.
> Implementation authorization is strictly reserved for human approval.

---

# Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Current State](#2-current-state)
3. [Problem Statement](#3-problem-statement)
4. [Goals & Non-Goals](#4-goals--non-goals)
5. [Component Architecture](#5-component-architecture)
6. [Durable Delivery Architecture & Outbox Protocol](#6-durable-delivery-architecture--outbox-protocol)
7. [At-Least-Once Delivery & Idempotency Model](#7-at-least-once-delivery--idempotency-model)
8. [Outbox State Machine & Lease Protocol](#8-outbox-state-machine--lease-protocol)
9. [Webhook Secret Security Contract](#9-webhook-secret-security-contract)
10. [AES-256-GCM Key Management & Cryptographic Contract](#10-aes-256-gcm-key-management--cryptographic-contract)
11. [Canonical HMAC-SHA256 Signature Contract](#11-canonical-hmac-sha256-signature-contract)
12. [Retry Semantics & Backoff Formula](#12-retry-semantics--backoff-formula)
13. [Atomic Multi-Pod Circuit Breaker](#13-atomic-multi-pod-circuit-breaker)
14. [Alert-to-Notification Matrix & Lifecycle Semantics](#14-alert-to-notification-matrix--lifecycle-semantics)
15. [SSRF Security Contract & DNS Pinning](#15-ssrf-security-contract--dns-pinning)
16. [Database Schema & Migration Design](#16-database-schema--migration-design)
17. [Transaction Boundaries & Failure Scenarios](#17-transaction-boundaries--failure-scenarios)
18. [PostgreSQL Concurrency vs. SQLite Emulation](#18-postgresql-concurrency-vs-sqlite-emulation)
19. [Mandatory PostgreSQL Staging Gate](#19-mandatory-postgresql-staging-gate)
20. [API Contract & Schema Specification](#20-api-contract--schema-specification)
21. [Authentication, RBAC & Tenant Isolation](#21-authentication-rbac--tenant-isolation)
22. [Resource Limits & DoS Safeguards](#22-resource-limits--dos-safeguards)
23. [Observability, Metrics & Structured Logging](#23-observability-metrics--structured-logging)
24. [Audit Trail Model](#24-audit-trail-model)
25. [Threat Model & Attack Vector Mitigations](#25-threat-model--attack-vector-mitigations)
26. [Security Gates](#26-security-gates)
27. [Behavioral Acceptance Criteria (AC01–AC24)](#27-behavioral-acceptance-criteria-ac01ac24)
28. [File-Level Change Plan](#28-file-level-change-plan)
29. [Protected Files Invariant](#29-protected-files-invariant)
30. [Dependency & CI/CD Impact](#30-dependency--cicd-impact)
31. [Rollback Plan](#31-rollback-plan)
32. [Risks & Open Questions](#32-risks--open-questions)
33. [Implementation Roadmap](#33-implementation-roadmap)
34. [Final Architecture Recommendation](#34-final-architecture-recommendation)

---

# 1. Executive Summary

Sprint 5 established autonomous threat monitoring, probe execution, scheduler fencing, and alert triage across Sprints 5A, 5B, and 5C. However, the system currently lacks an egress delivery mechanism to alert human analysts or external orchestration platforms (SIEM, SOAR, Slack, PagerDuty).

Sprint 5 Phase 5D delivers the **authoritative notification and alert delivery arm** of the suite. It activates the existing `Notification` and `NotificationPreference` database schemas and introduces a **durable, transactional Outbox dispatcher**.

By integrating an Outbox pattern directly into PostgreSQL/SQLAlchemy, Phase 5D achieves:
- **Zero Loss of High-Severity Alerts**: Transactional outbox records commit within the same atomic database boundary as the detected alert.
- **At-Least-Once Delivery**: Guaranteed outbound HTTP dispatch with receiver deduplication headers (`X-SOC-Delivery-ID`, `X-SOC-Event-ID`).
- **Fail-Closed Egress Security**: Complete immunity against outbound SSRF, DNS rebinding (TOCTOU), and cloud metadata theft via strict reuse of [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py).
- **Cryptographic Trust**: AES-256-GCM storage encryption at rest for secrets and canonical HMAC-SHA256 signature verification with 300-second anti-replay windows.
- **Decoupled Concurrency**: Background workers claim outbox jobs via `SELECT ... FOR UPDATE SKIP LOCKED`, ensuring detection workers and database transactions are never delayed by external HTTP latency.

---

# 2. Current State

- **Sprint 5A**: Targets created, validated, and quota-controlled.
- **Sprint 5B**: Autonomous worker pool, SSRF-safe probe execution, PG advisory leader election, epoch fencing, 59-feature inference, and stale-worker writeback fencing.
- **Sprint 5C**: Authoritative 4-state alert triage (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`), threat recurrence, target operations (`pause`, `resume`, `reactivate`, `check-now`), execution diagnostics, and 24-hour telemetry.
- **Baseline Commit**: `43d94a6c970de64c077ecc136a40ca04a135df2d` (Full repo: 497 passed, 2 skipped, 0 failures; CI: GREEN).
- **Existing Schemas**: `Notification` and `NotificationPreference` models defined in [`backend/database/models.py`](file:///E:/AI-Cyber-Security-Suite/backend/database/models.py) and created in migration `c5e6f7a8b9c0_sprint5_soc_monitoring_tables.py`.

---

# 3. Problem Statement

1. **Fragility of In-Memory Dispatch**: The v1.0 draft used `asyncio.create_task()`. Container restarts, node evictions, unhandled exceptions, or deployments immediately lose uncommitted tasks, permanently dropping zero-day security notifications.
2. **Secret Entropy & Representation Mismatch**: Conflating "32 characters" with "32 bytes (256 bits)" creates false security guarantees. An arbitrary 32-character string does not guarantee 256 bits of entropy.
3. **Database Secret Leakage**: Storing plaintext webhook secrets exposes third-party receiving infrastructure if database snapshots or read replicas are accessed.
4. **SSRF & DNS Rebinding (TOCTOU)**: Outbound webhook endpoints can be configured to point to internal services (`169.254.169.254`, `10.0.0.0/8`). A hostname that resolves to a public IP during registration could resolve to a private IP during dispatch.
5. **DDoS & Egress Amplification**: An alert storm on flapping targets could swamp external webhook receivers or exhaust outbound application connections.
6. **Concurrency Races in Circuit Breakers**: Multiple workers concurrently recording failures can overwrite failure counters or produce flapping circuit states.

---

# 4. Goals & Non-Goals

### Goals
1. **Transactional Durability**: Atomic insertion of notification outbox jobs within the alert creation database transaction.
2. **At-Least-Once Delivery**: Guaranteed delivery for all alerts meeting user threshold, with deterministic idempotency keys for receiver deduplication.
3. **Fail-Closed Egress SSRF**: Enforce delivery-time DNS resolution, IP pinning, host header preservation, TLS SNI preservation, and strict prohibition of HTTP redirects.
4. **Cryptographic Protection**: AES-256-GCM encryption for stored secrets; canonical HMAC-SHA256 signatures with 300s replay tolerance.
5. **Atomic Multi-Pod Circuit Breaker**: Disable webhooks after 5 consecutive failures using atomic database operations safe across 50 concurrent workers.
6. **Zero Regressions**: Zero changes to ML models, scheduler leadership, monitoring probes, or incident management.

### Non-Goals
1. **External Message Brokers**: No RabbitMQ, Kafka, Celery, or Redis Streams. Delivery uses native PostgreSQL outbox tables.
2. **SMTP / SMS Delivery**: Direct email/SMS transport is deferred to enterprise integrations.
3. **Frontend UI Implementation**: React components and settings pages belong strictly to Sprint 6.
4. **Real-time WebSockets / SSE**: Real-time browser push streams belong to Sprint 6.
5. **Inbound Webhook Handlers**: Egress dispatch only; inbound event ingestion is not in scope.

---

# 5. Component Architecture

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
│   1. Claim Job: UPDATE ... SET status='PROCESSING', locked_at=NOW()         │
│                 SKIP LOCKED                                                 │
│   2. SSRF Guard: resolve_and_validate_host(webhook_url) via security_network│
│   3. DNS Pinning: Connect directly to pinned IP (Host & SNI preserved)      │
│   4. Cryptographic Signing: HMAC-SHA256(secret, t + "." + raw_body)         │
│   5. Dispatch: HTTP POST (timeout 3.0s, follow_redirects=False)             │
│   6. Outcome:                                                               │
│      - 2xx: DELIVERED (atomic counter reset)                                │
│      - 3xx/4xx/SSRF: FAILED (permanent, atomic failure increment)           │
│      - 5xx/Timeout: PENDING (increment attempt, compute jittered backoff)   │
│   7. Update Outbox row & AuditEvent                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 6. Durable Delivery Architecture & Outbox Protocol

### Why In-Memory Dispatch is Prohibited
In-memory fire-and-forget (`asyncio.create_task`) ties execution to volatile process memory. If the application pod crashes, restarts, or scales down 20ms after the alert commits, the notification task vanishes forever.

### The Transactional Outbox Protocol
1. **Atomic Insertion**: When `AlertService.process_event()` commits an `Alert`, it inserts a corresponding row into `notification_outbox` in the **same database transaction**. If the alert rollback occurs, no orphan notification is queued. If the alert commits, the notification is durably written to disk.
2. **Decoupled Background Dispatcher**: A dedicated background asyncio task (`NotificationDispatcher`) periodically queries `notification_outbox` for eligible jobs:
   ```sql
   SELECT id FROM notification_outbox
   WHERE (status = 'PENDING' AND next_attempt_at <= NOW())
      OR (status = 'PROCESSING' AND locked_at < NOW() - INTERVAL '60 seconds')
   ORDER BY next_attempt_at ASC
   LIMIT 10
   FOR UPDATE SKIP LOCKED;
   ```
3. **Lockless Concurrency**: Using PostgreSQL `SKIP LOCKED`, multiple application replicas concurrently claim distinct outbox jobs without contention or deadlocks.

---

# 7. At-Least-Once Delivery & Idempotency Model

### The Impossibility of Exactly-Once Over HTTP
In distributed systems, true "exactly-once" delivery across an untrusted network is impossible (the Two Generals' Problem). Consider the following failure sequence:
1. Dispatcher claims outbox job.
2. Dispatcher sends HTTP POST to external webhook URL.
3. External receiver receives payload, processes it, and returns HTTP 200.
4. Before the HTTP response reaches the dispatcher, the dispatcher pod is killed (OOM, deployment, network partition).
5. The dispatcher never recorded `status = DELIVERED`.
6. The lease expires after 60 seconds. A second dispatcher claims the job and re-sends the HTTP POST.

### Architectural Solution: At-Least-Once Delivery + Idempotency Headers
Phase 5D explicitly establishes **At-Least-Once Delivery**. To allow external receivers to achieve end-to-end deduplication, every outbound request includes two critical headers:

1. **`X-SOC-Delivery-ID`**: A newly generated UUIDv4 for each physical network transmission attempt. Used by logging and network telemetry to correlate individual attempts.
2. **`X-SOC-Event-ID`**: A deterministic, invariant event hash calculated as:
   ```python
   event_id = hashlib.sha256(
       f"{alert_uuid}:{channel}:{event_type}:{occurrence_count}".encode("utf-8")
   ).hexdigest()
   ```
   This hash remains identical across all retries of the same security event. External receivers (e.g. Slack, PagerDuty, custom SIEM) are instructed to store `X-SOC-Event-ID` in a cache/table for 24 hours to deduplicate redundant incoming deliveries.

### Outbox Enqueue Idempotency
To prevent internal duplication during retries or concurrent worker processing:
- Table `notification_outbox` enforces a `UNIQUE` constraint on `idempotency_key`.
- Key format: `f"wh:{alert_uuid}:{event_type}:{severity}"`.
- Duplicate trigger attempts on the same alert state execute `ON CONFLICT DO NOTHING`, returning the existing outbox row.

---

# 8. Outbox State Machine & Lease Protocol

### Finite State Machine (FSM)

```
                  ┌──────────────┐
                  │   PENDING    │◀──────────────────┐
                  └──────┬───────┘                   │
                         │ worker claims lease       │ retryable 5xx / timeout
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

### State Definitions
- **`PENDING`**: Job is queued and waiting for initial dispatch, or scheduled for a retry (`next_attempt_at <= NOW()`).
- **`PROCESSING`**: Job has been claimed by a dispatcher worker. The lease is active (`locked_at = NOW()`, `locked_by = worker_pod_id`).
- **`DELIVERED`**: Terminal success. The remote server responded with HTTP `2xx`.
- **`FAILED`**: Terminal failure. Permanent client error (4xx), redirect rejection (3xx), SSRF security block, or exhaustion of all 3 retry attempts.

### Lease Parameters
- **`locked_at`**: Timestamp when worker acquired the lease.
- **`locked_by`**: Worker pod identity string: `f"dispatcher-{pod_name}-{uuid[:8]}"`.
- **Lease Expiry**: **60 seconds**.
- **Max Processing Duration**: Webhook timeout is bounded to 3.0s. Any job remaining in `PROCESSING` for > 60 seconds is treated as an abandoned job (e.g. worker process crash).
- **Stale Worker Recovery**: Active workers automatically claim jobs where `status = 'PROCESSING' AND locked_at < NOW() - INTERVAL '60 seconds'`. If `attempt_count >= max_attempts`, it is marked `FAILED`; otherwise, it is retried.

---

# 9. Webhook Secret Security Contract

### 1. Entropy vs. Characters
- **The Distinction**: A 32-character arbitrary ASCII string does not guarantee 256 bits of entropy (e.g. alphanumeric strings yield $\approx 5.95 \times 32 \approx 190$ bits; hex strings yield $4 \times 32 = 128$ bits).
- **System-Generated Secrets**:
  - MUST be generated using `secrets.token_bytes(32)`.
  - Represented as a **64-character hexadecimal string** (`secrets.token_hex(32)`), guaranteeing **256 bits of cryptographic entropy**.
- **User-Supplied Secrets**:
  - Minimum length: **32 characters**.
  - Must not be trivial: rejection of single repeated characters (`"a" * 32`), whitespace, or common sequences.
  - Recommended format: 64-character hex or 44-character base64 (256-bit key material).

### 2. API Validation & Lifecycle
- **Never Returned**: Plaintext secrets are **NEVER returned** in any API response, log line, or audit event.
- **Masking**: `GET /v1/notifications/preferences` returns:
  ```json
  {
    "has_webhook_secret": true,
    "webhook_secret_preview": "wh_sec_...f4a1"
  }
  ```
- **Preservation on Omit**: In `PUT /v1/notifications/preferences`, omitting `webhook_secret` preserves the existing encrypted secret.
- **Rotation**: Sending `rotate_secret: true` in `PUT` automatically generates a fresh 32-byte (64 hex character) secret, encrypts it, and saves it.
- **Explicit Clearing**: Sending `clear_webhook_secret: true` clears the secret and automatically sets `webhook_enabled = false`. A webhook cannot be enabled without an active secret.

---

# 10. AES-256-GCM Key Management & Cryptographic Contract

### 1. Codebase Cryptographic Audit
A comprehensive codebase audit confirmed that **no pre-existing symmetric data encryption mechanism exists** in the repository. (Existing security code uses bcrypt for password hashing and python-jose for JWT HS256 tokens).

Phase 5D introduces a dedicated, standalone cryptographic helper (`backend/core/crypto.py` or within `backend/services/notification_service.py`) without modifying `backend/core/security.py`.

### 2. The Cryptographic Envelope Contract
Webhook secrets are stored in the database in a versioned envelope format:
```
v1${salt_b64}${nonce_b64}${ciphertext_with_tag_b64}
```
- **Root Encryption Key**: Read from environment variable `WEBHOOK_ENCRYPTION_KEY`. If unset, falls back to `settings.SECRET_KEY` (must be at least 32 characters, otherwise the application fails fast at startup).
- **Key Derivation (KDF)**:
  - Algorithm: **PBKDF2-HMAC-SHA256**.
  - Iteration Count: **600,000 iterations** (conforming to NIST SP 800-132 recommendations).
  - Salt: **16 cryptographically random bytes** (`secrets.token_bytes(16)`) generated uniquely per encryption operation.
  - Derived Key: 32 bytes (256 bits).
- **Authenticated Encryption**:
  - Algorithm: **AES-256-GCM** via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
  - Nonce (IV): **12 cryptographically random bytes** (`secrets.token_bytes(12)`) generated uniquely per encryption operation (NIST recommendation for GCM).
  - Auth Tag: **16 bytes (128 bits)**, automatically appended to the ciphertext by AESGCM.
- **Decryption Failure Handling**:
  - If the ciphertext is corrupted or tampered with, `AESGCM.decrypt()` raises `InvalidTag`.
  - The service catches this, logs a security warning (`"Webhook secret decryption failed: authentication tag mismatch"`), raises `DecryptionError`, disables the webhook, and emits an `AuditEvent`.
  - Plaintext and keys are **never logged**.
- **Key Rotation Strategy**:
  - The envelope prefix `v1$` allows seamless migration to future algorithms (`v2$`).
  - Supports `WEBHOOK_ENCRYPTION_KEY` (current) and `WEBHOOK_ENCRYPTION_KEY_PREVIOUS` (fallback for decryption during rotation).

---

# 11. Canonical HMAC-SHA256 Signature Contract

Every outbound HTTP POST includes cryptographic headers allowing the destination receiver to authenticate the sender and prevent replay attacks.

### 1. Canonical Signing String
```
canonical_string = f"{timestamp}.{raw_json_body}"
```
- `timestamp`: Current Unix epoch seconds formatted as a string (e.g. `"1741891200"`).
- `raw_json_body`: The exact, unformatted, canonical UTF-8 bytes transmitted in the HTTP request body.

### 2. Signature Calculation
```python
signature_bytes = hmac.new(
    key=raw_secret.encode("utf-8"),
    msg=canonical_string.encode("utf-8"),
    digestmod=hashlib.sha256,
).digest()
signature_hex = signature_bytes.hex()
```

### 3. Outbound HTTP Headers
```http
POST /webhook-receiver HTTP/1.1
Host: api.partner.com
Content-Type: application/json; charset=utf-8
X-SOC-Delivery-ID: 550e8400-e29b-41d4-a716-446655440000
X-SOC-Event-ID: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-SOC-Timestamp: 1741891200
X-SOC-Signature-256: t=1741891200,v1=9b74c9897bac770ffc029102a200c5de4c07152b...
User-Agent: AI-Cyber-Security-Suite-Webhook/1.0
```

### 4. Verification Requirements for Receivers
1. Extract `t` (timestamp) and `v1` (signature) from `X-SOC-Signature-256`.
2. **Replay Window Enforcement**: Check `abs(current_epoch - int(t)) <= 300`. If $| \Delta t | > 300$ seconds (5 minutes), reject the request as a replay attack.
3. Construct `f"{t}.{raw_body}"` and calculate expected HMAC-SHA256.
4. Perform constant-time comparison via `hmac.compare_digest(v1, expected_hex)`.

---

# 12. Retry Semantics & Backoff Formula

### Status Classification Table

| Response / Failure Mode | Classification | Retryable? | Immediate Action |
|---|---|---|---|
| **2xx (200, 201, 204)** | Success | NO | Mark `DELIVERED`; reset `consecutive_failures = 0`. |
| **3xx (Redirects)** | Security Violation | NO | Mark `FAILED`; log `REDIRECT_FORBIDDEN`. Redirects are strictly prohibited to prevent SSRF bypass. |
| **4xx (400, 401, 404)** | Client Error | NO | Mark `FAILED`; increment `consecutive_failures`. Configuration is invalid. |
| **5xx (500, 502, 503)** | Transient Server Error | YES | Increment `attempt_count`. If `attempt < 3`, schedule retry; else mark `FAILED`. |
| **Connection Timeout (> 3.0s)** | Transient Network Error | YES | Increment `attempt_count`. If `attempt < 3`, schedule retry; else mark `FAILED`. |
| **DNS Resolution Glitch** | Transient Network Error | YES | Retryable up to 2 times, then mark `FAILED`. |
| **SSRF Security Block** | Critical Security Violation | NO | Mark `FAILED` immediately. Emit `SECURITY_ALERT` audit event. **NEVER RETRY.** |

### Backoff Formula with Full Jitter
For retryable errors, the next attempt timestamp is calculated as:
```python
backoff_seconds = min(60.0, 5.0 * (2 ** (attempt - 1))) + random.uniform(0.5, 2.0)
next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=backoff_seconds)
```
- **Attempt 1**: Immediate.
- **Attempt 2**: $\approx 5.5 - 7.0$ seconds delay.
- **Attempt 3**: $\approx 10.5 - 12.0$ seconds delay.
- **Max Attempts**: **3**.

---

# 13. Atomic Multi-Pod Circuit Breaker

### Concurrency Challenge
If 50 webhook deliveries fail concurrently across 10 worker pods, naive read-modify-write application logic will experience lost updates, race conditions, or duplicate circuit trip events.

### Atomic SQL Implementation
All failure and success state transitions are executed using **single atomic SQL statements** executed directly on the database:

#### 1. Atomic Failure Recording
```sql
UPDATE notification_preferences
SET 
    consecutive_failures = consecutive_failures + 1,
    circuit_broken = CASE 
        WHEN consecutive_failures + 1 >= 5 THEN TRUE 
        ELSE circuit_broken 
    END,
    circuit_broken_at = CASE 
        WHEN consecutive_failures + 1 >= 5 AND NOT circuit_broken THEN NOW() 
        ELSE circuit_broken_at 
    END,
    webhook_enabled = CASE 
        WHEN consecutive_failures + 1 >= 5 THEN FALSE 
        ELSE webhook_enabled 
    END
WHERE user_id = :user_id
RETURNING consecutive_failures, circuit_broken, (consecutive_failures >= 5 AND NOT circuit_broken) AS just_tripped;
```
- **Zero Lost Updates**: The database engine serializes the arithmetic increment on the row.
- **Exactly One Trip Event**: Exactly one worker receives `just_tripped = TRUE`. Only that worker emits the In-App notification and the `AuditEvent: WEBHOOK_CIRCUIT_BROKEN`. Subsequent failures increment the count but do not emit duplicate alerts.

#### 2. Atomic Success Reset & Race Protection
```sql
UPDATE notification_preferences
SET consecutive_failures = 0
WHERE user_id = :user_id AND NOT circuit_broken;
```
- **Race Condition Immunity**: The `AND NOT circuit_broken` clause ensures that if an in-flight delivery succeeds *after* the circuit has already tripped, it **CANNOT reset `consecutive_failures` or re-enable `webhook_enabled`**.
- Once tripped, the circuit remains broken until explicit human intervention.

#### 3. Manual Re-Enablement
```sql
UPDATE notification_preferences
SET 
    consecutive_failures = 0,
    circuit_broken = FALSE,
    circuit_broken_at = NULL,
    webhook_enabled = TRUE
WHERE user_id = :user_id;
```

---

# 14. Alert-to-Notification Matrix & Lifecycle Semantics

| Trigger Event | Target Severity | In-App Inbox? | Outbox Webhook? | Deduplication & Lifecycle Key |
|---|---|---|---|---|
| **New Alert (`OPEN`)** | `CRITICAL`, `HIGH` | YES | YES | `f"wh:{alert_uuid}:OPEN:{severity}:0"`. Dispatched if `severity >= min_severity`. |
| **New Alert (`OPEN`)** | `MEDIUM`, `LOW`, `INFO` | YES | Optional | Only dispatched if user explicitly lowered `min_severity`. |
| **Duplicate Event (within dedup window)** | Any | NO | NO | Suppressed. `occurrence_count` incremented on existing alert; zero duplicate notifications. |
| **Monotonic Severity Escalation** | e.g. `MEDIUM` $\to$ `CRITICAL` | YES | YES | `f"wh:{alert_uuid}:ESCALATED:{new_severity}:{escalation_count}"`. Not suppressed because key differs. |
| **Alert Recurrence on Terminal Alert** | Any | YES | YES | `f"wh:{new_alert_uuid}:OPEN:{severity}:0"`. Terminal recurrence generates a brand new `Alert` entity; never suppressed. |
| **Target Auto-Suspended** | `MEDIUM` (Operational) | YES | YES | Dispatched to alert owner that probe failed 5 consecutive checks. |
| **Target SSRF Probe Aborted** | `CRITICAL` (Security) | YES | YES | Dispatched immediately as high-priority security finding. |
| **Alert Acknowledged (`ACKNOWLEDGED`)** | Any | NO | NO | Triage state change; no outbound noise. |
| **Alert Resolved (`RESOLVED`)** | Any | Optional | NO | Recorded in audit log; no webhook emitted. |
| **Alert Dismissed (`DISMISSED`)** | Any | NO | NO | False positive suppression; zero notifications emitted. |
| **Alert Reopened (RESOLVED $\to$ OPEN)** | Any | YES | Optional | Emitted as an investigation-resumed event if configured. |
| **Alert Reopened (DISMISSED $\to$ OPEN)** | Any | YES | Optional | Emitted as an investigation-resumed event if configured. |

---

# 15. SSRF Security Contract & DNS Pinning

### 1. Zero Duplication of SSRF Code
Phase 5D does **NOT** create a second SSRF validation library. All outbound webhook egress strictly reuses [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py) without modifying that protected file.

### 2. Delivery-Time Egress Controls
1. **URL Validation**: Parse URL with `validate_target_url(url)`:
   - Must be `http` or `https`.
   - Embedded credentials (`user:pass@host`) are strictly forbidden.
2. **DNS Resolution & Inspection**:
   - `resolve_and_validate_host(hostname)` resolves all A and AAAA records.
   - Every resolved IP is evaluated against `is_blocked_ip()`.
   - Rejects RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
   - Rejects loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), carrier NAT (`100.64.0.0/10`), and cloud metadata (`169.254.169.254`).
   - If ANY IP is blocked, the request fails closed immediately.
3. **DNS Pinning (Anti-TOCTOU)**:
   - The TCP socket connects directly to the validated pinned IP address.
   - The original hostname is preserved in the HTTP `Host` header.
   - The original hostname is preserved in the TLS SNI extension during TLS handshake.
4. **Strict Prohibition of Redirects**:
   - Webhook HTTP client sets `follow_redirects = False`.
   - Any `3xx` response is treated as a security violation and marked `FAILED` immediately.
5. **Bounded Egress Limits**:
   - Connect timeout: 3.0s.
   - Read timeout: 3.0s.
   - Response body reading limit: truncated after 16 KB.

---

# 16. Database Schema & Migration Design

### Alembic Migration: `e7f8a9b0c1d2_sprint5_phase5d_outbox_circuit_breaker.py`

```python
"""sprint5 phase5d outbox and circuit breaker

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
Create Date: 2026-09-13
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade() -> None:
    # 1. Update notification_preferences
    op.add_column("notification_preferences", sa.Column("encrypted_webhook_secret", sa.Text(), nullable=True))
    op.add_column("notification_preferences", sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("notification_preferences", sa.Column("circuit_broken", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("notification_preferences", sa.Column("circuit_broken_at", sa.DateTime(timezone=True), nullable=True))
    
    # 2. Indexes for notifications table
    op.create_index("idx_notifications_user_created", "notifications", ["user_id", sa.text("created_at DESC")])
    op.create_index("idx_notifications_user_unread", "notifications", ["user_id", "is_read"])

    # 3. Create notification_outbox table
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("outbox_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.String(32), nullable=False, server_default="WEBHOOK"),
        sa.Column("destination_url", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(64), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_outbox_claim", "notification_outbox", ["status", "next_attempt_at"])
    op.create_index("idx_outbox_stale_lock", "notification_outbox", ["status", "locked_at"])

def downgrade() -> None:
    op.drop_table("notification_outbox")
    op.drop_index("idx_notifications_user_unread", table_name="notifications")
    op.drop_index("idx_notifications_user_created", table_name="notifications")
    op.drop_column("notification_preferences", "circuit_broken_at")
    op.drop_column("notification_preferences", "circuit_broken")
    op.drop_column("notification_preferences", "consecutive_failures")
    op.drop_column("notification_preferences", "encrypted_webhook_secret")
```

---

# 17. Transaction Boundaries & Failure Scenarios

### Boundary 1: Alert Ingestion & Outbox Enqueue (Atomic)
```python
async with session.begin():
    # 1. Create or update Alert
    alert = alert_service.create_alert(...)
    
    # 2. Check user preference
    pref = get_user_notification_preference(alert.user_id)
    if should_notify(alert, pref):
        # 3. Insert In-App Notification
        session.add(Notification(user_id=alert.user_id, ...))
        
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

### Boundary 2: Job Claiming (Atomic & Lockless)
```python
async with session.begin():
    # Uses FOR UPDATE SKIP LOCKED
    jobs = await claim_pending_outbox_jobs(session, limit=10, worker_id=pod_id)
# CLAIM COMMITS; JOBS LOCKED IN 'PROCESSING'
```

### Boundary 3: HTTP Delivery & Status Writeback
```python
# 1. Executed COMPLETELY OUTSIDE database transaction:
result = await execute_ssrf_safe_webhook(job.destination_url, job.payload_json, secret)

# 2. Separate Status Writeback Transaction:
async with session.begin():
    if result.is_success:
        await mark_job_delivered(session, job.id)
        await reset_circuit_breaker(session, job.user_id)
    elif result.is_retryable and job.attempt_count < 3:
        await schedule_job_retry(session, job.id, result.error)
    else:
        await mark_job_failed(session, job.id, result.error)
        await increment_circuit_breaker(session, job.user_id)
```

---

# 18. PostgreSQL Concurrency vs. SQLite Emulation

| Behavior | PostgreSQL (Production & Staging) | SQLite (In-Memory CI Test Harness) |
|---|---|---|
| **Outbox Job Claiming** | `SELECT ... FOR UPDATE SKIP LOCKED` | Emulated via table query + in-process `asyncio.Lock` |
| **Circuit Breaker** | Atomic `UPDATE ... RETURNING consecutive_failures` | Atomic `UPDATE ... RETURNING` (supported in modern SQLite) |
| **Clock Consistency** | `func.now()` evaluated by DB engine | `datetime.now(timezone.utc)` |
| **Concurrency Scale** | 50 concurrent worker threads / multi-pod safe | Serialized event loop execution |

---

# 19. Mandatory PostgreSQL Staging Gate

SQLite in-memory test execution is sufficient for functional regression in CI, but it **CANNOT prove PostgreSQL distributed MVCC correctness or `SKIP LOCKED` behavior**.

Prior to production authorization, the following **8 Mandatory Staging Verification Scenarios** MUST be executed against a multi-container PostgreSQL staging environment:

1. **Multiple Dispatcher Pods**: 3 concurrent dispatcher instances competing for 100 outbox records.
2. **`SKIP LOCKED` Verification**: Confirm zero lock-wait timeouts, zero deadlocks, and zero double-processing.
3. **Stale `PROCESSING` Recovery**: Simulate worker kill (`SIGKILL`) during active HTTP dispatch; verify backup worker reclaims the job exactly after 60s.
4. **Atomic Circuit Breaker Under Load**: 50 concurrent failures across 10 workers; verify `consecutive_failures` increments accurately and trips the circuit exactly once.
5. **Racing Success and Failure**: Verify that a delayed 200 OK cannot reset or reopen a circuit that has already tripped.
6. **Concurrent Outbox Enqueue**: High-throughput alert ingestion (100 alerts/sec) without outbox insertion deadlocks.
7. **Duplicate Event Deduplication**: Verify `ON CONFLICT DO NOTHING` on `idempotency_key` during concurrent alert processing.
8. **Multi-Tenant Isolation**: Verify that Tenant A's dispatcher cannot claim or leak Tenant B's outbox rows.

---

# 20. API Contract & Schema Specification

### 1. `GET /v1/notifications`
- **Auth**: Bearer User / Admin
- **Query Parameters**: `page: int = 1`, `page_size: int = 20 (max 100)`, `is_read: bool | None`, `severity: str | None`
- **Response** (`NotificationListResponse`):
  ```json
  {
    "items": [
      {
        "notification_uuid": "c9a0f44e-7db2-4e08-8e68-0fa986950275",
        "title": "CRITICAL Threat Detected: phishing-bank.com",
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

### 2. `GET /v1/notifications/unread-count`
- **Auth**: Bearer User / Admin
- **Response**: `{"unread_count": 1}`

### 3. `POST /v1/notifications/{notification_uuid}/read`
- **Auth**: Bearer User / Admin
- **Response**: `NotificationResponse` (HTTP 200)
- **Anti-Enumeration**: Foreign tenant lookup returns **HTTP 404 Not Found**.

### 4. `POST /v1/notifications/mark-all-read`
- **Auth**: Bearer User / Admin
- **Response**: `{"updated_count": 5}`

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

### 6. `PUT /v1/notifications/preferences`
- **Auth**: Bearer User / Admin
- **Request Body** (`NotificationPreferenceUpdate`):
  ```json
  {
    "in_app_enabled": true,
    "webhook_enabled": true,
    "webhook_url": "https://siem.partner.com/webhook",
    "webhook_secret": "long_secure_secret_with_at_least_32_characters_here",
    "rotate_secret": false,
    "clear_webhook_secret": false,
    "min_severity": "HIGH"
  }
  ```
- **Validation**:
  - `webhook_url`: Validated via `validate_target_url` and `resolve_and_validate_host`.
  - `webhook_secret`: Must be $\ge 32$ characters. Plaintext is encrypted via AES-256-GCM.
  - Omitted `webhook_secret` preserves the existing secret.

---

# 21. Authentication, RBAC & Tenant Isolation

- **Authentication**: Mandatory `Depends(get_current_user)` on all endpoints.
- **Tenant Isolation**: Every database query filters by `user_id == current_user.id`.
- **Anti-Enumeration**: Attempting to query or mark-read a `notification_uuid` belonging to another user unconditionally raises `NotificationNotFoundError` (HTTP 404).

---

# 22. Resource Limits & DoS Safeguards

1. **Max Webhook Payload**: 64 KB.
2. **Max Webhook Response Read**: 16 KB (stream terminated).
3. **Hard Timeout**: 3.0 seconds connect + read.
4. **Max Concurrency**: 20 global concurrent requests; max 2 concurrent per tenant.
5. **In-App Unread Cap**: Max 1,000 unread notifications per tenant.
6. **Rate Limits**:
   - `GET /v1/notifications`: 60/min.
   - `GET /v1/notifications/unread-count`: 120/min.
   - `PUT /v1/notifications/preferences`: 15/min.

---

# 23. Observability, Metrics & Structured Logging

### Structured JSON Logs
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

### Prometheus Metrics
- `soc_notifications_created_total{channel="in_app|webhook",severity="..."}`
- `soc_webhook_delivery_attempts_total{status="delivered|retry|failed"}`
- `soc_webhook_delivery_latency_seconds` (Histogram)
- `soc_webhook_circuit_breaker_trips_total`

---

# 24. Audit Trail Model

The security audit trail (`AuditEvent` table) remains completely independent from transient user notifications:
- `NOTIFICATION_PREFERENCES_UPDATED`: Recorded when preferences change. Secret is never logged.
- `WEBHOOK_CIRCUIT_BROKEN`: Recorded when the circuit breaker trips.
- `WEBHOOK_SSRF_ABORTED`: Recorded when an outbound webhook attempts to contact a restricted IP.
- `NOTIFICATION_DELIVERY_PERMANENT_FAILURE`: Recorded when all 3 retries fail.

---

# 25. Threat Model & Attack Vector Mitigations

| ID | Attack Vector | Severity | Mitigation |
|---|---|---|---|
| **TM-01** | Outbound SSRF via Webhook URL | CRITICAL | Pre-flight validation + delivery-time DNS pinning via `security_network.py`. |
| **TM-02** | DNS Rebinding (TOCTOU) | CRITICAL | Direct TCP connection to pinned IP; Host and TLS SNI preserved. |
| **TM-03** | Webhook DoS / Amplification | HIGH | Per-tenant concurrency limits (2), 3.0s timeout, 5-failure circuit breaker. |
| **TM-04** | Webhook Secret Leakage | HIGH | AES-256-GCM encryption at rest; write-only API; masked previews. |
| **TM-05** | Payload Forgery & Replay | HIGH | Canonical HMAC-SHA256 signature; 300s replay window; constant-time verify. |
| **TM-06** | Cross-Tenant Notification Access | HIGH | Server-side `user_id` filtering; HTTP 404 anti-enumeration. |
| **TM-07** | Database Bloat | MEDIUM | 30-day read purge; 1,000 unread cap; 7-day outbox purge. |

---

# 26. Security Gates

1. **SSRF Gate**: Zero outbound requests permitted to private/loopback/cloud metadata CIDRs.
2. **Secret Non-Leakage**: Zero plaintext secrets in logs, responses, or exceptions.
3. **Transaction Safety**: Notification delivery network calls must **never** run inside the primary alert transaction.
4. **Signature Integrity**: HMAC signature must match byte-for-byte with independent verification tools.
5. **Protected Files**: Zero modifications permitted to protected infrastructure files.

---

# 27. Behavioral Acceptance Criteria (AC01–AC24)

- [ ] **AC01 (Tenant Isolation)**: Foreign tenant notification lookups unconditionally return HTTP 404.
- [ ] **AC02 (RBAC)**: Standard users cannot view or modify other users' notification preferences.
- [ ] **AC03 (Notification Pagination)**: `GET /v1/notifications` returns correctly paginated, ordered results.
- [ ] **AC04 (Unread Count)**: `GET /v1/notifications/unread-count` reflects exact count of unread items.
- [ ] **AC05 (Idempotent Mark-Read)**: Marking read multiple times succeeds idempotently.
- [ ] **AC06 (Secret Non-Leakage)**: Plaintext secret is never returned in API responses, logs, or audit events.
- [ ] **AC07 (Secret Encryption)**: Webhook secret is encrypted at rest using AES-256-GCM (`v1$` envelope).
- [ ] **AC08 (HMAC Byte-Parity)**: Outbound `X-SOC-Signature-256` matches independent HMAC-SHA256 byte-for-byte.
- [ ] **AC09 (Replay Window)**: Signature includes timestamp; requests older than 300s are rejected by contract.
- [ ] **AC10 (SSRF Private-IP Rejection)**: Outbound requests to `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, and `::1` fail immediately.
- [ ] **AC11 (DNS Rebinding Protection)**: Delivery-time DNS pinning prevents TOCTOU IP resolution flips.
- [ ] **AC12 (Redirect Rejection)**: HTTP redirects (301/302) are strictly blocked (`follow_redirects=False`).
- [ ] **AC13 (Timeout Enforcement)**: Webhook delivery times out after exactly 3.0 seconds.
- [ ] **AC14 (Retry Classification)**: 2xx = Delivered, 3xx/4xx/SSRF = Permanent Failure, 5xx/Timeout = Retry.
- [ ] **AC15 (Bounded Retries)**: Maximum 3 delivery attempts with jittered exponential backoff.
- [ ] **AC16 (Durable Outbox Creation)**: Outbox job is committed atomically in the same DB transaction as Alert.
- [ ] **AC17 (Concurrent Outbox Claiming)**: Multiple workers claim pending jobs with zero double-processing.
- [ ] **AC18 (Stale Worker Recovery)**: Jobs locked > 60s are automatically reclaimed by active workers.
- [ ] **AC19 (Circuit-Breaker Atomicity)**: 5 consecutive failures disable webhook with atomic SQL; no lost updates.
- [ ] **AC20 (Alert-to-Notification Correctness)**: All states in Alert-to-Notification matrix trigger as specified.
- [ ] **AC21 (At-Least-Once Delivery Semantics)**: `X-SOC-Delivery-ID` and `X-SOC-Event-ID` present on every dispatch.
- [ ] **AC22 (Full Regression)**: All existing 497 repository tests continue to pass with 0 failures.
- [ ] **AC23 (Clean-Checkout CI)**: Clean GitHub Actions run passes with 0 lint errors.
- [ ] **AC24 (PostgreSQL Staging Concurrency)**: All 8 staging concurrency scenarios pass on real PostgreSQL.

---

# 28. File-Level Change Plan

### Files to CREATE:
1. `backend/schemas/notification.py`: Pydantic request/response schemas.
2. `backend/services/notification_service.py`: In-app notification management, secret encryption/decryption, outbox enqueueing.
3. `backend/services/notification_dispatcher.py`: Background worker claiming outbox rows, executing SSRF-pinned HTTP POST, retries, and circuit breaker.
4. `backend/api/routers/notifications.py`: REST API router.
5. `migrations/versions/e7f8a9b0c1d2_sprint5_phase5d_outbox_circuit_breaker.py`: Schema additions (`notification_outbox`, preference fields, indexes).
6. `tests/unit/test_notification_service.py`: Service, encryption, HMAC, and SSRF unit tests.
7. `tests/integration/test_notifications_api.py`: REST endpoint, RBAC, and multi-tenancy integration tests.
8. `tests/integration/test_notification_concurrency.py`: 50-way concurrent dispatch and claiming tests.

### Files to MODIFY:
1. `backend/main.py`: Include `notifications.router` under `/v1`; register `NotificationDispatcher` lifespan.
2. `backend/services/alert_service.py`: Enqueue outbox job inside alert transaction.
3. `backend/services/monitoring_worker.py`: Enqueue outbox job on target auto-suspension or SSRF abort.

---

# 29. Protected Files Invariant

The following files are strictly **PROTECTED** and **MUST NOT BE MODIFIED**:
- `backend/services/incident_service.py`
- `backend/services/monitoring_probe.py`
- `backend/services/scheduler_service.py`
- `backend/core/security_network.py`
- `backend/services/threat_intel.py`
- `backend/services/intel_enrichment.py`
- `backend/schemas/soc.py`
- `ml/**`

---

# 30. Dependency & CI/CD Impact

- **Zero New Dependencies**: Reuses existing dependencies (`httpx`, `sqlalchemy`, `cryptography`, `pydantic`).
- **CI/CD Impact**: Fully compatible with existing GitHub Actions CI workflow.

---

# 31. Rollback Plan

1. **Feature Flag**: Setting `ENABLE_NOTIFICATIONS=false` in configuration immediately stops the background dispatcher and bypasses outbox enqueueing.
2. **Database Rollback**: Reversible Alembic migration `downgrade()` cleanly drops the `notification_outbox` table and added columns.
3. **Core Isolation**: Alert triage, probe execution, and ML scoring continue functioning uninterrupted if notification features are disabled or rolled back.

---

# 32. Risks & Open Questions

- **Risk 1: Egress Flapping Targets**: Mitigated by the 5-failure circuit breaker.
- **Risk 2: Egress SSRF via DNS Rebinding**: Mitigated by delivery-time IP pinning and redirect blocking.
- **Open Question 1**: Support for custom headers (e.g. `Authorization: Bearer <token>`)?
  - *Resolution*: Defer to Sprint 6; HMAC-SHA256 signature is industry-standard and sufficient for Phase 5D.

---

# 33. Implementation Roadmap

1. **Stage 1 (Approval Gate)**: Human review of this v1.2 specification.
2. **Stage 2 (Database Migration & Models)**: Implement migration `e7f8a9b0c1d2` and ORM models.
3. **Stage 3 (Core Service Layer)**: Implement `NotificationService` (outbox enqueueing, AES encryption, HMAC signing).
4. **Stage 4 (Dispatcher Engine)**: Implement `NotificationDispatcher` with SSRF-safe pinned egress and retry loop.
5. **Stage 5 (REST API Router)**: Implement `notifications.py` router and mount in `backend/main.py`.
6. **Stage 6 (Pipeline Wiring)**: Connect outbox enqueueing in `alert_service.py` and `monitoring_worker.py`.
7. **Stage 7 (Verification & Review)**: Execute Ralph test loop (unit, integration, concurrency) -> CodeRabbit Review -> Commit.

---

# 34. Final Architecture Recommendation

### **FINAL DECISION: GO WITH CONDITIONS**

**Mandatory Conditions for Implementation Authorization:**
1. **Durable Outbox Mandate**: Implementation must exclusively use the database Transactional Outbox pattern (`notification_outbox`). In-memory fire-and-forget dispatch (`asyncio.create_task`) is strictly prohibited.
2. **SSRF & DNS Pinning Guarantee**: Webhook dispatch must strictly reuse [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py) with delivery-time IP pinning and `follow_redirects=False`.
3. **Cryptographic Protection**: Webhook secrets must be $\ge 32$ characters (or 64 hex chars for generated secrets), encrypted at rest via AES-256-GCM (`v1$` envelope), and signed with HMAC-SHA256 adhering to the canonical string contract. Plaintext secrets must never be logged or returned.
4. **Atomic Circuit Breaker**: The 5-failure tripwire must be implemented via atomic database updates, ensuring zero lost updates under concurrent load, with racing successes prevented from reopening broken circuits.
5. **Protected Infrastructure Invariant**: All 8 protected files and directories remain strictly read-only.

---

> [!CAUTION]
> **READ-ONLY GATE — HUMAN APPROVAL REQUIRED**
> Even though the final architecture recommendation is **GO WITH CONDITIONS**, this does **NOT** constitute implementation authorization.
> Explicit human review and authorization must be granted before Roo code implementation or Ralph verification begins.
