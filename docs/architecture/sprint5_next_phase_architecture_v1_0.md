# SPRINT 5 — POST-5C ARCHITECTURAL DISCOVERY & NEXT PHASE SPECIFICATION v1.0
## Continuous SOC Alert Delivery, Secure Webhook Egress & Notification Infrastructure
### Document: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
### Mode: ARCHITECTURAL DISCOVERY & GSD PLANNING ONLY — NO IMPLEMENTATION AUTHORIZED

---

> [!IMPORTANT]
> **READ-ONLY ARCHITECTURAL DISCOVERY DOCUMENT (v1.0).**
> Current Baseline Commit: `43d94a6c970de64c077ecc136a40ca04a135df2d` (CI Run: `34715675452`, GREEN).
> All Sprint 5 Phases 5A, 5B, and 5C are verified, committed, pushed, and passing all CI quality gates.
> NO source code, migrations, tests, or configurations are modified during this discovery task.
> Implementation authorization is strictly reserved for a subsequent authorized phase.

---

# Table of Contents
1. [Executive Summary](#executive-summary)
2. [Current Verified State](#current-verified-state)
3. [Proposed Next Phase](#proposed-next-phase)
4. [Goals](#goals)
5. [Non-Goals](#non-goals)
6. [Architecture](#architecture)
7. [Threat Model](#threat-model)
8. [Database Design](#database-design)
9. [API Contract](#api-contract)
10. [Concurrency Model](#concurrency-model)
11. [Observability](#observability)
12. [Frontend/Extension Impact](#frontendextension-impact)
13. [Testing Strategy](#testing-strategy)
14. [Acceptance Criteria](#acceptance-criteria)
15. [Security Gates](#security-gates)
16. [File-Level Change Plan](#file-level-change-plan)
17. [Dependency Impact](#dependency-impact)
18. [CI/CD Impact](#cicd-impact)
19. [Rollback Plan](#rollback-plan)
20. [Risks](#risks)
21. [Open Questions](#open-questions)
22. [Implementation Order](#implementation-order)
23. [Human Approval Gate](#human-approval-gate)

---

# Executive Summary

The AI-Cyber-Security-Suite has achieved a fully functioning, autonomous backend detection and monitoring pipeline across Sprints 1 through 5C. 

- **Phase 5A** laid the foundational monitoring targets, validation boundaries, and quotas.
- **Phase 5B** established multi-pod distributed scheduler leadership, monotonic epoch fencing, stale-worker fencing, SSRF-safe outbound probing, frozen 59-feature ML inference, and automated event/alert/incident correlation.
- **Phase 5C** established the authoritative 4-state alert triage lifecycle (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`), threat recurrence semantics, target operational controls (`pause`, `resume`, `reactivate`, `check-now`), execution diagnostics, and bounded 24-hour telemetry across 13 verified REST endpoints.

### The Critical Architectural Missing Link
Despite this sophisticated detection and triage capability, **the platform currently possesses no outbound notification or delivery capability**. When a monitoring target suffers a severe security compromise (e.g. zero-day phishing or malware detected with high confidence), or is auto-suspended due to network failure, or an analyst-assigned alert is triggered:
1. The alert is written to the database.
2. **Zero alerts are pushed to the user or external security tools.**
3. The analyst or user is forced to continually poll `GET /v1/alerts`.

Fortunately, the database foundation for notifications was already pre-migrated during earlier Sprint 5 phases: the `Notification` and `NotificationPreference` models already exist in [`backend/database/models.py`](file:///E:/AI-Cyber-Security-Suite/backend/database/models.py#L228-L263) and database tables were laid down in migration `c5e6f7a8b9c0_sprint5_soc_monitoring_tables.py`.

Therefore, the most logical, high-value, and secure next phase is **Sprint 5 Phase 5D: SOC Notification Dispatch, Secure Webhook Egress & In-App Alert Center**. Phase 5D closes the loop on Sprint 5 ("Real-Time Threat Monitoring & Alerting Infrastructure"), transforming passive database rows into active, secure, real-time security alerts before proceeding to the Frontend Console (Sprint 6).

---

# Current Verified State

### Complete & Operational Subsystems (Sprints 1–5C):
- **Sprint 1 (Core Scanning & Detection)**: Real-time URL threat scanning, XGBoost classification, TreeSHAP feature attributions, JWT authentication, rate limiting, and Manifest V3 Chrome Extension.
- **Sprint 2 (Threat Intelligence Waterfall)**: Heuristic pre-filter, Rule 0 major domain allowlist, VirusTotal v3 API, PhishTank feeds, and zero-day log ingestion.
- **Sprint 3 (MLOps Lifecycle & Retraining)**: Model versioning, active learning candidate curation, automated retrain pipeline, label provenance tracking, and artifact isolation in CI.
- **Sprint 4 (Security Intelligence & Enrichment)**: Deep WHOIS domain age extraction, TLS certificate validation, HTTP redirect tracing, and centralized SSRF-safe networking layer ([`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py)).
- **Sprint 5 Phases 1–4 (SOC Incident Management)**: `EventEngine`, `CorrelationEngine`, `IncidentService` with auto-escalation, monotonically escalating severity, and strict multi-tenant isolation.
- **Sprint 5 Phase 5A (Monitoring Target Management)**: Target CRUD, SSRF pre-registration validation, and per-user target quota enforcement.
- **Sprint 5 Phase 5B (Autonomous Execution Engine)**: Distributed PostgreSQL advisory lock leader election with SQLite dev parity, monotonic epoch fencing, worker leases (`WORKER_LEASE_SECONDS = 45`), SSRF-safe probing, frozen 59-feature ML inference, triple-predicate write-back fencing, and stale-worker no-op protection.
- **Sprint 5 Phase 5C (Alert Triage & Operational Controls)**: Authoritative 4-state lifecycle, forbidden terminal flips (HTTP 400), recurrence on terminal states creating brand-new `OPEN` alerts, target operational controls (`pause`, `resume`, `reactivate`, `check-now`), diagnostics, telemetry, and 13 public endpoints.

### Verified Git & CI State:
- **Baseline Commit**: `43d94a6c970de64c077ecc136a40ca04a135df2d` (`feat: implement sprint 5 phase 5c alert triage`)
- **Remote `origin/main`**: In exact parity with local HEAD
- **GitHub Actions CI Run**: `34715675452` (Result: **SUCCESS**, all jobs green)
- **Local Test Suite**: 497 passed, 2 skipped, 0 failures

### Staging Verification Limitation:
- Multi-pod PostgreSQL row locking and distributed lease fencing tests (`test_postgres_row_locking_concurrency`) remain skipped locally and require a live PostgreSQL container in staging.

---

# Proposed Next Phase

### **Sprint 5 Phase 5D — SOC Notification Dispatch, Secure Webhook Egress & In-App Alert Center**

Phase 5D delivers the outbound delivery arm of Sprint 5. It activates the dormant `Notification` and `NotificationPreference` database tables, introducing an asynchronous, fail-closed, SSRF-safe notification engine that dispatches both internal In-App notifications and external HMAC-SHA256 signed webhooks.

### Why Phase 5D (and not Sprint 6 Frontend or Staging Deployment)?
1. **Fulfills Sprint 5 Scope**: Sprint 5 is entitled *"Real-Time Threat Monitoring & Alerting Infrastructure"*. Without delivery mechanisms, "Alerting" is incomplete.
2. **Pre-Existing Schema Investment**: The database tables (`notifications`, `notification_preferences`) were already created in migration `c5e6f7a8b9c0`. Leaving them unused creates architectural debt.
3. **Backend-First Philosophy**: Building the frontend SOC dashboard (Sprint 6) requires stable notification, alert, and target endpoints. Constructing the frontend before the notification API exists would necessitate costly rework and mock-layer overhead.
4. **Security Isolation**: Outbound webhook dispatch introduces critical security risks (SSRF, egress amplification, credential leakage) that must be rigorously architected and gated in isolation before exposure to UI interactions.

---

# Goals

1. **In-App Notification Inbox API**:
   - Provide tenant-scoped endpoints to list, paginate, filter, count unread, and mark notifications as read.
   - Enforce anti-enumeration (HTTP 404) for foreign-tenant notification UUID access.
2. **User Notification Preferences API**:
   - Allow users to configure minimum notification severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), enable/disable in-app alerts, and configure outbound webhook delivery.
3. **SSRF-Safe Webhook Egress Engine**:
   - Provide asynchronous, non-blocking webhook delivery for qualifying security events (CRITICAL/HIGH alerts, target auto-suspension, SSRF probe aborts).
   - Enforce strict fail-closed SSRF validation against destination webhook URLs using [`backend/core/security_network.py`](file:///E:/AI-Cyber-Security-Suite/backend/core/security_network.py).
   - Re-resolve DNS and enforce IP pinning at delivery time to neutralize DNS rebinding (TOCTOU) attacks.
   - Forbid redirects (`follow_redirects=False`) to prevent open-redirect SSRF pivoting into internal cloud metadata or VPC services.
4. **Cryptographic Webhook Signing**:
   - Sign all outbound webhook payloads using HMAC-SHA256 with user-configured or system-generated secret tokens (`X-SOC-Signature-256`, `X-SOC-Timestamp`).
5. **Reliability & Circuit-Breaking**:
   - Enforce strict per-request delivery timeouts (3.0s) and bounded payloads (max 64KB).
   - Implement exponential retry backoff (max 3 retries) for transient 5xx errors; immediately abort on 4xx client errors.
   - Implement automatic circuit-breaking: disable webhook delivery and notify user via in-app alert after 5 consecutive delivery failures.
6. **Zero Regression on Existing Pipelines**:
   - Notification dispatch must run strictly asynchronously without delaying or blocking the monitoring worker loop (`MonitoringWorker`), alert ingestion (`AlertService`), or scheduler thread.

---

# Non-Goals

1. **Direct SMTP / SendGrid Email Integration**: Direct email dispatch requires third-party credentials, SPF/DKIM/DMARC domain configuration, and HTML templating. Email delivery is explicitly deferred to an enterprise integrations release.
2. **Frontend UI Implementation**: No React dashboard components, notification bells, or settings pages will be built in Phase 5D. All UI implementation is strictly reserved for Sprint 6.
3. **WebSocket / SSE Streaming**: Real-time push streams to browser clients will be implemented in Sprint 6 alongside the live React SOC console. Phase 5D delivers standard REST polling and outbound webhook egress.
4. **Modification of Protected Files**: Core ML pipelines (`ml/**`), frozen feature schemas, scheduler epoch fencing, and probe networking remain strictly read-only.
5. **Two-Way Webhook Ingestion**: Inbound webhook processing (e.g. receiving commands from external SIEMs) is not in scope. Egress only.

---

# Architecture

### Component Architecture & Event Flow
```
┌───────────────────────────────────────────────────────────────────────────┐
│                      DETECTION & MONITORING CORE                         │
│                                                                           │
│   MonitoringWorker / EventEngine / ThreatIntel Waterfall                  │
│                                │                                          │
│                                ▼                                          │
│   AlertService.process_event() ──▶ Alert Created / Severity Escalated     │
│   MonitoringWorker             ──▶ Target Auto-Suspended / SSRF Aborted   │
└────────────────────────────────┬──────────────────────────────────────────┘
                                 │ triggers async dispatch
                                 ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                     NOTIFICATION ENGINE (Phase 5D)                        │
│                                                                           │
│   NotificationService.dispatch_alert_notification(alert_id, user_id)     │
│                                │                                          │
│         ┌──────────────────────┴──────────────────────┐                   │
│         │ Check NotificationPreference                 │                   │
│         │ (min_severity, in_app_enabled, webhook_en)  │                   │
│         ▼                                             ▼                   │
│   [In-App Path]                                [Webhook Path]             │
│   Create `Notification` row                     Async Task Queue          │
│   - user_id, title, message                     - SSRF Pre-flight DNS     │
│   - severity, link_url                          - IP Pinning Validation   │
│   - is_read = False                             - HMAC-SHA256 Signing     │
│                                                 - POST payload (timeout 3s)
│                                                 - Bounded Exponential Retry
│                                                 - AuditEvent on failure   │
└───────────────────────────────────────────────────────────────────────────┘
```

### Key Architectural Invariants:
1. **Fire-and-Forget / Isolated Failure Domain**:
   A failure, network timeout, or SSRF abort during webhook dispatch **must never roll back or fail the calling transaction** in `alert_service` or `monitoring_worker`. Notification dispatch is scheduled as a detached asynchronous task (`asyncio.create_task` or worker queue) after the primary database transaction has committed.
2. **Egress SSRF Guard**:
   Webhook destinations must undergo identical security filtering to probe targets: IP literal validation, private CIDR blocking, cloud metadata blocking (`169.254.169.254`), and DNS rebinding pinning.

---

# Threat Model

| Threat ID | Threat Category | Attack Vector | Impact | Mitigation Strategy |
|---|---|---|---|---|
| **TM-01** | **Outbound SSRF** | Attacker configures `webhook_url` targeting AWS metadata (`http://169.254.169.254/latest/meta-data/`) or internal cluster service (`http://10.0.0.1/`). | Cloud credential theft, internal reconnaissance, unauthorized VPC access. | **Mandatory Dual-Check**: Validate URL syntax and resolve IP at configuration time via `security_network.py`; re-resolve and pin IP at dispatch time. Forbid private/loopback/metadata CIDRs. Forbid redirects (`follow_redirects=False`). |
| **TM-02** | **DNS Rebinding (TOCTOU)** | Attacker registers a domain that resolves to a public IP during configuration, then flips DNS to `127.0.0.1` before an alert triggers. | Bypass configuration-time SSRF filter. | **DNS Pinning**: The dispatch HTTP client uses a custom transport that resolves the domain immediately before connection, validates against `is_blocked_ip()`, and connects directly to the validated IP with the `Host` header intact. |
| **TM-03** | **Webhook DoS & Egress Amplification** | Attacker generates high-frequency alert storms to weaponize the suite as a DDoS reflection engine against a target webhook endpoint. | Denial of Service against target, egress network exhaustion, backend worker exhaustion. | **Per-Tenant Rate Limiting**: Limit webhook dispatches to max 10/minute per user. Circuit breaker: 5 consecutive failures auto-disables the webhook and emits an in-app security warning. |
| **TM-04** | **Payload Secret Leakage** | Webhook payload contains internal database IDs, passwords, API tokens, or raw exception stack traces. | Information disclosure to external receivers or log aggregators. | **Bounded Public Contract**: Webhook payload strictly uses `WebhookAlertPayload` schema exposing only public alert metadata (`alert_uuid`, `title`, `severity`, `rule_name`, `indicator_value`, `first_seen_at`, `fingerprint`). Never include internal sequential IDs or credentials. |
| **TM-05** | **Signature Spoofing / Forgery** | Attacker intercepts or replays webhook payloads or forges messages claiming to be from the SOC. | Downstream automated remediation systems trigger false incident containment. | **Cryptographic HMAC-SHA256**: All dispatches include `X-SOC-Signature-256: t=<timestamp>,v1=<hex_hmac>`. Secret is minimum 32 bytes. Downstream verifies signature using constant-time comparison and rejects timestamps older than 300 seconds. |
| **TM-06** | **Cross-Tenant Notification Leakage** | User A queries `/v1/notifications` with User B's notification UUID. | Unauthorized visibility into security incidents of other organizations. | **Authoritative Server Predicate**: All notification lookups include `WHERE user_id = current_user.id`. Foreign access returns HTTP 404 anti-enumeration. |
| **TM-07** | **Database Exhaustion** | Persistent alert recurrence generates millions of unread `Notification` rows. | Database disk exhaustion, degraded query performance. | **Bounded Pagination & Retention**: Max `page_size=100`. Index on `(user_id, is_read, created_at)`. Auto-cap unread notifications per tenant (max 1,000 unread). |

---

# Database Design

### Existing Tables (Reused from `c5e6f7a8b9c0`):
The schema in [`backend/database/models.py`](file:///E:/AI-Cyber-Security-Suite/backend/database/models.py#L228-L263) is already defined and migrated:

#### 1. Table `notification_preferences`
- `id`: Integer, Primary Key
- `user_id`: Integer, ForeignKey(`users.id`, ondelete="CASCADE"), Unique, Indexed
- `in_app_enabled`: Boolean, default=True, nullable=False
- `email_enabled`: Boolean, default=False, nullable=False
- `webhook_enabled`: Boolean, default=False, nullable=False
- `webhook_url`: Text, nullable=True
- `webhook_secret`: String(255), nullable=True (HMAC signing secret)
- `min_severity`: String(32), default="HIGH", nullable=False
- `updated_at`: DateTime(timezone=True), nullable=False

#### 2. Table `notifications`
- `id`: Integer, Primary Key
- `notification_uuid`: String(36), Unique, Indexed, nullable=False
- `user_id`: Integer, ForeignKey(`users.id`, ondelete="CASCADE"), Indexed, nullable=False
- `title`: String(255), nullable=False
- `message`: Text, nullable=False
- `severity`: String(32), default="INFO", nullable=False
- `is_read`: Boolean, default=False, Indexed, nullable=False
- `link_url`: String(512), nullable=True
- `created_at`: DateTime(timezone=True), nullable=False

### Proposed Migration Refinements (Phase 5D Migration):
To optimize performance for large-scale production query patterns, Phase 5D will apply one backward-compatible, non-destructive migration (`sprint5_phase5d_notification_indexes`):
1. Add compound index `idx_notifications_user_created` on `("user_id", "created_at")` for efficient reverse-chronological pagination.
2. Add `consecutive_webhook_failures` (Integer, default=0, nullable=False) and `webhook_disabled_reason` (String(255), nullable=True) to `notification_preferences` to support circuit-breaking.

---

# API Contract

All endpoints require standard `get_current_user` Bearer authentication.

### 1. `GET /v1/notifications`
- **Description**: List in-app notifications for authenticated user, sorted by `created_at DESC`.
- **Query Parameters**:
  - `page`: int (default=1, ge=1)
  - `page_size`: int (default=20, ge=1, le=100)
  - `is_read`: bool | None
  - `severity`: str | None
- **Response**: `NotificationListResponse` (`items: list[NotificationResponse]`, `total`, `unread_count`, `page`, `page_size`, `has_next`)
- **Rate Limit**: 60/minute

### 2. `GET /v1/notifications/unread-count`
- **Description**: Return scalar unread notification count for rapid UI badge polling.
- **Response**: `{"unread_count": int}`
- **Rate Limit**: 120/minute

### 3. `POST /v1/notifications/{notification_uuid}/read`
- **Description**: Mark a single notification as read. Idempotent.
- **Response**: `NotificationResponse` (HTTP 200)
- **Error Behavior**: HTTP 404 if notification not found or owned by foreign tenant.
- **Rate Limit**: 60/minute

### 4. `POST /v1/notifications/mark-all-read`
- **Description**: Mark all unread notifications for current user as read.
- **Response**: `{"updated_count": int}` (HTTP 200)
- **Rate Limit**: 30/minute

### 5. `GET /v1/notifications/preferences`
- **Description**: Retrieve notification preferences for authenticated user.
- **Response**: `NotificationPreferenceResponse` (Note: `webhook_secret` is masked as `wh_sec_****` to prevent credential exposure).
- **Rate Limit**: 30/minute

### 6. `PUT /v1/notifications/preferences`
- **Description**: Update notification preferences.
- **Payload**: `NotificationPreferenceUpdateRequest`
  - `in_app_enabled`: bool
  - `webhook_enabled`: bool
  - `webhook_url`: HttpUrl | None (Validated against `validate_target_url` and `resolve_and_validate_host`)
  - `webhook_secret`: str | None (min_length=16, max_length=255)
  - `min_severity`: enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- **Validation Error**: HTTP 422 for invalid schemes or private IP literals; HTTP 400 if `webhook_url` fails SSRF resolution.
- **Rate Limit**: 15/minute

---

# Concurrency Model

1. **Non-Blocking Asynchronous Egress**:
   - Webhook delivery occurs in a dedicated `asyncio` task pool with an execution timeout of 3.0s per attempt.
   - Database operations (inserting `Notification` records) occur in a separate short-lived session, ensuring zero lock contention with monitoring worker write-backs or alert triage.
2. **Idempotent Mark-Read Transactions**:
   - `POST /v1/notifications/{uuid}/read` uses atomic updates (`UPDATE notifications SET is_read = TRUE WHERE notification_uuid = :uuid AND user_id = :uid`).
   - Multiple concurrent clicks by the user result in safe idempotent returns without database deadlocks.
3. **Database Portability**:
   - Standard SQLAlchemy async patterns compatible with SQLite in-memory tests and PostgreSQL multi-connection pools.

---

# Observability

1. **Structured Logging**:
   - JSON logs capturing: `notification_uuid`, `user_id`, `alert_uuid`, `delivery_channel` (`in_app` vs `webhook`), `webhook_host`, `status_code`, `latency_ms`, and `attempt_number`.
2. **Audit Trail**:
   - Emit `AuditEvent`:
     - `NOTIFICATION_PREFERENCES_UPDATED` (details include altered flags, masked URL; never raw secret).
     - `WEBHOOK_CIRCUIT_BROKEN` (emitted when 5 consecutive failures disable a user's webhook).
     - `NOTIFICATION_DISPATCH_FAILED` (emitted on permanent delivery failure).
3. **Failure Taxonomy**:
   - `SSRF_BLOCKED`: Webhook URL failed egress network security check.
   - `DNS_RESOLUTION_FAILED`: Destination domain could not be resolved.
   - `CONNECT_TIMEOUT`: Connection timed out after 3.0s.
   - `HTTP_SERVER_ERROR`: Destination returned 5xx status.
   - `PAYLOAD_OVERSIZED`: Webhook payload exceeded 64KB.

---

# Frontend/Extension Impact

- **Frontend (Sprint 6 Readiness)**:
  - Phase 5D builds the exact backend contract required for the Sprint 6 React SOC Console:
    1. Top navigation notification bell with unread badge counter (`GET /v1/notifications/unread-count`).
    2. Slide-out notification center drawer with instant "Mark all as read" capability.
    3. User Settings tab for configuring webhook integrations (Slack / Discord / Webhook endpoints).
- **Browser Extension**:
  - Zero direct changes to Manifest V3 extension in Phase 5D.

---

# Testing Strategy

Phase 5D must achieve 100% test passing rate across the following categories:

1. **Unit Tests (`tests/unit/test_notification_service.py`)**:
   - In-app notification creation with correct severity filtering.
   - Idempotent mark-read and mark-all-read behavior.
   - Webhook HMAC-SHA256 signature generation and timestamp header verification.
   - SSRF rejection: Attempting to configure `http://169.254.169.254`, `http://127.0.0.1`, `http://10.0.0.1`, or `http://localhost` raises `MonitorSSRFError` / HTTP 422.
   - Circuit breaker activation after 5 consecutive simulated delivery failures.
2. **Integration Tests (`tests/integration/test_notifications_api.py`)**:
   - Full REST lifecycle: GET preferences -> PUT preferences -> trigger alert -> GET notifications -> POST read.
   - Multi-tenant isolation: Tenant A receives 404 when attempting to view or read Tenant B's notifications.
   - Anti-enumeration: Requesting non-existent UUID returns HTTP 404.
   - Mocked outbound webhook server: Verifies delivery headers (`X-SOC-Signature-256`, `X-SOC-Timestamp`), payload structure, and retry timing.
3. **Concurrency Tests (`tests/integration/test_notification_concurrency.py`)**:
   - 50 concurrent mark-read requests on the same notification.
   - Simultaneous alert creation and notification dispatch across multiple tenants.
4. **Full Regression Guard**:
   - Complete 497 existing repository tests must pass with 0 failures.
   - Ruff lint clean on all new Phase 5D files.

---

# Acceptance Criteria

- [ ] **AC-01**: `GET /v1/notifications` returns paginated notifications strictly scoped to the authenticated user.
- [ ] **AC-02**: `GET /v1/notifications/unread-count` accurately returns the count of unread notifications.
- [ ] **AC-03**: `POST /v1/notifications/{uuid}/read` transitions `is_read` to `True` idempotently; returns 404 for foreign tenants.
- [ ] **AC-04**: `POST /v1/notifications/mark-all-read` marks all unread notifications as read in a single atomic transaction.
- [ ] **AC-05**: `GET /v1/notifications/preferences` returns the user's preferences with `webhook_secret` masked.
- [ ] **AC-06**: `PUT /v1/notifications/preferences` validates `webhook_url` against SSRF rules (rejecting loopback, private, and metadata IPs with HTTP 422/400).
- [ ] **AC-07**: When an alert is created with `severity >= min_severity`, an in-app `Notification` record is created if `in_app_enabled=True`.
- [ ] **AC-08**: When an alert is created with `severity >= min_severity`, an outbound webhook request is dispatched if `webhook_enabled=True`.
- [ ] **AC-09**: Outbound webhook requests include valid `X-SOC-Signature-256` HMAC-SHA256 signatures and timestamp headers.
- [ ] **AC-10**: Outbound webhook requests enforce a strict 3.0s timeout and follow zero redirects.
- [ ] **AC-11**: 5 consecutive webhook delivery failures automatically disable the webhook, reset consecutive counter, and emit an in-app notification warning.
- [ ] **AC-12**: Full test suite passes (>= 530 tests, 0 failures, 0 regressions).

---

# Security Gates

The following are **STRICT BLOCKERS** that will prevent review approval:
1. **SSRF Bypass**: Any code path that permits an outbound HTTP request to a private, loopback, or cloud-metadata IP.
2. **Secret Leakage**: Any API response or log message containing the plaintext `webhook_secret`.
3. **Tenant Boundary Bleed**: Any query lacking the authoritative `WHERE user_id = current_user.id` filter.
4. **Blocking Dispatch**: Any webhook network request executed synchronously inside a database transaction or worker claim loop.
5. **Missing Signatures**: Any webhook payload dispatched without cryptographic HMAC authentication.
6. **Protected File Mutation**: Any edit targeting protected Sprint 1–5B infrastructure.

---

# File-Level Change Plan

### Files to CREATE:
1. `backend/schemas/notification.py` — Pydantic request/response schemas.
2. `backend/services/notification_service.py` — Notification creation, preference management, and SSRF-safe webhook dispatcher.
3. `backend/api/routers/notifications.py` — REST endpoints for notifications and preferences.
4. `migrations/versions/e7f8a9b0c1d2_sprint5_phase5d_notification_circuit_breaker.py` — Index additions and circuit-breaker columns.
5. `tests/unit/test_notification_service.py` — Unit tests for service logic, HMAC signing, and SSRF guards.
6. `tests/integration/test_notifications_api.py` — Integration tests for REST endpoints and multi-tenancy.
7. `tests/integration/test_notification_concurrency.py` — Concurrency tests.

### Files to MODIFY:
1. `backend/main.py` — Include `notifications.router` under `/v1`.
2. `backend/services/alert_service.py` — Invoke `notification_service.dispatch_alert_notification` asynchronously on qualifying new alert creation.
3. `backend/services/monitoring_worker.py` — Invoke `notification_service.dispatch_monitoring_notification` on target auto-suspension or SSRF abort.

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

- **Existing Dependencies Reused**:
  - `httpx` (Already declared in `requirements.txt`) — Used for asynchronous, non-blocking outbound webhook POST requests.
  - `pydantic` (v2) — Used for schema validation.
  - `sqlalchemy` — Used for database models.
  - `hashlib` / `hmac` (Standard library) — Used for HMAC-SHA256 signature computation.
- **New External Dependencies**: **ZERO (0)**. No new packages required in `requirements.txt`.

---

# CI/CD Impact

- Phase 5D tests will execute within standard GitHub Actions runners using SQLite in-memory fixtures.
- **Recommendation for CI**: Phase 5D does not require altering `.github/workflows/ci.yml`. However, as an infrastructure enhancement, adding a PostgreSQL service container to `ci.yml` in a dedicated DevOps maintenance task would enable un-skipping `test_postgres_row_locking_concurrency`. For Phase 5D itself, existing CI pipelines remain 100% green.

---

# Rollback Plan

1. **Feature Flag**:
   - Introduce `ENABLE_NOTIFICATIONS=true/false` environment variable. If disabled, `NotificationService` immediately no-ops on all dispatch calls.
2. **Database Rollback**:
   - Alembic migration `e7f8a9b0c1d2` will provide a deterministic `downgrade()` function dropping the added columns and indexes without affecting underlying user accounts or alerts.
3. **Zero Impact on Core Detection**:
   - Rolling back Phase 5D leaves monitoring target execution, alert triage, incident escalation, and ML scanning 100% operational.

---

# Risks

1. **Egress Network Latency (Low Risk)**:
   - *Mitigation*: 3.0s hard timeout; dispatched asynchronously outside the request/response lifecycle.
2. **Webhook Target Flapping (Medium Risk)**:
   - *Mitigation*: 5-failure circuit breaker prevents infinite retry loops against dead receiver servers.
3. **Malicious Webhook URL Injection (High Risk)**:
   - *Mitigation*: Full reuse of `backend/core/security_network.py` prevents all private IP / localhost access.

---

# Open Questions

- **OQ-01**: Should webhook delivery support custom headers (e.g. `Authorization: Bearer <token>`) in addition to HMAC signing?
  - *Recommendation*: Start with HMAC-SHA256 signatures in Phase 5D; add custom headers in enterprise integrations sprint.
- **OQ-02**: Should notification retention be capped at N days (e.g. 90 days)?
  - *Recommendation*: Maintain records with a max-1000 unread per-user limit in Phase 5D; add automated TTL purging job in future maintenance.

---

# Implementation Order

1. **Stage 1 (Architecture & Review)**: Human review and authorization of this Phase 5D Specification.
2. **Stage 2 (Migration & Schemas)**: Create schema definitions (`notification.py`) and Alembic migration.
3. **Stage 3 (Core Service Layer)**: Implement `NotificationService` with HMAC signing and SSRF-safe egress.
4. **Stage 4 (API Router)**: Implement `notifications.py` router and mount in `backend/main.py`.
5. **Stage 5 (Pipeline Integration)**: Connect notification triggers in `alert_service.py` and `monitoring_worker.py`.
6. **Stage 6 (Verification & Review)**: Execute Ralph test-fix loop (unit, integration, concurrency) -> CodeRabbit Review -> Commit.

---

# Human Approval Gate

Implementation is strictly blocked until explicit human approval is granted.

---

# Final Recommendation

### **GO WITH CONDITIONS**

**Conditions**:
1. **Scope Restriction**: Phase 5D must be restricted to In-App Notifications and Webhook Delivery. Email (SMTP/SendGrid) and React UI components are deferred.
2. **Egress Safety**: All webhook URLs must pass through `backend/core/security_network.py` without exception.
3. **Non-Blocking Invariant**: Notification dispatch must never hold or delay detection transactions.
