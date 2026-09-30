# SPRINT 5 — PHASE 5F ARCHITECTURE & SECURITY SPECIFICATION v1.0
## Automated Threat Containment, Declarative SOAR-Lite Playbooks & Lifecycle Retention

### Document: `docs/architecture/sprint5_phase5f_arch_spec_v1_0.md`
### Status: ARCHITECTURAL SPECIFICATION v1.0 — READ-ONLY — NO IMPLEMENTATION AUTHORIZED
### Authoritative Baseline: Commit `868f299145d1e2592c5ffacad8ea7d2c4678602f` (CI Run `35126256147`, GREEN)

---

> [!IMPORTANT]
> **READ-ONLY ARCHITECTURE SPECIFICATION (v1.0)**
> - Baseline Commit: `868f299145d1e2592c5ffacad8ea7d2c4678602f` (`feat(soc): implement sprint 5 phase 5e real-time alert streaming`).
> - Sprints 5A through 5E are 100% verified, committed, pushed, and passing all CI checks.
> - All 8 protected infrastructure components (`backend/core/security_network.py`, `backend/services/monitoring_probe.py`, `backend/services/monitoring_worker.py`, `backend/services/scheduler_service.py`, `backend/services/threat_intel.py`, `backend/services/intel_enrichment.py`, `backend/schemas/soc.py`, `ml/**`) remain untouched.
> - The 5 pre-existing working-tree files remain untouched and unstaged.
> - NO source code, migrations, tests, or configurations are modified during this architecture gate.
> - Implementation authorization is strictly reserved for subsequent explicit human approval.

---

# Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Current Verified State (Phases 5A–5E Baseline)](#2-current-verified-state-phases-5a5e-baseline)
3. [Problem Statement](#3-problem-statement)
4. [Goals](#4-goals)
5. [Explicit Non-Goals](#5-explicit-non-goals)
6. [Component Architecture & Event Flow](#6-component-architecture--event-flow)
7. [Human-Safety & Containment Policy Model](#7-human-safety--containment-policy-model)
8. [Rule 0 — Allowlist Fencing Invariant](#8-rule-0--allowlist-fencing-invariant)
9. [Declarative Playbook Engine](#9-declarative-playbook-engine)
10. [Automated Containment Actions](#10-automated-containment-actions)
11. [Target Quarantine Semantics](#11-target-quarantine-semantics)
12. [Incident Binding Integration](#12-incident-binding-integration)
13. [Idempotency & Concurrency Model](#13-idempotency--concurrency-model)
14. [Provenance-Safe Rollback Engine](#14-provenance-safe-rollback-engine)
15. [Dynamic Blacklist & Cache Invalidation](#15-dynamic-blacklist--cache-invalidation)
16. [Phase 5E Streaming Event Integration](#16-phase-5e-streaming-event-integration)
17. [Phase 5D Notification Integration](#17-phase-5d-notification-integration)
18. [Lifecycle Retention & Pruning Architecture](#18-lifecycle-retention--pruning-architecture)
19. [Database Schema & Migrations](#19-database-schema--migrations)
20. [API Contracts](#20-api-contracts)
21. [Threat Model & Security Invariants](#21-threat-model--security-invariants)
22. [Failure Modes & Degraded Behavior](#22-failure-modes--degraded-behavior)
23. [Observability & Audit Trail](#23-observability--audit-trail)
24. [Testing Strategy](#24-testing-strategy)
25. [Staging Strategy (AC24 Parity)](#25-staging-strategy-ac24-parity)
26. [Acceptance Criteria](#26-acceptance-criteria)
27. [Implementation File Scope](#27-implementation-file-scope)
28. [Protected Files & Invariants](#28-protected-files--invariants)
29. [Rollback Plan](#29-rollback-plan)
30. [Open Decisions & Approval Gate](#30-open-decisions--approval-gate)

---

## 1. Executive Summary

Sprint 5 Phase 5F delivers the final backend automation capstone for the AI-Cyber-Security-Suite SOC subsystem. 

While Phases 5A through 5E built continuous target scheduling, autonomous SSRF-safe scanning, alert triage lifecycles, transactional outbox webhook egress, and real-time SSE event streaming, **the platform remains fundamentally reactive**. When an active zero-day phishing attack or high-confidence ransomware threat is detected, the suite alerts the user, but cannot take automated defensive action. Furthermore, append-only logs (`soc_event_stream` and `notification_outbox`) accumulate indefinitely without automated retention pruning.

Phase 5F delivers:
1. **Automated Threat Containment**: Safe, policy-governed automated blacklisting, cache purging, and target quarantine.
2. **Declarative SOAR-Lite Playbooks**: Type-safe, auditable execution flows with zero arbitrary code execution.
3. **Rule 0 Allowlist Fencing**: An unbreakable security boundary preventing self-inflicted Denial of Service against legitimate domains.
4. **Idempotent, Provenance-Safe Rollback**: Precision undo mechanics that only revert actions taken by a specific containment execution.
5. **Durable Lifecycle Retention Worker**: Non-blocking, bounded batch pruning for event streams (7-day TTL) and outbox jobs (30-day TTL).

---

## 2. Current Verified State (Phases 5A–5E Baseline)

The Phase 5F specification builds upon the verified foundation of Sprints 5A through 5E:

| Phase | Commit | Key Architectural Properties Verified in Baseline |
|---|---|---|
| **Phase 5A** | `43225b6` | Target CRUD, SSRF pre-registration validation, quota (`MAX_TARGETS_PER_USER = 20`), `scheduler_state`. |
| **Phase 5B** | `3624207` | PostgreSQL advisory lock leader election, worker leases (`45s`), SSRF DNS-pinned probe, frozen 59-feature ML threat inference, triple-predicate atomic writeback fencing. |
| **Phase 5C** | `43d94a6` | Authoritative 4-state alert triage (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`), forbidden terminal flips (HTTP 400), recurrence on terminal states, operational target controls (`pause`, `resume`, `reactivate`, `check-now`), diagnostics, 24h telemetry. |
| **Phase 5D** | `c9765d5` | Transactional outbox table (`notification_outbox`), background `NotificationDispatcher`, SSRF DNS-pinned egress, AES-256-GCM secret encryption with `v1$` envelope, canonical HMAC-SHA256 signing with 300s replay tolerance, 5-failure atomic circuit breaker. |
| **Phase 5E** | `868f299` | Durable `soc_event_stream` with monotonic 64-bit `cursor_id`, W3C `Last-Event-ID` replay, single-use 30s stream tickets (`st_*`), query JWT prohibition, multi-pod Redis Pub/Sub with in-memory degraded mode, bounded client queues (100 items, 16KB payload), and AC24 staging harness (`docker-compose.staging.yml`). |

---

## 3. Problem Statement

1. **Passive Detection Void**: When an alert escalates to `CRITICAL` or a target suffers repeated compromise, no automated mitigation occurs. Malicious indicators remain accessible until an analyst manually acts.
2. **Denial-of-Service Risk from Naive Auto-Blocking**: Blindly auto-blacklisting indicators on `CRITICAL` alerts creates a catastrophic vulnerability: an attacker crafting an alert targeting `google.com` or `microsoft.com` could cause the security suite to block mission-critical enterprise services.
3. **Target Flapping Under Active Attack**: A monitoring target experiencing repeated active exploitation continues executing probes, generating alert storms and exhausting resources without an automated circuit breaker.
4. **Append-Only Database Accumulation**: Phase 5E specified a 7-day TTL for `soc_event_stream` and Phase 5D accumulated outbox records, but no background worker cleans up old rows, leading to unbounded storage growth.
5. **Disjoint Incident Workflow**: Security alerts and SOC incidents exist as separate entities unless manually correlated, delaying coordinated incident response.

---

## 4. Goals

1. **Human-Safe Default Policy**: Automated containment is **disabled by default**. Tenants must explicitly opt in through granular configuration.
2. **Unbreakable Rule 0 Allowlist Fencing**: Zero automated containment action can ever blacklist, block, or quarantine an allowlisted domain.
3. **Declarative, Auditable Playbooks**: Predefined, typed execution DAGs with zero arbitrary code execution (`eval`, `exec`, or shell).
4. **Durable Idempotency**: Exactly-once execution guaranteed at the database layer via collision-safe uniqueness constraints.
5. **Provenance-Safe Rollback**: Reverting a containment action removes *only* the specific entries created by that action, preserving analyst and external blacklist entries.
6. **Unified Real-Time Observability**: Emit real-time Phase 5E streaming events (`containment_applied`, `containment_reverted`, `playbook_completed`) and Phase 5D outbox notifications.
7. **Non-Blocking Lifecycle Retention Worker**: Bounded-batch background task cleaning up expired event streams (7 days) and outbox jobs (30 days) with zero table locking.

---

## 5. Explicit Non-Goals

1. **Frontend UI Implementation**: All React 19 UI components (Alert Center, Playbook Drawer, Containment Console) belong strictly to Sprint 6.
2. **Arbitrary Code Execution**: No user-supplied scripts, regexes, Python snippets, or shell commands.
3. **External Infrastructure Mutation**: No direct integration with external firewalls, AWS Security Groups, or Cloudflare WAF. Containment is restricted to internal detection surfaces (`blacklist`, `cache`, `monitoring_targets`, `incidents`).
4. **Bulk Triage & SIEM Export**: Bulk status updates and CEF/Syslog exports are deferred to a dedicated integration phase.
5. **Modifying Protected Files**: Core ML pipelines (`ml/**`), SSRF networking (`security_network.py`), probe mechanics (`monitoring_probe.py`), threat intel feeds (`threat_intel.py`), and scheduler state (`scheduler_service.py`) remain strictly read-only.

---

## 6. Component Architecture & Event Flow

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  ALERT TRIAGE / DETECTION EVENT                                  │
│                                                                                                  │
│   AlertService.create_alert() / AlertService.acknowledge_alert()                                 │
│   (Emits CRITICAL / HIGH severity alert within database transaction)                             │
└────────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                 │ POST-COMMIT
                                                 ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 CONTAINMENT ENGINE (Phase 5F)                                    │
│                                                                                                  │
│  1. Check Policy Gate: `auto_containment_enabled == True`?                                       │
│     NO  ──▶ Log Policy Bypass Audit Event ──▶ TERMINATE                                          │
│     YES ──▶ Continue                                                                             │
│                                                                                                  │
│  2. Rule 0 Allowlist Fence: `threat_intel_service.is_whitelisted(indicator)`?                    │
│     YES ──▶ Log ALLOWLIST_CONTAINMENT_BLOCKED Audit ──▶ TERMINATE                                │
│     NO  ──▶ Continue                                                                             │
│                                                                                                  │
│  3. Acquire Distributed Execution Lock: `soc:playbook:lock:{tenant_id}:{target_id}`              │
│  4. Check Idempotency Key in Database: `soc_playbook_runs` (Unique Constraint)                   │
│                                                                                                  │
│  5. Execute Declarative Playbook Actions:                                                         │
│     ┌────────────────────────┬────────────────────────┬────────────────────────┐                 │
│     │  BLACKLIST_INDICATOR   │   QUARANTINE_TARGET    │    CREATE_INCIDENT     │                 │
│     │  Insert into           │   Update status to     │   Link alert to        │                 │
│     │  `soc_dynamic_blacklist`│  `SUSPENDED`           │   `IncidentService`    │                 │
│     └───────────┬────────────┴───────────┬────────────┴───────────┬────────────┘                 │
│                 │                        │                        │                              │
│                 ▼                        ▼                        ▼                              │
│  6. Invalidate Cache: `cache_service.invalidate(indicator)` (Non-blocking)                       │
│  7. Persist Actions & Run: Commit `soc_containment_actions` and `soc_playbook_runs`              │
│  8. Emit Phase 5E Event: `event_broadcaster.publish_event_nowait(containment_applied)`           │
│  9. Enqueue Phase 5D Outbox: `notification_service.create_in_app_and_outbox_for_alert()`         │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Human-Safety & Containment Policy Model

To ensure automated containment never executes unpredictably:

### 1. Default Safe Mode:
Automated containment is **disabled by default** across all tenants. A tenant's alerts will never trigger automated mitigation unless explicitly configured.

### 2. Granular Policy Configuration:
Extended in `notification_preferences` or dedicated `soc_containment_policies`:
- `auto_containment_enabled: bool` (Master kill-switch, default `False`)
- `auto_blacklist_enabled: bool` (Enables automated indicator blacklisting, default `False`)
- `auto_quarantine_enabled: bool` (Enables target suspension on alert storms, default `False`)
- `auto_incident_binding_enabled: bool` (Enables automatic incident creation/linking, default `False`)
- `containment_min_severity: str` (Minimum severity to evaluate; default `"CRITICAL"`, restricted to `"CRITICAL"` or `"HIGH"`)

### 3. Separation of Concerns:
- **DETECTION**: ML inference and rules determine threat class and severity.
- **CONTAINMENT AUTHORIZATION**: Policy evaluation verifies tenant configuration, allowlist status, and idempotency.
- **CONTAINMENT EXECUTION**: Atomically modifies database state, invalidates cache, and notifies stakeholders.

---

## 8. Rule 0 — Allowlist Fencing Invariant

> [!CAUTION]
> **HARD SECURITY INVARIANT — ZERO BYPASS PERMITTED**
> Under no circumstances may an automated containment action blacklist, block, or disrupt an indicator matching the trusted allowlist.

### Verification Mechanism:
Before `BLACKLIST_INDICATOR` or `QUARANTINE_TARGET` can execute:
1. The indicator (URL, normalized domain, or host) is evaluated against the trusted allowlist:
   `is_allowlisted = threat_intel_service.is_whitelisted(indicator_value)`
2. If `is_allowlisted == True`:
   - The action is immediately aborted.
   - Action status is recorded as `BLOCKED_BY_ALLOWLIST`.
   - An immutable `AuditEvent` is logged: `CONTAINMENT_BLOCKED_BY_ALLOWLIST` with actor, tenant, indicator, and timestamp.
   - No blacklist entry is created; no target status is altered.

### Protected File Invariant:
[`backend/services/threat_intel.py`](file:///e:/AI-Cyber-Security-Suite/backend/services/threat_intel.py) is strictly protected. Containment invokes its existing public methods (`is_whitelisted()`) without modifying the underlying service.

---

## 9. Declarative Playbook Engine

Playbooks are strictly declarative Python classes defining deterministic sequences of predefined action types.

### Predefined Action Types:
1. `BLACKLIST_INDICATOR`: Inserts indicator into `soc_dynamic_blacklist`.
2. `INVALIDATE_CACHE`: Purges matching URL/domain from Redis prediction cache.
3. `QUARANTINE_TARGET`: Suspends monitoring target (`is_active = False`).
4. `CREATE_INCIDENT`: Creates or binds to a SOC Incident via `IncidentService`.
5. `EMIT_SOC_EVENT`: Dispatches real-time SSE event via `EventBroadcaster`.
6. `SEND_NOTIFICATION`: Enqueues outbox webhook and in-app notification.

### Predefined Playbooks:
1. `CRITICAL_THREAT_AUTO_CONTAINMENT_V1`:
   - Triggers on: `alert_created` or `alert_updated` where `severity == "CRITICAL"`.
   - Actions: `BLACKLIST_INDICATOR` -> `INVALIDATE_CACHE` -> `CREATE_INCIDENT` -> `EMIT_SOC_EVENT` -> `SEND_NOTIFICATION`.
2. `REPEATED_TARGET_COMPROMISE_QUARANTINE_V1`:
   - Triggers on: Target reaching $\ge 3$ active high-severity alerts in 10 minutes.
   - Actions: `QUARANTINE_TARGET` -> `EMIT_SOC_EVENT` -> `SEND_NOTIFICATION`.
3. `MANUAL_CONTAINMENT_V1`:
   - Triggers on: Analyst invoking `POST /v1/soc/actions/contain`.
   - Actions: Configured action executed with analyst user attribution.

---

## 10. Automated Containment Actions

Every action is persisted in `soc_containment_actions`:
- **Action UUID**: Unique v4 identifier.
- **Tenant Scope**: Strictly bound to `tenant_id`.
- **Action Status**: `PENDING` -> `EXECUTED` | `FAILED` | `REVERTED` | `BLOCKED_BY_ALLOWLIST`.
- **Target Identifier**: The URL, domain, or target UUID affected.
- **Rollback Metadata**: Captures exact pre-execution state for deterministic rollback.

---

## 11. Target Quarantine Semantics

To prevent runaway alert storms and mitigate active compromise:

### Exact Quarantine Threshold Criteria:
A monitoring target is automatically quarantined if and only if:
1. `auto_quarantine_enabled == True` for the owning tenant.
2. The target currently has **$\ge 3$ distinct active alerts** where:
   - Status is `OPEN` or `ACKNOWLEDGED` (resolved or dismissed alerts do not count).
   - Severity is `CRITICAL` or `HIGH`.
   - `Alert.user_id == target.user_id` (strict tenant ownership).
   - `Alert.indicator_value` or `Alert.fingerprint` links to `target.url` or `target.normalized_domain`.
   - `Alert.last_seen_at >= NOW() - INTERVAL '10 minutes'`.
3. The target is not already `is_active == False` (idempotent no-op).

### Quarantine Execution:
1. Sets `monitoring_targets.is_active = False`.
2. Sets `monitoring_targets.last_error_message = "Auto-quarantined: 3+ high-severity alerts within 10m"`.
3. Emits `target_status_changed` SSE event and enqueues notification.

---

## 12. Incident Binding Integration

Containment seamlessly reuses the existing `IncidentService` without creating competing models:
1. When `CREATE_INCIDENT` executes:
   - Queries for an existing open incident: `incident_service.get_open_incident_for_target(session, target_id, tenant_id)`.
   - If an open incident exists: attaches the triggering alert via `incident_service.attach_alerts_to_incident()` and escalates severity if the new alert is more severe.
   - If no open incident exists: creates a new incident via `incident_service.create_incident()`.
2. All operations remain strictly tenant-isolated (`tenant_id == current_user.id`).

---

## 13. Idempotency & Concurrency Model

### 1. Collision-Safe Idempotency Key:
Every playbook run and containment action computes a deterministic idempotency key:
- Playbook Run Key: `f"tenant:{tenant_id}:alert:{alert_id}:playbook:{playbook_name}"`
- Action Key: `f"tenant:{tenant_id}:alert:{alert_id}:action:{action_type}:{target_identifier}"`

### 2. Database-Enforced Uniqueness:
- Table `soc_playbook_runs` enforces `UNIQUE(idempotency_key)`.
- Table `soc_containment_actions` enforces `UNIQUE(action_idempotency_key)`.
- Concurrent triggers for the same alert race: exactly one transaction commits; the loser catches the unique constraint violation and cleanly returns the existing run.

### 3. Distributed Redis Coordination (Optional Optimization):
- Key: `soc:playbook:lock:{tenant_id}:{target_id}`.
- Value: Random UUID token.
- TTL: 30 seconds.
- Safe release via Lua script checking token before `DEL`.
- If Redis is offline: Engine falls back cleanly to database uniqueness guarantees.

### 4. Tenant Concurrency Throttling:
- Max 5 concurrent playbook executions per tenant via an in-memory `asyncio.Semaphore(5)` per process.
- Excess requests are rejected with HTTP 429 or enqueued up to a bounded limit of 20.

---

## 14. Provenance-Safe Rollback Engine

Rollback must be deterministic, auditable, and incapable of damaging independent security data.

### Rollback Contract (`POST /v1/soc/actions/{action_uuid}/revert`):
1. **Ownership Check**: Requesting user must own the action (`tenant_id == current_user.id`) or have `role == "admin"`.
2. **Current Status Check**: Action must be in status `EXECUTED`. Reverting `REVERTED` or `FAILED` actions returns HTTP 400.
3. **Provenance Validation**:
   - `BLACKLIST_INDICATOR` Rollback:
     - Looks up the specific row in `soc_dynamic_blacklist` where `containment_action_id == action.id`.
     - Deactivates only that row (`is_active = False`).
     - **NEVER deletes or deactivates** blacklist rows created by analysts, external feeds, or other playbooks.
   - `QUARANTINE_TARGET` Rollback:
     - Restores `monitoring_targets.is_active = True` **only if** the target was deactivated by this exact containment action and has not been subsequently altered.
4. **State Transition**: Action transitions to `REVERTED` with `reverted_at` and `reverted_by_user_id`.
5. **Event Emission**: Dispatches `containment_reverted` SSE frame and logs an immutable `AuditEvent`.

---

## 15. Dynamic Blacklist & Cache Invalidation

### Table: `soc_dynamic_blacklist`
```sql
CREATE TABLE soc_dynamic_blacklist (
    id                    SERIAL PRIMARY KEY,
    indicator_type        VARCHAR(32) NOT NULL,            -- 'url', 'domain', 'ip'
    indicator_value       VARCHAR(512) NOT NULL,
    tenant_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    containment_action_id INTEGER REFERENCES soc_containment_actions(id) ON DELETE SET NULL,
    reason                VARCHAR(255) NOT NULL,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at            TIMESTAMPTZ NULL,                -- Optional TTL
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dynamic_blacklist_indicator ON soc_dynamic_blacklist (indicator_value, is_active);
CREATE INDEX idx_dynamic_blacklist_tenant ON soc_dynamic_blacklist (tenant_id, is_active);
```

### Cache Invalidation:
Upon blacklisting:
1. `cache_service.invalidate(indicator_value)` purges cached scan responses.
2. Invalidation is non-blocking; Redis errors log a warning without failing the database transaction.

---

## 16. Phase 5E Streaming Event Integration

Containment engine dispatches real-time SSE frames using the Phase 5E `EventBroadcaster`:
- `playbook_triggered`: Playbook evaluation initiated.
- `containment_applied`: Action executed (includes action UUID, type, and target).
- `containment_reverted`: Action successfully rolled back.
- `playbook_completed`: Playbook finished execution.

All events:
- Are written to `soc_event_stream` inside the transaction.
- Are broadcast post-commit via `publish_event_nowait`.
- Are bounded to 16KB max payload.

---

## 17. Phase 5D Notification Integration

Containment events trigger stakeholder notifications via existing Phase 5D architecture:
1. In-app notification created with `severity = "CRITICAL"`.
2. Transactional outbox row inserted into `notification_outbox` for webhook subscribers.
3. Webhook payloads signed with HMAC-SHA256 (`X-SOC-Signature-256`) and dispatched via `NotificationDispatcher` with SSRF DNS pinning.

---

## 18. Lifecycle Retention & Pruning Architecture

Phase 5F delivers the background retention pruning worker closing the Phase 5E architectural requirement.

### Retention Policy:
| Table | Retention Window | Purge Filter |
|---|---|---|
| `soc_event_stream` | **7 Days** | `created_at < NOW() - INTERVAL '7 days'` |
| `notification_outbox` | **30 Days** | `created_at < NOW() - INTERVAL '30 days' AND status IN ('DELIVERED', 'DEAD_LETTER')` |
| `soc_containment_actions` | **90 Days** | `created_at < NOW() - INTERVAL '90 days' AND status IN ('EXECUTED', 'REVERTED')` |
| `soc_playbook_runs` | **90 Days** | `created_at < NOW() - INTERVAL '90 days' AND status IN ('COMPLETED', 'FAILED')` |

### Bounded Batch Pruning Worker (`RetentionWorker`):
1. **Cadence**: Executes once every 1 hour (`RETENTION_INTERVAL_SECONDS = 3600`).
2. **Batching**: Deletes in bounded batches of **500 rows** (`LIMIT 500`) with a 0.5s pause between batches to prevent PostgreSQL lock contention.
3. **Replay Invariant**: When `soc_event_stream` rows are pruned, reconnecting clients with older cursors receive `stream_reset` per Phase 5E protocol.
4. **Lifecycle**: Starts and stops cleanly in `backend/main.py` lifespan context.

---

## 19. Database Schema & Migrations

### Migration ID: `b2c3d4e5f6a7_sprint5_phase5f_soc_containment.py`
Creates tables:
1. `soc_playbook_runs`
2. `soc_containment_actions`
3. `soc_dynamic_blacklist`

### Schema Definitions (Dialect-Safe SQLAlchemy):
All JSON columns use `JSON().with_variant(Text, "sqlite")` for cross-dialect compatibility between SQLite in-memory testing and PostgreSQL 16 production.

---

## 20. API Contracts

All endpoints require standard `Authorization: Bearer <jwt>` headers and enforce strict tenant scoping.

### 1. `POST /v1/soc/actions/contain`
- **Description**: Manually invoke a containment action on an indicator or target.
- **Request Body**: `ContainmentRequest` (`action_type`, `target_identifier`, `alert_id`, `reason`).
- **Response**: `ContainmentActionResponse` (HTTP 201).
- **Rate Limit**: 20/minute.

### 2. `GET /v1/soc/actions`
- **Description**: List containment actions scoped to authenticated tenant.
- **Query Params**: `status`, `action_type`, `page`, `page_size`.
- **Response**: `PaginatedContainmentActions` (HTTP 200).
- **Rate Limit**: 60/minute.

### 3. `GET /v1/soc/actions/{action_uuid}`
- **Description**: Retrieve details of a specific containment action.
- **Response**: `ContainmentActionResponse` (HTTP 200). 404 for foreign tenant.
- **Rate Limit**: 60/minute.

### 4. `POST /v1/soc/actions/{action_uuid}/revert`
- **Description**: Idempotently rollback an executed containment action.
- **Response**: `ContainmentActionResponse` (HTTP 200, status=`REVERTED`).
- **Rate Limit**: 20/minute.

### 5. `GET /v1/soc/playbooks/runs`
- **Description**: List playbook execution runs for authenticated tenant.
- **Response**: `PaginatedPlaybookRuns` (HTTP 200).
- **Rate Limit**: 60/minute.

---

## 21. Threat Model & Security Invariants

| Threat ID | Threat Vector | Impact | Mitigation Strategy |
|---|---|---|---|
| **T-5F-01** | **False-Positive Blacklisting via Crafted Alert** | Attacker tricks model into flagging `google.com`, causing suite to blacklist it. | **Rule 0 Allowlist Fence**: Mandatory check against `threat_intel_service.is_whitelisted()` before any blacklist action. Blocked with audit event. |
| **T-5F-02** | **Cross-Tenant Containment Manipulation** | Tenant A attempts to view or revert Tenant B's containment action. | **Authoritative Server Predicate**: All action and playbook lookups enforce `WHERE tenant_id = current_user.id`. Foreign access returns HTTP 404. |
| **T-5F-03** | **Playbook Execution Storm / DoS** | Alert storm triggers 1,000 simultaneous playbook executions, exhausting DB pool. | **Concurrency Cap & Rate Limit**: Max 5 concurrent executions per tenant; queue bounded at 20; database idempotency key prevents duplicate execution. |
| **T-5F-04** | **Blind Rollback Collateral Damage** | Reverting an auto-containment action accidentally removes an analyst's manual blacklist rule. | **Provenance Tracking**: Blacklist entries record `containment_action_id`. Rollback deletes only rows linked to that exact action. |
| **T-5F-05** | **Arbitrary Code Injection in Playbook** | Attacker submits payload attempting to inject shell commands or script execution. | **Declarative Type Safety**: Playbooks are strictly hardcoded Python DAGs; zero `eval`, `exec`, or shell invocations. |

---

## 22. Failure Modes & Degraded Behavior

1. **Redis Unavailable**: Distributed lock acquisition fails open to database uniqueness constraints; cache invalidation logs a warning; containment commits successfully.
2. **Database Transaction Rollback**: If any action step fails, the entire transaction rolls back; no partial containment entries persist; `soc_event_stream` row is discarded.
3. **Allowlist Failure / Timeout**: If allowlist check cannot be confirmed, containment fails closed (action is aborted, alert remains uncontained, audit event logged).
4. **Process Crash During Playbook Execution**: Idempotency key preserves state; subsequent retries safely detect existing run.

---

## 23. Observability & Audit Trail

### Structured Logging:
All containment operations log structured JSON containing: `tenant_id`, `action_uuid`, `run_uuid`, `action_type`, `target_identifier`, `duration_ms`, `status`.

### Immutable Audit Events (`audit_events`):
- `CONTAINMENT_ACTION_EXECUTED`
- `CONTAINMENT_ACTION_REVERTED`
- `CONTAINMENT_BLOCKED_BY_ALLOWLIST`
- `PLAYBOOK_RUN_COMPLETED`
- `PLAYBOOK_RUN_FAILED`
- `RETENTION_PRUNING_BATCH_COMPLETED`

---

## 24. Testing Strategy

Phase 5F must achieve 100% test pass rate across all tiers:
1. **Unit Tests (`tests/unit/test_containment_service.py`)**:
   - Rule 0 allowlist fencing (verifying allowlisted domains cannot be blacklisted).
   - Default safe mode (verifying containment no-ops when policy is disabled).
   - Idempotent action execution and idempotency key collision handling.
   - Provenance-safe rollback (verifying only action-owned blacklist rows are removed).
   - Target quarantine threshold evaluation.
2. **API Tests (`tests/integration/test_containment_api.py`)**:
   - REST endpoints for contain, list, details, and revert.
   - Multi-tenant isolation (HTTP 404 on foreign action UUIDs).
   - Admin RBAC operations.
3. **Concurrency Tests (`tests/integration/test_containment_concurrency.py`)**:
   - 20 concurrent triggers for the same alert producing exactly 1 containment action.
   - Simultaneous rollback attempts.
4. **Retention Tests (`tests/unit/test_retention_worker.py`)**:
   - Batch pruning deleting only rows older than specified TTLs.
   - Non-blocking execution.
5. **Full Regression Guard**: All 548 existing repository tests must pass with zero regressions.

---

## 25. Staging Strategy (AC24 Parity)

- Turnkey staging environment [`docker-compose.staging.yml`](file:///e:/AI-Cyber-Security-Suite/docker-compose.staging.yml) is reused.
- AC24 will continue to be reported truthfully as **NOT VERIFIED — Docker/PostgreSQL/Redis unavailable** in the local Windows environment until live containers are executed.

---

## 26. Acceptance Criteria

- [ ] **AC-5F-01**: Allowlisted indicators can NEVER be automatically blacklisted (`threat_intel_service.is_whitelisted == True` immediately aborts containment).
- [ ] **AC-5F-02**: Automated containment is disabled by default; triggers only when `auto_containment_enabled == True` for the owning tenant.
- [ ] **AC-5F-03**: Duplicate alert containment triggers produce exactly one durable action and playbook run via database uniqueness.
- [ ] **AC-5F-04**: Containment rollback is idempotent and provenance-safe, removing only entries created by the specific action.
- [ ] **AC-5F-05**: Target quarantine executes if and only if $\ge 3$ distinct active high-severity alerts occur within 10 minutes for the target.
- [ ] **AC-5F-06**: All containment operations are recorded in `soc_containment_actions` and emit immutable `AuditEvent` records.
- [ ] **AC-5F-07**: Containment lifecycle events (`containment_applied`, `containment_reverted`) broadcast over Phase 5E SSE streams.
- [ ] **AC-5F-08**: Containment notifications reuse Phase 5D transactional outbox and HMAC-SHA256 signing.
- [ ] **AC-5F-09**: Retention worker prunes `soc_event_stream` rows older than 7 days in bounded batches of 500.
- [ ] **AC-5F-10**: Retention worker prunes completed `notification_outbox` rows older than 30 days.
- [ ] **AC-5F-11**: Full regression suite remains 100% green (548+ tests passing, 0 failures, 0 errors).

---

## 27. Implementation File Scope

### Files to CREATE:
1. `backend/schemas/containment.py` — Pydantic schemas for containment requests, responses, and playbook models.
2. `backend/services/containment_service.py` — Core containment engine, Rule 0 fence, and playbook runner.
3. `backend/services/retention_worker.py` — Background bounded-batch retention pruning task.
4. `backend/api/routers/containment.py` — REST endpoints for containment actions and playbook history.
5. `migrations/versions/b2c3d4e5f6a7_sprint5_phase5f_soc_containment.py` — Schema migration for `soc_containment_actions`, `soc_playbook_runs`, and `soc_dynamic_blacklist`.
6. `tests/unit/test_containment_service.py` — Unit tests for containment logic and allowlist fencing.
7. `tests/unit/test_retention_worker.py` — Unit tests for retention pruning.
8. `tests/integration/test_containment_api.py` — API integration and tenant isolation tests.
9. `tests/integration/test_containment_concurrency.py` — Concurrency and race-condition tests.

### Files to MODIFY (Post-Authorization Only):
1. `backend/main.py` — Mount `containment.router` under `/v1`; manage `RetentionWorker` in lifespan.
2. `backend/database/models.py` — Declare `SOCContainmentAction`, `SOCPlaybookRun`, and `SOCDynamicBlacklist` models.
3. `backend/services/alert_service.py` — Invoke `containment_service.evaluate_alert_containment()` post-commit on qualifying alerts.

---

## 28. Protected Files & Invariants

The following 8 infrastructure files MUST NEVER be modified:
1. `backend/core/security_network.py`
2. `backend/services/monitoring_probe.py`
3. `backend/services/monitoring_worker.py`
4. `backend/services/scheduler_service.py`
5. `backend/services/threat_intel.py`
6. `backend/services/intel_enrichment.py`
7. `backend/schemas/soc.py`
8. `ml/**`

---

## 29. Rollback Plan

1. **Feature Flag**: Set `ENABLE_AUTO_CONTAINMENT=false` in environment variables to immediately deactivate all automated containment.
2. **Database Rollback**: Alembic migration `b2c3d4e5f6a7` provides a deterministic `downgrade()` function dropping containment tables cleanly.
3. **Core Isolation**: Rolling back Phase 5F leaves alert triage (5C), webhook egress (5D), and SSE streaming (5E) 100% operational.

---

## 30. Open Decisions & Approval Gate

1. **Containment Policy Granularity**: Should policy configuration live inside the existing `notification_preferences` table or in a dedicated `soc_containment_policies` table?
   - *Recommendation*: Introduce dedicated `soc_containment_policies` table to keep notification channels decoupled from security action authorization.
2. **Blacklist TTL Default**: Should automated blacklist entries expire after 24 hours or 7 days?
   - *Recommendation*: Default to 24 hours (`DEFAULT_BLACKLIST_TTL_SECONDS = 86400`) with option for analyst extension.

---

STATUS: AWAITING HUMAN APPROVAL — NO IMPLEMENTATION AUTHORIZED
