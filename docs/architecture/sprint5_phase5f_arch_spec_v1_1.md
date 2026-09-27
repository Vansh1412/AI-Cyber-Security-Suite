# SPRINT 5 — PHASE 5F ARCHITECTURE & SECURITY SPECIFICATION v1.1
## Automated Threat Containment, Declarative SOAR-Lite Playbooks & Lifecycle Retention

### Document: `docs/architecture/sprint5_phase5f_arch_spec_v1_1.md`
### Status: ARCHITECTURAL SPECIFICATION v1.1 — FINAL HARDENED — READ-ONLY — NO IMPLEMENTATION AUTHORIZED
### Authoritative Baseline: Commit `868f299145d1e2592c5ffacad8ea7d2c4678602f` (CI Run `35126256147`, GREEN)

---

> [!IMPORTANT]
> **READ-ONLY ARCHITECTURE SPECIFICATION (v1.1)**
> - Baseline Commit: `868f299145d1e2592c5ffacad8ea7d2c4678602f` (`feat(soc): implement sprint 5 phase 5e real-time alert streaming`).
> - Sprints 5A through 5E are 100% verified, committed, pushed, and passing all CI checks (548 passed, 6 skipped, 0 failures, 0 errors).
> - All 8 protected infrastructure components (`backend/core/security_network.py`, `backend/services/monitoring_probe.py`, `backend/services/monitoring_worker.py`, `backend/services/scheduler_service.py`, `backend/services/threat_intel.py`, `backend/services/intel_enrichment.py`, `backend/schemas/soc.py`, `ml/**`) remain untouched.
> - The 5 pre-existing working-tree files (`src/data/clean.py`, `src/data/inspect.py`, `src/data/merge.py`, `tests/integration/test_analytics_api.py`, `tests/unit/test_intel_enrichment.py`) remain untouched and unstaged.
> - AC24 (PostgreSQL 16 + Redis 7 distributed staging) remains **NOT VERIFIED — Docker/PostgreSQL/Redis unavailable** in the local Windows environment.
> - NO source code, migrations, tests, or configurations are modified during this architecture gate.
> - Implementation authorization is strictly reserved for subsequent explicit human approval.

---

# Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Baseline & Verified State](#2-baseline--verified-state)
3. [Authoritative Phase 5F Scope](#3-authoritative-phase-5f-scope)
4. [Explicit Non-Goals](#4-explicit-non-goals)
5. [Architecture Overview & Event Flow](#5-architecture-overview--event-flow)
6. [Component Responsibilities](#6-component-responsibilities)
7. [Containment Policy Model (`soc_containment_policies`)](#7-containment-policy-model-soc_containment_policies)
8. [Playbook Model (Declarative Typed Action Sequences)](#8-playbook-model-declarative-typed-action-sequences)
9. [Action State Machines & Failure Semantics](#9-action-state-machines--failure-semantics)
10. [Playbook State Machine & Resumption Semantics](#10-playbook-state-machine--resumption-semantics)
11. [Exactly-Once / At-Least-Once Semantics Contract](#11-exactly-once--at-least-once-semantics-contract)
12. [Distributed Concurrency Control](#12-distributed-concurrency-control)
13. [Stale Worker Fencing](#13-stale-worker-fencing)
14. [Rule 0 — Allowlist Fencing Invariant](#14-rule-0--allowlist-fencing-invariant)
15. [Indicator Containment & Dynamic Blacklist](#15-indicator-containment--dynamic-blacklist)
16. [Target Quarantine Semantics](#16-target-quarantine-semantics)
17. [Incident Binding Integration](#17-incident-binding-integration)
18. [Provenance-Safe Rollback Engine](#18-provenance-safe-rollback-engine)
19. [Database Schema & Migrations](#19-database-schema--migrations)
20. [API Contracts](#20-api-contracts)
21. [Phase 5D Notification Integration](#21-phase-5d-notification-integration)
22. [Phase 5E Streaming Event Integration](#22-phase-5e-streaming-event-integration)
23. [Redis Architecture & Distributed Primitives](#23-redis-architecture--distributed-primitives)
24. [Retention Worker (`RetentionWorker`)](#24-retention-worker-retentionworker)
25. [PostgreSQL-Safe Bounded Batch Pruning](#25-postgresql-safe-bounded-batch-pruning)
26. [Failure Modes & Recovery Semantics](#26-failure-modes--recovery-semantics)
27. [Security Threat Model](#27-security-threat-model)
28. [Testing Strategy](#28-testing-strategy)
29. [Staging Strategy (AC24 Parity)](#29-staging-strategy-ac24-parity)
30. [Acceptance Criteria Matrix](#30-acceptance-criteria-matrix)
31. [Exact Implementation File Scope](#31-exact-implementation-file-scope)
32. [Protected Files & Invariants](#32-protected-files--invariants)
33. [Open Risks & Residual Risks](#33-open-risks--residual-risks)
34. [Architecture Verdict](#34-architecture-verdict)

---

## 1. Executive Summary

Sprint 5 Phase 5F delivers the final backend automation capstone for the AI-Cyber-Security-Suite SOC subsystem.

While Phases 5A through 5E built continuous target scheduling, autonomous SSRF-safe scanning, alert triage lifecycles, transactional outbox webhook egress, and real-time SSE event streaming, **the platform remains fundamentally reactive**. When an active zero-day phishing attack or high-confidence ransomware threat is detected, the suite alerts the user, but cannot take automated defensive action. Furthermore, append-only logs (`soc_event_stream` and `notification_outbox`) accumulate indefinitely without automated retention pruning.

Phase 5F delivers:
1. **Automated Threat Containment**: Safe, policy-governed automated blacklisting, cache purging, and target quarantine.
2. **Declarative SOAR-Lite Playbooks**: Type-safe, auditable execution sequences with zero arbitrary code execution.
3. **Rule 0 Allowlist Fencing**: An unbreakable security boundary preventing self-inflicted Denial of Service against legitimate domains.
4. **Idempotent, Provenance-Safe Rollback**: Precision undo mechanics that only revert actions taken by a specific containment execution.
5. **Durable Lifecycle Retention Worker**: Non-blocking, bounded batch pruning for event streams (7-day TTL), outbox jobs (30-day TTL), and containment history (90-day TTL) with zero table locking.

---

## 2. Baseline & Verified State

The Phase 5F specification builds upon the verified foundation of Sprints 5A through 5E:

| Phase | Baseline Commit | Key Architectural Properties Verified in Baseline |
|---|---|---|
| **Phase 5A** | `43225b6` | Target CRUD, SSRF pre-registration validation, quota (`MAX_TARGETS_PER_USER = 20`), `scheduler_state`. |
| **Phase 5B** | `3624207` | PostgreSQL advisory lock leader election, worker leases (`45s`), SSRF DNS-pinned probe, frozen 59-feature ML threat inference, triple-predicate atomic writeback fencing. |
| **Phase 5C** | `43d94a6` | Authoritative 4-state alert triage (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`), forbidden terminal flips (HTTP 400), recurrence on terminal states, operational target controls (`pause`, `resume`, `reactivate`, `check-now`), diagnostics, 24h telemetry. |
| **Phase 5D** | `c9765d5` | Transactional outbox table (`notification_outbox`), background `NotificationDispatcher`, SSRF DNS-pinned egress, AES-256-GCM secret encryption with `v1$` envelope, canonical HMAC-SHA256 signing with 300s replay tolerance, 5-failure atomic circuit breaker. |
| **Phase 5E** | `868f299` | Durable `soc_event_stream` with monotonic 64-bit `cursor_id`, W3C `Last-Event-ID` replay, single-use 30s stream tickets (`st_*`), query JWT prohibition, multi-pod Redis Pub/Sub with in-memory degraded mode, bounded client queues (100 items, 16KB payload), and AC24 staging harness (`docker-compose.staging.yml`). |

**Verification Baseline:**
- GitHub Actions Run ID: `35126256147`
- Test suite: 548 passed, 6 skipped, 0 failures, 0 errors.
- Status of AC24: **NOT VERIFIED — Docker/PostgreSQL/Redis unavailable** in the local Windows environment.

---

## 3. Authoritative Phase 5F Scope

### Included in Phase 5F:
1. **Automated Indicator Containment**: Inserting malicious URLs/domains into `soc_dynamic_blacklist` and purging Redis caches.
2. **Automated Target Quarantine**: Suspending active monitoring targets (`monitoring_targets.is_active = False`) under active attack storms.
3. **Automated Incident Binding**: Seamlessly attaching alerts to existing open incidents or creating new incidents via `IncidentService`.
4. **Declarative SOAR-Lite Playbooks**: Type-safe, deterministic typed action sequences without dynamic script interpretation.
5. **Durable Containment Action Persistence**: Tracking all containment actions in `soc_containment_actions`.
6. **Durable Playbook Run Persistence**: Auditable execution records in `soc_playbook_runs`.
7. **Idempotent Containment Execution**: Database-enforced uniqueness constraints preventing duplicate execution on repeated alert triggers.
8. **Provenance-Safe Rollback**: Reverting containment actions while preserving analyst-created rules and independent target states.
9. **Containment Audit Trail**: Immutable `AuditEvent` records for all containment decisions, allowlist blocks, and reverts.
10. **Phase 5E SOC Event Stream Integration**: Emitting real-time SSE frames (`playbook_triggered`, `containment_applied`, `containment_reverted`, `playbook_completed`, `playbook_failed`).
11. **Phase 5D Notification/Outbox Integration**: Enqueueing signed webhook deliveries and in-app notifications for containment actions.
12. **Lifecycle Retention Pruning Worker**: Non-blocking bounded-batch deletion for `soc_event_stream` (7 days), `notification_outbox` (30 days), and containment history (90 days).

---

## 4. Explicit Non-Goals

1. **Frontend UI Implementation**: All React 19 UI components (Alert Center, Playbook Drawer, Containment Console) belong strictly to Sprint 6.
2. **Arbitrary Code Execution**: Zero user-supplied scripts, regexes, Python snippets, shell commands, `eval()`, or `exec()`.
3. **External Infrastructure Mutation**: No direct integration with external firewalls, AWS Security Groups, Palo Alto, or Cloudflare WAF. Containment is restricted to internal detection surfaces (`soc_dynamic_blacklist`, `cache`, `monitoring_targets`, `incidents`).
4. **Bulk Triage & SIEM Export**: Bulk status updates, CEF export, Syslog export, and NDJSON streaming are deferred to a dedicated integration phase.
5. **Modifying Protected Files**: Core ML pipelines (`ml/**`), SSRF networking (`backend/core/security_network.py`), probe mechanics (`backend/services/monitoring_probe.py`), threat intel feeds (`backend/services/threat_intel.py`), scheduler state (`backend/services/scheduler_service.py`), and worker loops (`backend/services/monitoring_worker.py`) remain strictly read-only.
6. **Modifying Audit Log Retention**: `AuditEvent` is an immutable compliance log and is explicitly excluded from Phase 5F pruning.

---

## 5. Architecture Overview & Event Flow

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
│  1. Check Policy Gate: `soc_containment_policies` (Tenant-scoped)                                │
│     `auto_containment_enabled == True` AND `severity >= containment_min_severity`?               │
│     NO  ──▶ Log Policy Bypass Audit Event ──▶ TERMINATE                                          │
│     YES ──▶ Continue                                                                             │
│                                                                                                  │
│  2. Rule 0 Allowlist Fence: `ThreatIntelAdapter.is_whitelisted(indicator)`                       │
│     Evaluated PER ACTION TYPE:                                                                   │
│     - BLACKLIST_INDICATOR: If allowlisted ──▶ BLOCKED_BY_ALLOWLIST (Skip action)                 │
│     - QUARANTINE_TARGET:   If allowlisted ──▶ BLOCKED_BY_ALLOWLIST (Skip action)                 │
│     - Observability actions: (CREATE_INCIDENT, EMIT_SOC_EVENT, SEND_NOTIFICATION) continue       │
│                                                                                                  │
│  3. Acquire Distributed Execution Lock:                                                          │
│     Redis: `soc:playbook:lock:{tenant_id}:{target_id}` (Token-bound, 30s TTL)                    │
│     Fallback: DB transaction with row-level locks on `soc_playbook_runs`                         │
│                                                                                                  │
│  4. Check Idempotency Key in Database: `soc_playbook_runs` (Unique Constraint)                   │
│                                                                                                  │
│  5. Execute Declarative Typed Action Sequence:                                                   │
│     ┌────────────────────────┬────────────────────────┬────────────────────────┐                 │
│     │  BLACKLIST_INDICATOR   │   QUARANTINE_TARGET    │    CREATE_INCIDENT     │                 │
│     │  Insert into           │   Update status to     │   Link alert to        │                 │
│     │  `soc_dynamic_blacklist`│  `is_active = False`   │   `IncidentService`    │                 │
│     └───────────┬────────────┴───────────┬────────────┴───────────┬────────────┘                 │
│                 │                        │                        │                              │
│                 ▼                        ▼                        ▼                              │
│  6. Invalidate Cache: `cache_service.invalidate(indicator)` (Non-blocking, Redis-safe)           │
│  7. Persist Actions & Run: Commit `soc_containment_actions` and `soc_playbook_runs`              │
│  8. Emit Phase 5E Event: `event_broadcaster.publish_event_nowait(containment_applied)`           │
│  9. Enqueue Phase 5D Outbox: `notification_service.create_in_app_and_outbox_for_alert()`         │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Component Responsibilities

1. **`ContainmentService` (`backend/services/containment_service.py`)**:
   - Central orchestrator for evaluating alerts against containment policies.
   - Enforces Rule 0 allowlist fencing via `ThreatIntelAdapter`.
   - Dispatches declarative typed action sequences via `PlaybookRunner`.
   - Manages provenance-safe rollback logic and idempotency verification.
2. **`ThreatIntelAdapter` (Internal Adapter in `ContainmentService`)**:
   - Read-only adapter importing `TRUSTED_DOMAINS` and `_is_legitimate_domain` from `backend.services.threat_intel`.
   - Evaluates whether an indicator or target domain matches the trusted allowlist without modifying the protected file.
   - Implements fail-closed semantics: any exception or parsing failure returns `True` (treated as allowlisted / safe from blacklisting).
3. **`PlaybookRunner` (Internal Engine in `ContainmentService`)**:
   - Executes ordered declarative typed action sequences.
   - Verifies fencing tokens before each mutation to prevent stale worker execution.
   - Updates action and run status records within database transactions.
4. **`RetentionWorker` (`backend/services/retention_worker.py`)**:
   - Background periodic worker executing once every hour.
   - Uses PostgreSQL-safe bounded batch deletion (500 rows per batch) with 0.5s pause.
   - Prunes `soc_event_stream` (7 days), `notification_outbox` (30 days), and containment history (90 days).
   - Manages distributed leader election via Redis or PostgreSQL advisory locks.
5. **`ContainmentRouter` (`backend/api/routers/containment.py`)**:
   - REST endpoints for manual containment, listing actions/runs, action details, rollback, and policy management.
   - Enforces strict tenant scoping and admin RBAC.

---

## 7. Containment Policy Model (`soc_containment_policies`)

### 1. Dedicated Policy Table
Containment authorization is decoupled from notification preferences and stored in a dedicated `soc_containment_policies` table.

```sql
CREATE TABLE soc_containment_policies (
    id                             SERIAL PRIMARY KEY,
    tenant_id                      INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    auto_containment_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    auto_blacklist_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    auto_quarantine_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    auto_incident_binding_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    containment_min_severity       VARCHAR(16) NOT NULL DEFAULT 'CRITICAL',
    blacklist_ttl_seconds          INTEGER NOT NULL DEFAULT 86400,
    policy_version                 INTEGER NOT NULL DEFAULT 1,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by                     INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_min_severity CHECK (containment_min_severity IN ('CRITICAL', 'HIGH')),
    CONSTRAINT chk_blacklist_ttl CHECK (blacklist_ttl_seconds >= 60 AND blacklist_ttl_seconds <= 2592000)
);

CREATE INDEX idx_containment_policies_tenant ON soc_containment_policies (tenant_id);
```

### 2. Default Safe Mode Invariant
- **All automated containment flags default to `FALSE`**.
- Merely deploying Phase 5F does not enable automated mitigation for any tenant.
- Tenants or administrators must explicitly set `auto_containment_enabled = True` and relevant sub-flags.

### 3. Default Policy Synthesis (Missing Row Handling)
If no policy row exists for a tenant:
- The system synthesizes an in-memory default policy where all `auto_*` flags are `False`, `containment_min_severity = 'CRITICAL'`, and `blacklist_ttl_seconds = 86400`.
- No automated actions are executed; an audit event is logged on containment evaluation.

### 4. Optimistic Concurrency Control
Policy updates use `policy_version`:
- Updates submit `current_version`. If the database version does not match, HTTP 409 Conflict is returned.
- On successful update, `policy_version` is incremented, and an immutable `AuditEvent` (`CONTAINMENT_POLICY_UPDATED`) is recorded.

---

## 8. Playbook Model (Declarative Typed Action Sequences)

> [!IMPORTANT]
> **NO ARBITRARY CODE EXECUTION**
> The playbook engine strictly rejects DAG graph terminology, dynamic scripting, Python `eval()`, `exec()`, or shell execution. All playbooks are deterministic sequences of predefined, strongly-typed action classes.

### Predefined Action Types:
1. `BLACKLIST_INDICATOR`: Inserts indicator into `soc_dynamic_blacklist` with TTL.
2. `INVALIDATE_CACHE`: Purges matching URL/domain from Redis scan prediction cache.
3. `QUARANTINE_TARGET`: Suspends monitoring target (`is_active = False`) and records diagnostic reason.
4. `CREATE_INCIDENT`: Attaches alert to existing open incident or creates a new incident via `IncidentService`.
5. `EMIT_SOC_EVENT`: Dispatches real-time SSE event via `EventBroadcaster`.
6. `SEND_NOTIFICATION`: Enqueues outbox webhook and in-app notification via `NotificationService`.

### Predefined Playbook Sequences:
1. `CRITICAL_THREAT_AUTO_CONTAINMENT_V1`:
   - Sequence: `BLACKLIST_INDICATOR` -> `INVALIDATE_CACHE` -> `CREATE_INCIDENT` -> `EMIT_SOC_EVENT` -> `SEND_NOTIFICATION`.
   - Trigger: Qualifying `CRITICAL` alert with `auto_blacklist_enabled == True`.
2. `REPEATED_TARGET_COMPROMISE_QUARANTINE_V1`:
   - Sequence: `QUARANTINE_TARGET` -> `CREATE_INCIDENT` -> `EMIT_SOC_EVENT` -> `SEND_NOTIFICATION`.
   - Trigger: Monitoring target reaching $\ge 3$ active high-severity alerts in 10 minutes with `auto_quarantine_enabled == True`.
3. `MANUAL_CONTAINMENT_V1`:
   - Sequence: Single specified action invoked by analyst via `POST /v1/soc/actions/contain`.

---

## 9. Action State Machines & Failure Semantics

### 1. Action State Transitions
```
                ┌───────────────────────────────────┐
                │              PENDING              │
                └─┬───────────────┬───────────────┬─┘
                  │               │               │
        Rule 0 Hit│      Execution│      Execution│
                  ▼        Success▼        Failure▼
┌───────────────────────┐ ┌───────────────┐ ┌───────────────┐
│ BLOCKED_BY_ALLOWLIST  │ │   EXECUTED    │ │    FAILED     │
└───────────────────────┘ └───────┬───────┘ └───────────────┘
                                  │
                          Reverted│
                                  ▼
                          ┌───────────────┐
                          │   REVERTED    │
                          └───────────────┘
```

- **`PENDING`**: Action record initialized in database before execution.
- **`EXECUTED`**: Action successfully committed to database / executed.
- **`FAILED`**: Action raised an exception during execution; error details persisted.
- **`BLOCKED_BY_ALLOWLIST`**: Rule 0 prevented execution; no mutation occurred.
- **`SKIPPED`**: Action pre-conditions not met (e.g. target already quarantined).
- **`REVERTED`**: Action was successfully undone via rollback API.

### 2. Action Failure & Partial Playbook Semantics
What happens when Action 1 succeeds, Action 2 succeeds, Action 3 fails, and Action 4 is never attempted?
1. **Durable Persistence**:
   - Action 1 and Action 2 remain committed in `soc_containment_actions` with status `EXECUTED`.
   - Action 3 is marked as `FAILED` with `error_message` and `failed_at`.
   - Action 4 remains `PENDING` (or is marked `SKIPPED`).
   - The playbook run in `soc_playbook_runs` transitions to `FAILED`.
2. **No Blind Rollback**:
   - Prior successful actions (e.g. `BLACKLIST_INDICATOR`) are **NOT** automatically rolled back. In a security context, leaving an active phishing domain blacklisted is significantly safer than unblocking it because a notification webhook failed.
3. **Analyst Alerting**:
   - A high-severity `AuditEvent` (`PLAYBOOK_EXECUTION_FAILED`) is logged, detailing the failed step and preserved containment state.
4. **Resumption**:
   - An analyst can trigger a retry from the failed step via the management API, or issue a formal rollback.

---

## 10. Playbook State Machine & Resumption Semantics

```
       ┌───────────────┐
       │    PENDING    │
       └───────┬───────┘
               │ Worker acquires run
               ▼
       ┌───────────────┐
       │    RUNNING    │
       └─┬───────────┬─┘
         │           │
All steps│   Any step│
  succeed│      fails│
         ▼           ▼
┌─────────────┐ ┌─────────────┐
│  COMPLETED  │ │   FAILED    │
└──────┬──────┘ └─────────────┘
       │ Revert API called
       ├──────────────────────────┐
       │ All actions reverted     │ Some actions reverted
       ▼                          ▼
┌─────────────┐            ┌────────────────────┐
│  REVERTED   │            │ PARTIALLY_REVERTED │
└─────────────┘            └────────────────────┘
```

- **`PENDING`**: Run registered, waiting for worker acquisition.
- **`RUNNING`**: Worker actively executing action sequence.
- **`COMPLETED`**: All actions completed (`EXECUTED`, `SKIPPED`, or `BLOCKED_BY_ALLOWLIST`).
- **`FAILED`**: One or more critical actions raised an unhandled exception.
- **`PARTIALLY_REVERTED`**: Some actions rolled back, but others failed or are irreversible.
- **`REVERTED`**: All reversible actions successfully rolled back.

---

## 11. Exactly-Once / At-Least-Once Semantics Contract

The architecture distinguishes **Durable Action Identity** from external side effects:

- **Durable Action Identity**: Exactly-once identity is guaranteed at the database layer via unique constraints on `(tenant_id, idempotency_key)`.
- **Non-Transactional External Side Effects**: Network operations (Redis cache invalidation, SSE broadcasting, webhook delivery) are **NOT** claimed to be exactly-once. They are designed to be idempotent or safely retryable.

### Action Execution Contract Matrix:

| Action Type | Transactional? | Idempotent? | Retryable? | Compensatable? | Recovery Semantics |
|---|---|---|---|---|---|
| `BLACKLIST_INDICATOR` | **Yes (DB)** | **Yes** | **Yes** | **Yes** (`soc_dynamic_blacklist.is_active = False`) | If crash occurs before DB commit, no row exists; if crash occurs after, unique constraint prevents duplicate. |
| `INVALIDATE_CACHE` | **No (Redis)** | **Yes** | **Yes** | **No** (Cache miss repopulates naturally) | Best-effort. If Redis fails, log warning. Does not fail DB transaction. |
| `QUARANTINE_TARGET` | **Yes (DB)** | **Yes** | **Yes** | **Yes** (Provenance-safe reactivation) | Atomic DB update on `monitoring_targets`. Idempotent if already inactive. |
| `CREATE_INCIDENT` | **Yes (DB)** | **Yes** | **Yes** | **Yes** (Detach alert or close incident) | Reuses open incident or creates one; unique constraint prevents duplicate binding. |
| `EMIT_SOC_EVENT` | **Yes (DB write) / No (SSE publish)** | **Yes** | **Yes** | **No** (Compensatory `containment_reverted` event) | DB row in `soc_event_stream` is transactional. SSE broadcast is at-most-once for live clients, at-least-once via `Last-Event-ID` replay. |
| `SEND_NOTIFICATION` | **Yes (DB outbox) / No (HTTP webhook)** | **Yes** | **Yes** | **No** (Compensatory notification) | Outbox row is transactional. Webhook delivery via `NotificationDispatcher` is at-least-once with HMAC-SHA256 signature and replay tolerance. |

---

## 12. Distributed Concurrency Control

### 1. Global Per-Tenant Concurrency Limit
- **Maximum 5 concurrent playbook executions per tenant across all pods**.
- Replaces process-local `asyncio.Semaphore(5)` with a distributed coordination model.

### 2. Redis-Available Mode (Distributed Token Semaphore)
- **Key**: `soc:playbook:tenant_concurrency:{tenant_id}`.
- Implemented via a Redis Hash or Sorted Set tracking active execution tokens with timestamps.
- TTL: 60 seconds (heartbeated during execution).
- Token acquisition via Lua script: atomically checks active count $< 5$. If $< 5$, adds `token` and returns OK; if $\ge 5$, returns REJECTED.
- Release via Lua script: atomically removes `token`.
- Crash recovery: Active tokens older than 60s are pruned during acquisition.

### 3. Redis-Unavailable Mode (Authoritative PostgreSQL Fallback)
When Redis is offline or unreachable:
- Concurrency is enforced authoritatively in PostgreSQL via transactional row counting with table/row-level synchronization:
  ```sql
  SELECT count(*) 
  FROM soc_playbook_runs 
  WHERE tenant_id = :tenant_id AND status = 'RUNNING'
  FOR UPDATE;
  ```
- If active count $\ge 5$, the new run is rejected with HTTP 429 / enqueued up to a bounded backlog.
- **Database uniqueness prevents duplicate execution of the same alert, while this count query limits total concurrent runs across distinct alerts for the tenant.**

### 4. SQLite CI Mode (Testing Parity)
- In SQLite environments (local tests, CI):
  - Emulated via `asyncio.Semaphore(5)` bound to the active loop and a threading lock.
  - Explicitly documented as process-local test emulation, not production distributed coordination.

---

## 13. Stale Worker Fencing

### The Stale Worker Problem:
Worker A starts a playbook run, experiences a network partition / GC pause, and loses its Redis lock. Worker B acquires the lock and begins executing. Worker A resumes and attempts to perform destructive mutations.

### Fencing Token Protocol:
1. Every playbook run has a monotonically increasing integer `fencing_token` in `soc_playbook_runs`.
2. When Worker B acquires or reclaims a run, it increments `fencing_token` atomically:
   ```sql
   UPDATE soc_playbook_runs
   SET fencing_token = fencing_token + 1, updated_at = NOW()
   WHERE id = :run_id
   RETURNING fencing_token;
   ```
3. Before Worker A executes any destructive mutation (`UPDATE monitoring_targets`, `INSERT INTO soc_dynamic_blacklist`), it executes an authoritative verification inside the mutation transaction:
   ```sql
   SELECT fencing_token, status 
   FROM soc_playbook_runs 
   WHERE id = :run_id 
   FOR UPDATE;
   ```
4. If `fencing_token != worker_assigned_token` or `status != 'RUNNING'`, Worker A **immediately aborts** without applying mutations, logs an audit warning (`STALE_WORKER_FENCED`), and terminates.

---

## 14. Rule 0 — Allowlist Fencing Invariant

> [!CAUTION]
> **HARD SECURITY INVARIANT — ZERO BYPASS PERMITTED**
> Under no circumstances may an automated containment action blacklist or disrupt an indicator matching the trusted allowlist.

### 1. Per-Action-Type Enforcement Matrix:
Rule 0 is enforced granularly per action type:

| Action Type | Rule 0 Behavior | Status on Allowlist Match | Mutation Applied? |
|---|---|---|---|
| `BLACKLIST_INDICATOR` | **HARD BLOCK** | `BLOCKED_BY_ALLOWLIST` | **NO**. Row is not inserted into `soc_dynamic_blacklist`. |
| `INVALIDATE_CACHE` | **ALLOWED** | `EXECUTED` | **YES**. Clearing cached scan results for an allowlisted domain is safe and forces fresh evaluation. |
| `QUARANTINE_TARGET` | **HARD BLOCK** | `BLOCKED_BY_ALLOWLIST` | **NO**. Target `is_active` remains unchanged; protects core infrastructure. |
| `CREATE_INCIDENT` | **ALLOWED** | `EXECUTED` | **YES**. Incident creation is purely observational; does not disrupt traffic. |
| `EMIT_SOC_EVENT` | **ALLOWED** | `EXECUTED` | **YES**. Event streaming provides visibility into the threat detection. |
| `SEND_NOTIFICATION` | **ALLOWED** | `EXECUTED` | **YES**. Alerts administrators that an allowlisted domain was flagged. |

### 2. Implementation via Protected File Adapter
- `backend/services/threat_intel.py` is protected and remains read-only.
- `ContainmentService` utilizes `ThreatIntelAdapter`:
  ```python
  from backend.services.threat_intel import TRUSTED_DOMAINS, _is_legitimate_domain

  class ThreatIntelAdapter:
      @staticmethod
      def is_whitelisted(indicator: str) -> bool:
          try:
              parsed = urlparse(indicator)
              hostname = (parsed.hostname or indicator).lower().strip()
              if not hostname:
                  return True  # Fail-closed
              for trusted in TRUSTED_DOMAINS:
                  if _is_legitimate_domain(hostname, trusted):
                      return True
              return False
          except Exception:
              # Fail-closed: treat parsing errors as whitelisted to prevent DoS
              return True
  ```

### 3. Fail-Closed Semantics:
If allowlist verification fails due to an exception or network error:
- The system **fails closed** for blacklisting (`is_whitelisted` returns `True`).
- `BLACKLIST_INDICATOR` is aborted.
- Action status is set to `BLOCKED_BY_ALLOWLIST`.
- Audit event `CONTAINMENT_ALLOWLIST_LOOKUP_FAILED` is logged.

---

## 15. Indicator Containment & Dynamic Blacklist

### 1. Schema: `soc_dynamic_blacklist`
```sql
CREATE TABLE soc_dynamic_blacklist (
    id                    SERIAL PRIMARY KEY,
    indicator_type        VARCHAR(32) NOT NULL,            -- 'url', 'domain', 'ip'
    indicator_value       VARCHAR(512) NOT NULL,
    tenant_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    containment_action_id INTEGER NULL REFERENCES soc_containment_actions(id) ON DELETE SET NULL,
    reason                VARCHAR(255) NOT NULL,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at            TIMESTAMPTZ NOT NULL,            -- Mandatory TTL
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_indicator_type CHECK (indicator_type IN ('url', 'domain', 'ip'))
);

CREATE INDEX idx_dynamic_blacklist_indicator ON soc_dynamic_blacklist (indicator_value, is_active);
CREATE INDEX idx_dynamic_blacklist_tenant ON soc_dynamic_blacklist (tenant_id, is_active);
CREATE INDEX idx_dynamic_blacklist_expires ON soc_dynamic_blacklist (expires_at) WHERE is_active = TRUE;
```

### 2. Automated Blacklist TTL (24 Hours)
- Default TTL: **24 hours (86,400 seconds)**: `expires_at = NOW() + INTERVAL '86400 seconds'`.
- **Repeated Containment Before Expiry**: If an active entry already exists for the same indicator and tenant:
  - The existing entry's `expires_at` is extended to `NOW() + 86400 seconds`.
  - Action is marked `EXECUTED` with details noting the TTL extension.
- **Manual Analyst Extension**: An analyst may manually extend an entry or set `containment_action_id = NULL`. Once disassociated, automated rollback will not revert the analyst's rule.
- **Expiration Behavior**: Expired entries are soft-deactivated (`is_active = False`) by the `RetentionWorker` or during lookup evaluation (`WHERE is_active = TRUE AND expires_at > NOW()`).

---

## 16. Target Quarantine Semantics

### 1. Exact Threshold Criteria
A monitoring target is automatically quarantined if and only if ALL of the following criteria are satisfied:
1. `auto_quarantine_enabled == True` in `soc_containment_policies` for the owning tenant.
2. The target currently has **$\ge 3$ distinct active alerts** satisfying:
   - **Distinctness**: Distinct database primary keys (`alert.id`).
   - **Target Match**: `Alert.indicator_value` or `Alert.fingerprint` links to `target.url` or `target.normalized_domain`.
   - **Tenant Ownership**: `Alert.user_id == target.user_id`.
   - **Rolling Window**: `Alert.created_at >= NOW() - INTERVAL '10 minutes'` (inclusive).
   - **Severity**: `Alert.severity IN ('CRITICAL', 'HIGH')`.
   - **Active State Machine Status**: Strictly `Alert.status IN ('OPEN', 'ACKNOWLEDGED')`. Alerts in `RESOLVED` or `DISMISSED` states **DO NOT COUNT**.
3. Target is currently active (`monitoring_targets.is_active == True`).

### 2. Quarantine Execution:
1. Atomically sets:
   - `monitoring_targets.is_active = False`
   - `monitoring_targets.last_error_message = 'Auto-quarantined: 3+ high-severity alerts within 10m'`
2. Records action in `soc_containment_actions` with `target_identifier = target.target_uuid` and `rollback_metadata` storing `{ "previous_is_active": true, "target_id": target.id }`.
3. Emits `containment_applied` SSE event and enqueues notification.

### 3. Provenance-Safe Rollback Semantics:
> [!CAUTION]
> **NO BLIND TARGET REACTIVATION**
> Rollback of `QUARANTINE_TARGET` MUST NOT blindly set `is_active = True`.

Rollback reactivates the target **only if**:
1. The target was suspended by this exact action (`action.action_uuid`).
2. The target has not been manually paused, deleted, or independently suspended by an analyst.
3. If an analyst subsequently modified the target, rollback aborts with HTTP 409 Conflict, preserving the analyst's override.

---

## 17. Incident Binding Integration

Containment reuses the existing `IncidentService` without creating competing models:
1. When `CREATE_INCIDENT` executes:
   - Queries for an existing open incident for the target: `incident_service.get_open_incident_for_target(session, target_id, tenant_id)`.
   - **Existing Open Incident**: Attaches the triggering alert via `incident_service.attach_alerts_to_incident()`. If the alert has higher severity, escalates incident severity monotonically via `_higher_severity()`.
   - **No Open Incident**: Creates a new incident via `incident_service.create_incident()`.
2. All operations are strictly tenant-isolated (`user_id == current_user.id`).
3. Rollback: Detaches the alert or appends a rollback diagnostic note to the incident timeline; does not delete the incident.

---

## 18. Provenance-Safe Rollback Engine

### Rollback Contract (`POST /v1/soc/actions/{action_uuid}/revert`):
1. **Tenant Isolation**: Requester must own the action (`tenant_id == current_user.id`) or have `role == 'admin'`. Foreign UUIDs return HTTP 404 (anti-enumeration).
2. **Status Check**: Action must be in status `EXECUTED`. Reverting `REVERTED` or `FAILED` returns HTTP 400.
3. **Action-Specific Rollback Execution**:
   - `BLACKLIST_INDICATOR`:
     - Queries `soc_dynamic_blacklist` for rows where `containment_action_id == action.id`.
     - Updates `is_active = False` for matching rows.
     - **NEVER** touches blacklist entries created by analysts or other actions.
   - `QUARANTINE_TARGET`:
     - Verifies provenance; reactivates target only if suspended by this action.
   - `INVALIDATE_CACHE`:
     - No-op (cannot un-purge cache).
   - `CREATE_INCIDENT`:
     - Appends rollback note to incident timeline.
   - `SEND_NOTIFICATION` / `EMIT_SOC_EVENT`:
     - Irreversible. Enqueues a compensatory `containment_reverted` event and notification.
4. **State Transition**: Action transitions to `REVERTED` with `reverted_at` and `reverted_by_user_id`.
5. **Audit Event**: Logs `CONTAINMENT_ACTION_REVERTED`.

---

## 19. Database Schema & Migrations

### Migration Revision: `c1d2e3f4a5b6_sprint5_phase5f_soc_containment.py`
Creates:
1. `soc_containment_policies`
2. `soc_playbook_runs`
3. `soc_containment_actions`
4. `soc_dynamic_blacklist`

### Schema Definitions:

```sql
-- 1. Policies
-- (Defined in Section 7)

-- 2. Playbook Runs
CREATE TABLE soc_playbook_runs (
    id                 SERIAL PRIMARY KEY,
    run_uuid           VARCHAR(36) NOT NULL UNIQUE,
    playbook_name      VARCHAR(128) NOT NULL,
    playbook_version   VARCHAR(32) NOT NULL DEFAULT '1.0',
    tenant_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    trigger_event      VARCHAR(64) NOT NULL,
    alert_id           INTEGER NULL REFERENCES alerts(id) ON DELETE SET NULL,
    target_id          INTEGER NULL REFERENCES monitoring_targets(id) ON DELETE SET NULL,
    status             VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    fencing_token      INTEGER NOT NULL DEFAULT 1,
    action_count       INTEGER NOT NULL DEFAULT 0,
    idempotency_key    VARCHAR(255) NOT NULL UNIQUE,
    error_message      TEXT NULL,
    started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at       TIMESTAMPTZ NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_run_status CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIALLY_REVERTED', 'REVERTED'))
);

CREATE INDEX idx_playbook_runs_tenant_status ON soc_playbook_runs (tenant_id, status);
CREATE INDEX idx_playbook_runs_alert ON soc_playbook_runs (alert_id);

-- 3. Containment Actions
CREATE TABLE soc_containment_actions (
    id                     SERIAL PRIMARY KEY,
    action_uuid            VARCHAR(36) NOT NULL UNIQUE,
    run_id                 INTEGER NULL REFERENCES soc_playbook_runs(id) ON DELETE SET NULL,
    tenant_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    alert_id               INTEGER NULL REFERENCES alerts(id) ON DELETE SET NULL,
    incident_id            INTEGER NULL REFERENCES incidents(id) ON DELETE SET NULL,
    target_identifier      VARCHAR(512) NOT NULL,
    action_type            VARCHAR(64) NOT NULL,
    status                 VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    actor_user_id          INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    trigger_source         VARCHAR(64) NOT NULL,
    action_idempotency_key VARCHAR(255) NOT NULL UNIQUE,
    rollback_metadata      JSON NULL,
    result_metadata        JSON NULL,
    error_message          TEXT NULL,
    expires_at             TIMESTAMPTZ NULL,
    reverted_at            TIMESTAMPTZ NULL,
    reverted_by_user_id    INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at             TIMESTAMPTZ NULL,
    completed_at           TIMESTAMPTZ NULL,
    CONSTRAINT chk_action_status CHECK (status IN ('PENDING', 'EXECUTED', 'FAILED', 'BLOCKED_BY_ALLOWLIST', 'SKIPPED', 'REVERTED')),
    CONSTRAINT chk_action_type CHECK (action_type IN ('BLACKLIST_INDICATOR', 'INVALIDATE_CACHE', 'QUARANTINE_TARGET', 'CREATE_INCIDENT', 'EMIT_SOC_EVENT', 'SEND_NOTIFICATION'))
);

CREATE INDEX idx_containment_actions_tenant_status ON soc_containment_actions (tenant_id, status);
CREATE INDEX idx_containment_actions_target ON soc_containment_actions (target_identifier);

-- 4. Dynamic Blacklist
-- (Defined in Section 15)
```

### Dialect Safety:
All JSON columns use `JSON().with_variant(Text, "sqlite")` for seamless testing on SQLite in-memory and production PostgreSQL 16.

### Deletion Behavior Rationale:
- `tenant_id REFERENCES users(id) ON DELETE RESTRICT`: Prevents deletion of user accounts while containment audit records exist, preserving security compliance trails.
- `alert_id` / `incident_id` `ON DELETE SET NULL`: Preserves containment history even if an alert or incident is pruned or purged.

---

## 20. API Contracts

All endpoints enforce `Authorization: Bearer <jwt>` and strict tenant scoping (`tenant_id == current_user.id` or `current_user.role == 'admin'`).

### 1. `POST /v1/soc/actions/contain`
- **Description**: Manually trigger containment action on an indicator or target.
- **Request Body**:
  ```json
  {
    "action_type": "BLACKLIST_INDICATOR",
    "target_identifier": "https://malicious-phish.xyz",
    "alert_id": 142,
    "reason": "Analyst manual containment"
  }
  ```
- **Response (HTTP 201)**:
  ```json
  {
    "action_uuid": "act_a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "action_type": "BLACKLIST_INDICATOR",
    "target_identifier": "https://malicious-phish.xyz",
    "status": "EXECUTED",
    "created_at": "2026-09-20T22:30:00Z"
  }
  ```
- **Rate Limit**: 20 requests/minute per tenant.

### 2. `GET /v1/soc/actions`
- **Description**: List paginated containment actions for the authenticated tenant.
- **Query Params**: `status`, `action_type`, `page` (default 1), `page_size` (default 50, max 100).
- **Response (HTTP 200)**: Paginated list of containment action summaries.
- **Rate Limit**: 60 requests/minute.

### 3. `GET /v1/soc/actions/{action_uuid}`
- **Description**: Retrieve detailed action record including rollback and result metadata.
- **Response (HTTP 200)**: Full action detail. Returns **HTTP 404** if action belongs to another tenant.

### 4. `POST /v1/soc/actions/{action_uuid}/revert`
- **Description**: Idempotently rollback an executed containment action.
- **Response (HTTP 200)**: Updated action detail with `status = "REVERTED"`.

### 5. `GET /v1/soc/playbooks/runs`
- **Description**: List paginated playbook execution runs for the tenant.
- **Response (HTTP 200)**: Paginated playbook runs.

### 6. `GET /v1/soc/containment/policy` & `PUT /v1/soc/containment/policy`
- **Description**: Get or update tenant containment policy.
- **PUT Request**:
  ```json
  {
    "auto_containment_enabled": true,
    "auto_blacklist_enabled": true,
    "auto_quarantine_enabled": false,
    "auto_incident_binding_enabled": true,
    "containment_min_severity": "CRITICAL",
    "blacklist_ttl_seconds": 86400,
    "policy_version": 1
  }
  ```
- **PUT Response**: HTTP 200 on success; HTTP 409 on version conflict.

---

## 21. Phase 5D Notification Integration

1. Containment engine integrates seamlessly with `NotificationService` and `NotificationDispatcher`.
2. Upon action execution (`containment_applied` or `containment_reverted`):
   - In-app notification created via `notification_service.create_in_app_notification()`.
   - Transactional outbox row inserted into `notification_outbox` for webhook subscribers.
3. Webhook delivery:
   - Handled by `NotificationDispatcher` in the background.
   - Outbox creation is atomic within the containment database transaction.
   - Network delivery is at-least-once with canonical HMAC-SHA256 signatures (`X-SOC-Signature-256`) and SSRF DNS-pinned egress.

---

## 22. Phase 5E Streaming Event Integration

1. Real-time SSE frames broadcast via `event_broadcaster.publish_event_nowait()`:
   - `playbook_triggered`: Playbook evaluation initiated.
   - `containment_applied`: Action executed (includes action UUID, type, target, and status).
   - `containment_reverted`: Action successfully rolled back.
   - `playbook_completed`: Playbook execution finished.
   - `playbook_failed`: Playbook encountered an error.
2. All events:
   - Written to `soc_event_stream` within the database transaction.
   - Dispatched to Redis Pub/Sub (`soc:events:broadcast`) post-commit.
   - Bounded to 16 KB max payload; secrets redacted via `sanitize_payload_secrets()`.

---

## 23. Redis Architecture & Distributed Primitives

### 1. Redis Keys & Scopes:
- **Playbook Lock**: `soc:playbook:lock:{tenant_id}:{target_id}` (Token-bound, 30s TTL).
- **Tenant Semaphore**: `soc:playbook:tenant_semaphore:{tenant_id}` (Token-bound, 60s TTL).
- **Retention Leader Lock**: `soc:retention:leader_lock` (Token-bound, 300s TTL).
- **Prediction Cache**: `cache:prediction:{normalized_url_hash}` (Invalidated on containment).

### 2. Lua Safe Release Script:
Prevents blind deletion of locks acquired by another worker:
```lua
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
```

### 3. Graceful Degraded Mode:
If Redis is down or unreachable:
- Playbook lock acquisition falls back to database row-level locking on `soc_playbook_runs`.
- Tenant concurrency limit falls back to PostgreSQL `SELECT count(*) ... FOR UPDATE`.
- Cache invalidation logs a warning and proceeds without blocking containment.

---

## 24. Retention Worker (`RetentionWorker`)

### 1. Worker Specification:
- Implemented in `backend/services/retention_worker.py`.
- Runs on a periodic background loop with an hourly cadence (`RETENTION_INTERVAL_SECONDS = 3600`).
- **Leader Election**: In multi-pod deployments, acquires `soc:retention:leader_lock` in Redis (or PostgreSQL advisory lock `pg_try_advisory_lock(0x5F5F0001)`). Only the leader executes pruning.
- Managed cleanly within FastAPI application lifespan in `backend/main.py` (`startup` and `shutdown`).
- **Does NOT modify `scheduler_service.py`**.

---

## 25. PostgreSQL-Safe Bounded Batch Pruning

> [!IMPORTANT]
> **NO `DELETE ... LIMIT 500` SYNTAX**
> PostgreSQL does not support `LIMIT` in `DELETE` statements. Pruning must use bounded key selection via CTEs with `FOR UPDATE SKIP LOCKED`.

### 1. Pruning Implementation Pattern:
```sql
-- PostgreSQL-safe bounded deletion pattern (executed in batches of 500)
WITH doomed AS (
    SELECT id FROM notification_outbox
    WHERE created_at < NOW() - INTERVAL '30 days'
      AND status IN ('DELIVERED', 'DEAD_LETTER')
    ORDER BY id ASC
    LIMIT 500
    FOR UPDATE SKIP LOCKED
)
DELETE FROM notification_outbox
WHERE id IN (SELECT id FROM doomed);
```

### 2. Pruning Policy Matrix:
| Table | Primary Key | Retention TTL | Pruning Eligibility Predicate |
|---|---|---|---|
| `soc_event_stream` | `cursor_id` | **7 Days** | `created_at < NOW() - INTERVAL '7 days'` |
| `notification_outbox` | `id` | **30 Days** | `created_at < NOW() - INTERVAL '30 days' AND status IN ('DELIVERED', 'DEAD_LETTER')` |
| `soc_containment_actions` | `id` | **90 Days** | `created_at < NOW() - INTERVAL '90 days' AND status IN ('EXECUTED', 'REVERTED', 'FAILED', 'BLOCKED_BY_ALLOWLIST')` |
| `soc_playbook_runs` | `id` | **90 Days** | `created_at < NOW() - INTERVAL '90 days' AND status IN ('COMPLETED', 'FAILED', 'REVERTED')` |

### 3. Execution Safety Invariants:
- **Batch Size**: Maximum 500 rows per batch.
- **Deterministic Ordering**: Ordered by primary key ASC (`cursor_id ASC` or `id ASC`).
- **Short Transactions**: Each batch commits immediately.
- **Inter-Batch Pause**: `await asyncio.sleep(0.5)` between batches to prevent connection pool exhaustion and table locks.
- **Active State Preservation**: Records in `PENDING`, `RUNNING`, `LOCKED`, or retryable states are **NEVER deleted**.
- **Audit Logs Excluded**: `AuditEvent` is an immutable compliance log and is strictly excluded from Phase 5F pruning.
- **Replay Behavior**: If an SSE client reconnects with `Last-Event-ID` older than 7 days, Phase 5E logic detects the missing cursor and issues `event: stream_reset` per protocol.

---

## 26. Failure Modes & Recovery Semantics

1. **Redis Unavailable During Containment**:
   - Engine falls back to PostgreSQL row-level locking.
   - Cache invalidation logs a warning; database transaction commits successfully.
2. **Database Transaction Rollback**:
   - If any action raises an unhandled database error, the transaction rolls back.
   - No partial database records persist; `soc_event_stream` frame is discarded.
3. **Allowlist Lookup Failure / Timeout**:
   - System fails closed: treats indicator as whitelisted, aborts blacklisting, logs audit event.
4. **Worker Crash During Playbook Execution**:
   - Run remains `RUNNING` in database.
   - Stale worker detection identifies runs where `updated_at < NOW() - INTERVAL '5 minutes'`.
   - Subsequent worker reclaims the run, increments `fencing_token`, and safely resumes or fails the run.
5. **Worker Resumes After Losing Lock (Stale Worker)**:
   - Fencing token check rejects stale mutations before database write.

---

## 27. Security Threat Model

| Threat ID | Threat Vector | Impact | Mitigation Strategy | Residual Risk | Required Test |
|---|---|---|---|---|---|
| **T-5F-01** | **False-Positive Blacklisting via Crafted Alert** | Attacker crafts alert targeting `google.com`, causing suite to block legitimate services. | **Rule 0 Allowlist Fence**: Mandatory check against `TRUSTED_DOMAINS` before blacklisting. Fail-closed on error. | New legitimate domain not yet in allowlist. | `test_rule0_allowlist_fencing()` |
| **T-5F-02** | **Cross-Tenant Containment Manipulation** | Tenant A attempts to view, contain, or revert Tenant B's targets. | **Authoritative Server Predicates**: Lookups enforce `WHERE tenant_id = :tenant_id`. Foreign lookups return 404. | None. | `test_tenant_isolation_idor()` |
| **T-5F-03** | **Playbook Execution Storm / DoS** | Alert storm triggers 1,000 simultaneous playbooks, exhausting DB connections. | **Concurrency Limit & Idempotency**: Global per-tenant cap of 5 concurrent runs. Database unique constraint. | Rate limit rejection (HTTP 429). | `test_playbook_concurrency_limit()` |
| **T-5F-04** | **Blind Rollback Collateral Damage** | Reverting an auto-containment action removes an analyst's manual blacklist entry. | **Provenance Tracking**: Blacklist records `containment_action_id`. Rollback deletes only action-owned rows. | None. | `test_provenance_safe_rollback()` |
| **T-5F-05** | **Arbitrary Code Execution** | Attacker attempts to submit payload injecting shell or Python commands. | **Declarative Type Safety**: Playbooks are strictly hardcoded typed sequences; zero `eval`, `exec`, or shell. | None. | `test_declarative_action_types_only()` |
| **T-5F-06** | **Replay / Idempotency Key Abuse** | Attacker submits duplicate triggers attempting double mitigation. | **Database Uniqueness**: Unique constraints on `idempotency_key` prevent duplicate execution. | None. | `test_idempotency_duplicate_trigger()` |
| **T-5F-07** | **Stale Worker Execution** | Paused worker resumes after lock expiry and applies stale mutation. | **Fencing Token Protocol**: Worker verifies `fencing_token` before mutation inside transaction. | None. | `test_stale_worker_fencing()` |
| **T-5F-08** | **Policy Update Race** | Concurrent policy updates overwrite configuration unpredictably. | **Optimistic Concurrency Control**: Updates require matching `policy_version`. | 409 on race. | `test_policy_optimistic_concurrency()` |
| **T-5F-09** | **Redis Lock Expiry Race** | Long-running playbook loses Redis lock before completion. | **Safe Token Release**: Lua script verifies token before `DEL`. Fencing token protects DB. | None. | `test_safe_lock_release_lua()` |
| **T-5F-10** | **Retention Deleting Active State** | Pruning worker mistakenly deletes pending outbox jobs or running playbooks. | **Terminal State Filter**: Pruning queries strictly filter for terminal states (`DELIVERED`, `DEAD_LETTER`). | None. | `test_retention_preserves_active_records()` |
| **T-5F-11** | **Sensitive Data Leakage in Metadata** | Containment metadata leaks passwords or API keys in action details. | **Secret Redaction**: Payloads pass through `sanitize_payload_secrets()` before persistence. | None. | `test_containment_metadata_redaction()` |
| **T-5F-12** | **Privilege Escalation via Containment API** | Non-admin user attempts global containment or policy modification. | **RBAC Enforcement**: Policy updates and global actions require `admin` or `soc_lead` role. | None. | `test_containment_rbac_enforcement()` |

---

## 28. Testing Strategy

Phase 5F requires 100% test pass rate across all tiers:

1. **Unit Tests (`tests/unit/test_containment_service.py`)**:
   - Rule 0 allowlist fencing (verifying allowlisted domains cannot be blacklisted).
   - Default safe mode (verifying containment no-ops when policy is disabled).
   - Idempotency key collision handling and exactly-once durable action records.
   - Provenance-safe rollback (verifying only action-owned blacklist rows are removed).
   - Target quarantine threshold evaluation (3+ active alerts in 10m).
2. **Retention Tests (`tests/unit/test_retention_worker.py`)**:
   - PostgreSQL-safe CTE batch pruning deleting only rows older than specified TTLs.
   - Preserving active, pending, and running records.
   - Non-blocking execution with 0.5s pause.
3. **API Tests (`tests/integration/test_containment_api.py`)**:
   - REST endpoints for contain, list, details, revert, and policy management.
   - Multi-tenant isolation (HTTP 404 on foreign action UUIDs).
   - Admin RBAC operations.
4. **Concurrency Tests (`tests/integration/test_containment_concurrency.py`)**:
   - 20 concurrent triggers for the same alert producing exactly 1 containment action.
   - Simultaneous rollback attempts.
   - Stale worker fencing token rejection.
5. **Full Regression Guard**: All 548 existing repository tests must pass with zero regressions.

---

## 29. Staging Strategy (AC24 Parity)

- Turnkey staging environment [`docker-compose.staging.yml`](file:///e:/AI-Cyber-Security-Suite/docker-compose.staging.yml) is reused.
- AC24 (and AC-5F-19) will continue to be reported truthfully as **NOT VERIFIED — Docker/PostgreSQL/Redis unavailable** in the local Windows environment until live containers are executed.

---

## 30. Acceptance Criteria Matrix

| AC ID | Requirement | Verification Method | Expected Result | Environment |
|---|---|---|---|---|
| **AC-5F-01** | Rule 0 Allowlist Fencing | Unit Test | Allowlisted indicators are NEVER blacklisted; status is `BLOCKED_BY_ALLOWLIST`. | Local / CI |
| **AC-5F-02** | Default-Safe Policy | Unit Test / API | Automated containment is disabled by default; triggers only when explicitly enabled. | Local / CI |
| **AC-5F-03** | Durable Idempotency | Concurrency Test | 20 concurrent triggers produce exactly one durable action and playbook run. | Local / CI |
| **AC-5F-04** | Provenance-Safe Rollback | Unit / Integration | Rollback reverts only action-owned blacklist entries; does not touch analyst rules. | Local / CI |
| **AC-5F-05** | Exact Quarantine Semantics | Unit Test | Quarantine triggers iff $\ge 3$ distinct active (`OPEN`/`ACKNOWLEDGED`) high/critical alerts occur in 10m. | Local / CI |
| **AC-5F-06** | Immutable Audit Trail | Integration Test | All containment decisions, blocks, and reverts emit immutable `AuditEvent` records. | Local / CI |
| **AC-5F-07** | Phase 5E SSE Events | Integration Test | Lifecycle events (`containment_applied`, etc.) broadcast over SSE streams. | Local / CI |
| **AC-5F-08** | Phase 5D Outbox Integration | Integration Test | Containment notifications reuse transactional outbox and HMAC-SHA256 signing. | Local / CI |
| **AC-5F-09** | Event Stream Retention | Unit / DB Test | Pruning deletes `soc_event_stream` rows older than 7 days in bounded batches of 500. | Local / CI |
| **AC-5F-10** | Outbox Job Retention | Unit / DB Test | Pruning deletes terminal outbox jobs older than 30 days. | Local / CI |
| **AC-5F-11** | Containment History Retention | Unit / DB Test | Pruning deletes terminal containment actions and runs older than 90 days. | Local / CI |
| **AC-5F-12** | Distributed Concurrency Limit | Concurrency Test | Max 5 concurrent playbook runs per tenant enforced via Redis/DB fallback. | Local / CI |
| **AC-5F-13** | Stale Worker Fencing | Concurrency Test | Stale worker with mismatched `fencing_token` is rejected before database mutation. | Local / CI |
| **AC-5F-14** | Failure / Degraded Recovery | Integration Test | Redis outage falls back to DB locks; allowlist failure fails closed. | Local / CI |
| **AC-5F-15** | Strict Tenant Isolation | API Test | Cross-tenant action lookup returns HTTP 404 (anti-enumeration). | Local / CI |
| **AC-5F-16** | Policy Authorization & RBAC | API Test | Only authorized admins can update containment policies; optimistic locking enforced. | Local / CI |
| **AC-5F-17** | PostgreSQL-Safe Pruning | SQL / DB Test | Pruning uses CTEs with `FOR UPDATE SKIP LOCKED`; no `DELETE ... LIMIT` syntax. | Local / CI |
| **AC-5F-18** | Full Regression Pass | Regression Suite | All 548 existing repository tests continue to pass (0 failures, 0 errors). | Local / CI |
| **AC-5F-19** | Distributed Staging Verification | Staging Test | Verification against live PostgreSQL 16 and Redis 7 containers. | Staging Only (Pending Docker) |

---

## 31. Exact Implementation File Scope

### Files to CREATE (Post-Approval Only):
1. `backend/schemas/containment.py` — Pydantic schemas for containment requests, responses, policy, and playbook models.
2. `backend/services/containment_service.py` — Core containment engine, `ThreatIntelAdapter`, and `PlaybookRunner`.
3. `backend/services/retention_worker.py` — Background bounded-batch retention pruning task.
4. `backend/api/routers/containment.py` — REST endpoints for containment actions, playbook history, and policy.
5. `migrations/versions/c1d2e3f4a5b6_sprint5_phase5f_soc_containment.py` — Schema migration for `soc_containment_policies`, `soc_playbook_runs`, `soc_containment_actions`, and `soc_dynamic_blacklist`.
6. `tests/unit/test_containment_service.py` — Unit tests for containment logic, policy defaults, and allowlist fencing.
7. `tests/unit/test_retention_worker.py` — Unit tests for PostgreSQL-safe retention pruning.
8. `tests/integration/test_containment_api.py` — API integration and tenant isolation tests.
9. `tests/integration/test_containment_concurrency.py` — Concurrency, race-condition, and stale worker fencing tests.

### Files to MODIFY (Post-Approval Only):
1. `backend/main.py` — Mount `containment.router` under `/v1`; manage `RetentionWorker` in lifespan context.
2. `backend/database/models.py` — Declare `SOCContainmentPolicy`, `SOCPlaybookRun`, `SOCContainmentAction`, and `SOCDynamicBlacklist` models.
3. `backend/services/alert_service.py` — Invoke `containment_service.evaluate_alert_containment()` post-commit on qualifying alerts.

---

## 32. Protected Files & Invariants

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

## 33. Open Risks & Residual Risks

1. **Local Staging Verification (AC24 & AC-5F-19)**:
   - *Risk*: Docker is currently unavailable on the local Windows environment.
   - *Mitigation*: Local tests verify all logic using SQLite and mock adapters. Staging ACs are clearly documented as pending live container execution and never falsely marked verified.
2. **Allowlist Feed Freshness**:
   - *Risk*: A brand-new legitimate domain not yet in `TRUSTED_DOMAINS` could theoretically be blacklisted if policy is enabled.
   - *Mitigation*: Automated containment is disabled by default. Fail-closed parsing protects known structures, and manual analyst rollback is available.

---

## 34. Architecture Verdict

### Verdict: **GO WITH CONDITIONS**

### Conditions for Implementation Authorization:
1. **Explicit Human Approval**: A human lead must formally review and approve this `v1.1` specification.
2. **Zero Code Implementation Prior to Approval**: No source code, models, migrations, or tests may be created until explicit authorization is granted.
3. **Protected Files Invariant**: The 8 protected infrastructure files and 5 pre-existing working-tree files must remain completely untouched.
4. **Truthful AC24 Reporting**: Staging ACs must remain marked `NOT VERIFIED` until Docker/PostgreSQL/Redis containers are physically executed.
