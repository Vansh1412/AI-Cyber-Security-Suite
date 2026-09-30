# Roadmap: AI Cyber Security Suite

## Overview

The AI Cyber Security Suite roadmap captures the progression from core machine learning URL classification to an enterprise-grade autonomous Security Operations Center (SOC) platform with real-time event streaming, continuous monitoring, and automated threat containment.

## Phases

- [x] **Phase 1: Threat Detection & ML Engine** - Multi-class classification (Phishing, Malware, Defacement), feature extraction, and SHAP explainability.
- [x] **Phase 2: Autonomous MLOps & Promotion** - Active learning pipeline, zero-day threat verification, safety guardrails, and atomic rollback.
- [x] **Phase 3: Threat Intelligence Enrichment & SSRF Defense** - On-demand WHOIS, TLS inspection, and redirect analysis with DNS-pinning SSRF protection.
- [x] **Phase 4: SOC Event Bus, Correlation & Incidents** - Normalized SecurityEvent engine, temporal PSL correlation, incident lifecycle, monitoring daemon, and transactional outbox notifications.
- [x] **Phase 5: Real-Time SSE Broadcaster & Multi-Pod Gateway** - Scalable Server-Sent Events gateway, Redis Pub/Sub multi-pod fanout, stream ticketing, and connection bounding.
- [x] **Phase 6: SOC Dynamic Containment & Reversible Playbooks** - Dynamic blacklists, target suspension, playbook execution engine, and one-click rollback.
- [ ] **Phase 7: Production Hardening & Staging Parity** - PostgreSQL staging verification, end-to-end integration tests, and production deployment readiness.

## Phase Details

### Phase 1: Threat Detection & ML Engine
**Goal**: High-throughput URL threat classification with feature transparency.
**Depends on**: Nothing
**Requirements**: REQ-SCAN-01, REQ-EXP-01
**Success Criteria**:
  1. API returns threat class and confidence in < 50ms (cached) and < 200ms (uncached).
  2. Local SHAP explainability exposes top positive and negative risk factors.
**Plans**: Complete
**UI hint**: yes

### Phase 2: Autonomous MLOps & Promotion
**Goal**: Closed-loop active learning and safe candidate model deployment.
**Depends on**: Phase 1
**Requirements**: REQ-MLOPS-01
**Success Criteria**:
  1. Verified zero-day samples autonomously trigger candidate model retraining.
  2. Promotion gate prevents regressions against PR-AUC, F1, and recall floors.
  3. Atomic rollback demotes bad champion without re-promoting previously failed models.
**Plans**: Complete

### Phase 3: Threat Intelligence Enrichment & SSRF Defense
**Goal**: Enriched contextual telemetry over secured outbound network sockets.
**Depends on**: Phase 1
**Requirements**: REQ-INTEL-01
**Success Criteria**:
  1. On-demand WHOIS, TLS certificate, and HTTP redirect chain lookups.
  2. Outbound probes block private IP spaces (RFC1918, link-local, loopback) with anti-rebinding DNS resolution.
**Plans**: Complete

### Phase 4: SOC Event Bus, Correlation & Incidents
**Goal**: Enterprise event ingestion, temporal correlation, incident lifecycle, and resilient dispatching.
**Depends on**: Phase 2, Phase 3
**Requirements**: REQ-EVT-01, REQ-CORR-01, REQ-INC-01, REQ-MON-01, REQ-NOTIF-01
**Success Criteria**:
  1. Normalized `SecurityEvent` ingestion bounded to 16 KB with deterministic serialization.
  2. Sliding-window correlation with PSL root-domain clustering de-duplicates alerts.
  3. Incidents enforce monotonic severity escalation and complete audit histories.
  4. Distributed monitoring worker probes targets using database lease claims.
  5. Transactional outbox delivers notifications across Email, Webhooks, and In-App with exponential backoff.
**Plans**: Complete
**UI hint**: yes

### Phase 5: Real-Time SSE Broadcaster & Multi-Pod Gateway
**Goal**: Live event streaming to SOC analyst consoles across distributed application pods.
**Depends on**: Phase 4
**Requirements**: REQ-STREAM-01
**Success Criteria**:
  1. Native EventSource connects via single-use 30-second stream tickets.
  2. Redis Pub/Sub fans out events across pods with graceful local fallback.
  3. Strict stream bounding (max 5 per user, max 1,000 per pod) and 15s heartbeats.
**Plans**: Complete
**UI hint**: yes

### Phase 6: SOC Dynamic Containment & Reversible Playbooks
**Goal**: Automated and analyst-driven mitigation of active threats.
**Depends on**: Phase 4, Phase 5
**Requirements**: REQ-CONT-01
**Success Criteria**:
  1. Dynamic blacklist entries prevent compromised target resolution.
  2. Guarded playbooks execute containment actions with transaction isolation.
  3. Analysts can execute atomic, one-click rollbacks for all mitigation actions.
**Plans**: Complete
**UI hint**: yes

### Phase 7: Production Hardening & Staging Parity
**Goal**: Validate multi-tenant PostgreSQL concurrency, end-to-end integration, and production deployment readiness.
**Depends on**: Phase 6
**Requirements**: REQ-PROD-01
**Success Criteria**:
  1. PostgreSQL staging environment passes full concurrency and race-condition suites.
  2. Docker and production orchestration compose stacks run cleanly without deprecated dependencies.
  3. All public API endpoints and frontend consoles operate without unhandled exceptions.
**Plans**: TBD
**UI hint**: yes

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Threat Detection & ML Engine | Complete | Complete | 2026-09-10 |
| 2. Autonomous MLOps & Promotion | Complete | Complete | 2026-09-15 |
| 3. Threat Intelligence & SSRF | Complete | Complete | 2026-09-20 |
| 4. SOC Event Bus & Incidents | Complete | Complete | 2026-09-25 |
| 5. Real-Time SSE Broadcaster | Complete | Complete | 2026-09-28 |
| 6. SOC Dynamic Containment | Complete | Complete | 2026-09-29 |
| 7. Production Hardening & Parity | 1/3 | In progress | - |
