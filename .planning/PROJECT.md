# AI Cyber Security Suite

## What This Is

An enterprise-grade, AI-driven cyber security operations center (SOC) and real-time threat intelligence suite. It protects users and enterprise endpoints by classifying malicious URLs across multiple threat vectors (Phishing, Malware, Defacement), dynamically correlating security telemetry across sliding temporal windows, providing explainable AI risk factors, and automatically containing threats via reversible SOC playbooks.

## Core Value

Real-time, explainable threat detection and deterministic SOC incident containment that protects enterprise infrastructure while preventing alert fatigue and operational lockouts.

## Requirements

### Validated

- ✓ **REQ-SCAN-01**: Multi-class URL threat detection across Legitimate, Phishing, Malware, and Defacement (<50ms cached, <200ms uncached) — Milestone 1 & 2
- ✓ **REQ-EXP-01**: Local SHAP explainability and top risk attribution — Milestone 2
- ✓ **REQ-MLOPS-01**: Autonomous active learning pipeline with safety guardrails and zero-day promotion — Sprint 3
- ✓ **REQ-INTEL-01**: On-demand intelligence enrichment (WHOIS, TLS certs, HTTP redirects) with SSRF defense — Sprint 4
- ✓ **REQ-EVT-01**: Normalized SOC Event Engine with bounded payloads (16 KB) — Sprint 5 Phase 4
- ✓ **REQ-CORR-01**: Temporal sliding-window correlation with PSL-aware domain clustering and alert de-duplication — Sprint 5 Phase 5C
- ✓ **REQ-INC-01**: Security incident management lifecycle with monotonic severity escalation — Sprint 5 Phase 4
- ✓ **REQ-MON-01**: Continuous target endpoint monitoring with distributed lease claims — Sprint 5 Phase 5A & 5B
- ✓ **REQ-NOTIF-01**: Resilient multi-channel notification dispatcher using transactional outbox — Sprint 5 Phase 5D
- ✓ **REQ-STREAM-01**: Real-time SSE broadcasting with Redis Pub/Sub multi-pod gateway — Sprint 5 Phase 5E
- ✓ **REQ-CONT-01**: Dynamic containment actions and reversible auto-remediation playbooks — Sprint 5 Phase 5F

### Active

- [ ] **REQ-PROD-01**: Production deployment hardening, staging parity validation, and end-to-end integration verification — Sprint 6

### Out of Scope

- Raw packet capture (PCAP) inspection — Focused on application/network URL and SOC domain intelligence.
- Invasive remote endpoint agent installation — Operating via Chrome Extension MV3, API integrations, and webhook probes.

## Context

The system consists of:
- **FastAPI Backend**: Async REST API, SSE gateway, Prometheus metrics, and background daemons.
- **Machine Learning Core**: Scikit-Learn, Calibrated XGBoost, SHAP, and active learning loop.
- **Frontend SPA**: React 19 + TypeScript + Vite + TailwindCSS + Recharts enterprise SOC console.
- **Browser Extension**: Manifest V3 Chrome extension for live browser URL inspection.
- **Infrastructure**: PostgreSQL (`asyncpg`) / SQLite (`aiosqlite`), Redis cache & pub/sub, Docker & Docker Compose.

## Constraints

- **Payload Bounds**: Event payloads capped at 16 KB; HTTP body inspection capped at 50 KB.
- **Concurrency & Streams**: Strict global limit of 5 SSE streams per standard user and 1,000 per pod instance.
- **SSRF Defense**: Outbound probes strictly block RFC1918, link-local, loopback, and private address spaces with DNS pinning.
- **Database Engine**: Async architecture supporting both SQLite for test isolation and PostgreSQL for multi-tenant production.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| DEC-001: Async Architecture (FastAPI + AsyncPG + SQLite) | Enables high-throughput I/O with unified schema migrations and sub-second test isolation | ✓ Good |
| DEC-002: Strict Tenant Isolation with Admin Role Separation | Guarantees multi-tenant data boundaries while allowing SOC analysts to view aggregated telemetry | ✓ Good |
| DEC-003: Ephemeral 30s Stream Tickets for SSE | Native browser `EventSource` lacks auth header support; tickets ensure secure credential exchange | ✓ Good |
| DEC-004: Transactional Outbox for Notifications | Decouples event triggers from third-party network latency with guaranteed delivery and retry backoff | ✓ Good |
| DEC-005: PSL-Aware Domain Correlation | Excludes shared cloud CDNs (`github.io`, `workers.dev`) from false-positive root correlation | ✓ Good |
| DEC-006: Reversible Dynamic Containment | Prevents permanent operational disruption from false-positive automated blocks | ✓ Good |

---
*Last updated: 2026-09-30 after documentation ingestion*
