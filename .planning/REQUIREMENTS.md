# Requirements: AI Cyber Security Suite

**Defined**: 2026-09-30 (Ingested from Architecture Specs & System Documentation)  
**Core Value**: Real-time, explainable threat detection and deterministic SOC incident containment that protects enterprise infrastructure while preventing alert fatigue and operational lockouts.

## v1 Requirements

### Threat Scanning & Machine Learning
- [x] **REQ-SCAN-01**: Multi-class URL threat detection across Legitimate, Phishing, Malware, and Defacement (<50ms cached, <200ms uncached)
- [x] **REQ-EXP-01**: Local SHAP explainability and top risk attribution for scans
- [x] **REQ-MLOPS-01**: Autonomous active learning pipeline with safety guardrails and zero-day promotion
- [x] **REQ-INTEL-01**: On-demand intelligence enrichment (WHOIS, TLS certs, HTTP redirects) with SSRF defense

### Security Operations Center (SOC) Engine
- [x] **REQ-EVT-01**: Normalized SOC Event Engine with bounded payloads (16 KB)
- [x] **REQ-CORR-01**: Temporal sliding-window correlation with PSL-aware domain clustering and alert de-duplication
- [x] **REQ-INC-01**: Security incident management lifecycle with monotonic severity escalation
- [x] **REQ-MON-01**: Continuous target endpoint monitoring with distributed lease claims
- [x] **REQ-NOTIF-01**: Resilient multi-channel notification dispatcher using transactional outbox
- [x] **REQ-STREAM-01**: Real-time SSE broadcasting with Redis Pub/Sub multi-pod gateway
- [x] **REQ-CONT-01**: Dynamic containment actions and reversible auto-remediation playbooks

### Production & Integration (Sprint 6)
- [ ] **REQ-PROD-01**: Production deployment hardening, staging parity validation, and end-to-end integration verification

## Out of Scope

| Feature | Reason |
|---------|--------|
| Deep Packet Inspection (DPI) | Focused on application/URL layer and SOC telemetry |
| Kernel-Level Endpoint Drivers | Operates non-invasively via API, Browser MV3 Extension, and webhooks |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| REQ-SCAN-01 | Phase 1: Threat Detection & ML Engine | Complete |
| REQ-EXP-01 | Phase 1: Threat Detection & ML Engine | Complete |
| REQ-MLOPS-01 | Phase 2: Autonomous MLOps & Promotion | Complete |
| REQ-INTEL-01 | Phase 3: Intelligence Enrichment & SSRF | Complete |
| REQ-EVT-01 | Phase 4: SOC Event Bus & Incidents | Complete |
| REQ-CORR-01 | Phase 4: SOC Event Bus & Incidents | Complete |
| REQ-INC-01 | Phase 4: SOC Event Bus & Incidents | Complete |
| REQ-MON-01 | Phase 4: SOC Event Bus & Incidents | Complete |
| REQ-NOTIF-01 | Phase 4: SOC Event Bus & Incidents | Complete |
| REQ-STREAM-01 | Phase 5: Real-Time SSE Broadcaster | Complete |
| REQ-CONT-01 | Phase 6: SOC Dynamic Containment | Complete |
| REQ-PROD-01 | Phase 7: Production Hardening & Parity | In Progress |
