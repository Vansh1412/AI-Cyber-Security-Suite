# Project Synthesis: AI Cyber Security Suite

## Executive Overview
The **AI Cyber Security Suite** is an enterprise-grade threat intelligence and security operations center (SOC) automation platform. It combines machine learning URL threat classification (Phishing, Malware, Defacement) with an active event pipeline, temporal correlation engine, incident response management, distributed endpoint monitoring, resilient multi-channel notifications, real-time SSE broadcasting, and reversible automated containment playbooks.

## Ingested Documentation Breakdown
- **Architecture Specifications (7)**:
  - System Architecture (`docs/architecture/ARCHITECTURE.md`)
  - Sprint 5 SOC Next Phase Architecture (`docs/architecture/sprint5_next_phase_architecture_v1_0.md`)
  - Phase 5D Notification Engine Specs (`v1.1` and `v1.2`)
  - Phase 5E Real-Time Event Broadcaster Spec (`v1.1`)
  - Phase 5F SOC Containment & Auto-Remediation Specs (`v1.0` and `v1.1`)
- **Operational & System Guides (8)**:
  - Master README (`README.md`)
  - API Reference & Documentation (`docs/api/API_REFERENCE.md`, `docs/api/README.md`)
  - Architecture Index (`docs/architecture/README.md`)
  - Deployment & Docker Guide (`docs/DEPLOYMENT.md`)
  - Machine Learning Pipeline (`docs/ML_PIPELINE.md`)
  - Troubleshooting Runbook (`docs/TROUBLESHOOTING.md`)
  - Literature Review (`docs/research/LITERATURE_REVIEW.md`)

## Key Structural Components
1. **Core Threat Engine**:
   - 64-feature extraction pipeline (Lexical, Structural, Statistical, Keyword).
   - Calibrated XGBoost with custom confidence cascades and local SHAP explainability.
   - Autonomous active learning with external intelligence verification and rollback protection.
2. **SOC Event & Correlation Bus**:
   - Normalized `SecurityEvent` ingestion with 16 KB payload bounds.
   - PSL-aware domain correlation and sliding-window temporal deduplication.
   - `Alert` generation with automated incident escalation.
3. **Operations & Dispatching**:
   - Incident management with monotonic severity escalation and tenant isolation.
   - Continuous endpoint monitoring with distributed lease claims.
   - Transactional outbox notification dispatcher (Email, Webhook, In-App).
   - Real-time Server-Sent Events (SSE) gateway with multi-pod Redis pub/sub fanout.
   - Dynamic containment playbooks with reversible blacklisting.
