# Extracted Requirements (Ingested)

## REQ-SCAN-01: Multi-Class URL Threat Detection
- **Source**: `docs/architecture/ARCHITECTURE.md`, `README.md`
- **Scope**: ML, Prediction, API
- **Description**: Real-time URL threat detection classifying inputs into 4 classes: Legitimate, Phishing, Malware, and Defacement. Inference latency must be < 50ms for cached URLs and < 200ms for uncached URLs.

## REQ-EXP-01: SHAP Model Explainability
- **Source**: `docs/architecture/ARCHITECTURE.md`, `docs/ML_PIPELINE.md`
- **Scope**: Explainer, ML
- **Description**: Provide transparent local SHAP feature attributions and top contributing risk factors for each scan result to guide SOC analysts and end users.

## REQ-MLOPS-01: Autonomous Active Learning & Safe Model Promotion
- **Source**: `docs/ML_PIPELINE.md`, `docs/architecture/ARCHITECTURE.md`
- **Scope**: MLOps, Retraining
- **Description**: Collect ground-truth zero-day threat samples, autonomously trigger model retraining with safety metrics verification (PR-AUC, F1-macro, recall floors), and support atomic rollback without reinstalling demoted models.

## REQ-EVT-01: Enterprise SOC Event Engine
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Scope**: SOC, Events
- **Description**: Ingest, validate, and normalize security events with strict payload limits (16 KB) and deterministic serialization across tenant and system boundaries.

## REQ-CORR-01: Temporal Correlation & Alert Generation
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Scope**: Correlation, Alerts
- **Description**: Correlate security events within bounded sliding time windows using weighted indicator scoring and PSL-aware root domains to produce de-duplicated alerts and prevent alert storms.

## REQ-INC-01: Security Incident Management Lifecycle
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Scope**: Incidents, SOC
- **Description**: Provide complete incident lifecycle management (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), alert attachment, monotonic severity escalation, and comprehensive audit trails.

## REQ-MON-01: Continuous Target Monitoring & Distributed Lease Claims
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Scope**: Monitoring, Probes
- **Description**: Monitor external endpoints on configurable intervals (5 to 1440 minutes), executing lightweight probes via distributed leader-worker lease claiming to prevent duplicate execution across pods.

## REQ-NOTIF-01: Resilient Multi-Channel Notification Dispatcher
- **Source**: `docs/architecture/sprint5_phase5d_arch_spec_v1_2.md`
- **Scope**: Notifications, Outbox
- **Description**: Dispatch alerts and incident notifications across Email (SMTP), Webhooks, and In-App channels using a transactional outbox with guaranteed delivery, backoff, and tenant preferences.

## REQ-STREAM-01: Real-Time SSE Broadcasting & Multi-Pod Gateway
- **Source**: `docs/architecture/sprint5_phase5e_arch_spec_v1_1.md`
- **Scope**: Streams, SSE, WebSockets
- **Description**: Broadcast SOC security events live to analyst consoles over Server-Sent Events (SSE) with Redis Pub/Sub multi-pod fanout, bounded client queues, and 15s heartbeats.

## REQ-CONT-01: SOC Dynamic Containment & Reversible Playbooks
- **Source**: `docs/architecture/sprint5_phase5f_arch_spec_v1_1.md`
- **Scope**: Containment, Automation
- **Description**: Execute automated and manual containment playbooks, maintaining dynamic IP/domain blacklists, target suspension, and one-click reversible rollback actions.
