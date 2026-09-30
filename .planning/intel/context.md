# System Context (Ingested)

## Operational Architecture & Topology
- **Source**: `docs/DEPLOYMENT.md`, `README.md`
- **Context**: The AI Cyber Security Suite operates as a distributed system comprised of:
  1. **Frontend**: React 19 + TypeScript + Vite + TailwindCSS + Recharts SPA presenting the enterprise SOC dashboard, alert triage, incident manager, monitoring console, and containment consoles.
  2. **Extension**: Chrome Manifest V3 browser extension providing real-time URL scanning with in-page badges and sidepanel threat breakdown.
  3. **Backend**: FastAPI asynchronous API server providing REST endpoints, WebSocket/SSE streams, and Prometheus metrics.
  4. **Storage & Cache**: PostgreSQL / SQLite persistent store with Alembic schema migrations; Redis asynchronous cache and pub/sub bus.
  5. **Background Workers**: Distributed monitoring worker, notification outbox dispatcher, retention cleanup worker, and autonomous retraining pipeline.

## Machine Learning Pipeline Context
- **Source**: `docs/ML_PIPELINE.md`, `docs/architecture/ARCHITECTURE.md`
- **Context**: The threat prediction core utilizes a 64-feature vector extracted from URLs across 4 domains (Lexical, Structural, Statistical, and Keywords). Models evaluated include Logistic Regression, Random Forest, and Calibrated XGBoost with Optuna hyperparameter optimization. Active learning verifies zero-day candidates through external intelligence sources before model promotion.

## Operations & Troubleshooting Runbook
- **Source**: `docs/TROUBLESHOOTING.md`
- **Context**: Standard procedures for diagnosing database locks, Redis reconnection failover degradation, model pickle hash mismatches, and multi-pod lease expiration.
