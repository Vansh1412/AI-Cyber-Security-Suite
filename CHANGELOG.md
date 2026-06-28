# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-06-28 — Initial Public Release (RC1)

### Added
- **FastAPI Backend** with async SQLAlchemy, Alembic migrations, and SQLite/PostgreSQL support.
- **XGBoost URL Threat Classifier** trained on PhishTank, Alexa, and ISCX-URL-2016 datasets.
- **SHAP Explainability** — top feature attributions computed asynchronously per scan.
- **Threat Intelligence Waterfall** — local blacklist + heuristic engine + ML pipeline with trusted domain allowlist (Rule 0).
- **React 18 Dashboard** — authentication, historical scan views, analytics charts (Recharts), and manual scan interface.
- **Manifest V3 Browser Extension** — real-time per-tab scanning with badge status indicators, local TTL cache, and rich popup UI.
- **SlowAPI Rate Limiting** — per-role dynamic limits across all endpoints.
- **Prometheus + OpenTelemetry Observability** — metrics at `/metrics`, trace instrumentation.
- **Docker Compose** — full production stack (FastAPI + PostgreSQL + Redis + Prometheus).
- **Structured Logging** — `structlog` with ASGI correlation IDs.
- **JWT Authentication** — secure token-based auth with bcrypt password hashing.

### Security
- CORS restricted to configured origins in production.
- No secrets committed; all credentials are environment-variable-driven.
- Rate limits prevent API abuse against the inference engine.

---

## [0.x.x] — Development Milestones (Internal)

Pre-release development phases covering data engineering, ML training, feature engineering, backend scaffolding, and enterprise hardening. Not publicly released.
