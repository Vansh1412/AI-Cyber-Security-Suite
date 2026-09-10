# Technology Stack

**Analysis Date:** 2026-09-10

## Languages

**Primary:**
- Python 3.10 / 3.11 - Backend REST API (`backend/`), Machine Learning training and inference pipelines (`ml/`), and legacy dataset ingestion utilities (`src/`)
- TypeScript 5.5 - Frontend dashboard (`frontend/src/`) and Chrome browser extension (`extension/`)

**Secondary:**
- JavaScript (ES Modules / Node.js 20+) - Build scripting (`extension/build.mjs`, `frontend/vite.config.ts`, `frontend/tailwind.config.js`)
- SQL / PostgreSQL dialect - Async database schemas and Alembic migrations (`migrations/`, `backend/database/`)
- HTML5 / CSS3 - React UI styling with TailwindCSS 3.4 (`frontend/src/index.css`) and Extension UI (`extension/popup/popup.html`, `extension/sidepanel/sidepanel.html`)

## Runtime

**Environment:**
- Python 3.10+ virtual environment (`.venv`)
- Node.js 18+ (tested with Node 20 LTS in CI)
- Docker & Docker Compose (`docker-compose.yml`, Dockerfile based on Python 3.10)

**Package Manager:**
- Python: `pip` via `requirements.txt` (no `Pipfile` or `poetry.lock`)
- Lockfile (Python): missing (version ranges unpinned in `requirements.txt`)
- Node.js (Frontend): `npm` with lockfile present (`frontend/package-lock.json`)
- Node.js (Extension): `npm` with lockfile present (`extension/package-lock.json`)

## Frameworks

**Core:**
- FastAPI 0.115+ - High-performance async Python web framework (`backend/main.py`)
- React 19.0.0 - Component-based SPA dashboard UI (`frontend/src/main.tsx`, `frontend/package.json`)
- Chrome Extensions Manifest V3 - Browser security agent (`extension/manifest.json`)
- SQLAlchemy 2.0 (Async) - ORM and database abstraction (`backend/database/models.py`, `backend/database/session.py`)

**Testing:**
- Pytest 8.x + pytest-asyncio - Python unit and pipeline testing (`pytest.ini`, `tests/`)
- Vitest 2.1.1 - Frontend test runner (`frontend/package.json`, configured in CI with `--passWithNoTests`)

**Build/Dev:**
- Vite 5.4.8 - Frontend bundler and dev server (`frontend/vite.config.ts`)
- TailwindCSS 3.4.13 + PostCSS + Autoprefixer - Utility-first CSS styling (`frontend/tailwind.config.js`)
- Ruff - Python linter and code formatter (`pyproject.toml`)
- Alembic - Database schema migration framework (`alembic.ini`, `migrations/`)
- esbuild / custom build script - Extension bundler (`extension/build.mjs`)

## Key Dependencies

**Critical:**
- `xgboost` (1.7+ / 2.x): Production classifier for multiclass URL threat detection (`ml/models/xgboost_model.py`)
- `scikit-learn`: Feature scaling, calibration (`CalibratedClassifierCV`), and evaluation metrics (`ml/models/calibrate.py`, `ml/models/base.py`)
- `shap`: TreeSHAP explainability engine producing real-time feature attribution rankings (`backend/services/explainer.py`, `ml/tracking/shap_analyzer.py`)
- `optuna`: Bayesian hyperparameter optimization engine (`ml/models/tuner.py`)
- `pandas` & `numpy`: High-performance vectorized tabular feature manipulation (`ml/features/extractor.py`, `ml/features/pipeline.py`)
- `pyarrow`: High-speed column-oriented Parquet read/write for feature store (`ml/feature_store/`)
- `pydantic-settings` & `pydantic[email]`: Strict request/response payload validation and environment configuration (`backend/core/config.py`, `backend/schemas/`)
- `python-jose[cryptography]` & `passlib[bcrypt]`: JWT authentication token generation, verification, and bcrypt password hashing (`backend/core/security.py`)
- `httpx`: Async HTTP client for threat intelligence feeds (VirusTotal, PhishTank) (`backend/services/threat_intel.py`)

**Infrastructure & Observability:**
- `asyncpg`: Async PostgreSQL driver for production workloads (`backend/database/session.py`)
- `aiosqlite`: Async SQLite driver for zero-config local development (`backend/database/session.py`)
- `redis[asyncio]`: Async distributed cache and request deduplication (`backend/services/cache.py`)
- `slowapi`: Leaky-bucket / sliding window rate limiting (`backend/core/rate_limit.py`, `backend/main.py`)
- `prometheus-fastapi-instrumentator`: Real-time Prometheus metrics exporter mounted at `/metrics` (`backend/main.py`)
- `asgi-correlation-id`: Request tracing via correlation ID headers (`backend/main.py`)
- `structlog`: Structured logging framework (`src/utils/logger.py`)
- `mlflow`: MLOps experiment tracking, metric logging, and artifact registry (`ml/tracking/mlflow_manager.py`)

## Configuration

**Environment:**
- Managed via `pydantic-settings` in `backend/core/config.py` loading `.env` file (fallback `.env.example`).
- Key variables: `SECRET_KEY`, `DATABASE_URL`, `REDIS_URL`, `VIRUSTOTAL_API_KEY`, `PHISHTANK_API_KEY`, `MODEL_ENV`, `RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD`.
- Frontend environment: `VITE_API_URL` loaded via Vite runtime environment.

**Build:**
- `pyproject.toml`: Configures Ruff linter rules and line length (100).
- `pytest.ini`: Configures test paths (`tests`), root pythonpath (`.`), and output flags (`-v --tb=short`).
- `alembic.ini`: Database migration path and connection URL string template.
- `configs/training.yaml`: Dataset split ratios, dropped features, XGBoost tuning parameters.
- `configs/model_config.yaml`: Multi-class probability thresholds for cascade prediction logic.

## Platform Requirements

**Development:**
- Python 3.10+ with pip
- Node.js 18+ and npm
- Local SQLite (default) or Dockerized PostgreSQL & Redis
- Modern Chromium browser (Chrome/Edge/Brave) for Extension Manifest V3 testing

**Production:**
- Linux container (Ubuntu/Debian Alpine base)
- Docker Compose or Kubernetes cluster
- PostgreSQL 16+ database
- Redis 7+ caching instance
- Prometheus monitoring stack

---

*Stack analysis: 2026-09-10*
