<!-- refreshed: 2026-09-10 -->
# Architecture

**Analysis Date:** 2026-09-10

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Client Modalities                                     │
├───────────────────────────────────┬─────────────────────────────────────────────┤
│      Chrome Extension (MV3)       │            React 19 Dashboard               │
│  `extension/popup/`               │  `frontend/src/pages/Scan.tsx`              │
│  `extension/background/`          │  `frontend/src/pages/Dashboard.tsx`         │
└─────────────────┬─────────────────┴──────────────────────┬──────────────────────┘
                  │                                        │
                  │ HTTP POST /v1/scan                     │ HTTP REST (JWT auth)
                  ▼                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   FastAPI Application (`backend/main.py`)                       │
│   Rate Limiting (SlowAPI) · Auth (`backend/api/routers/auth.py`) · Prometheus   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                     Threat Intelligence Waterfall Layer                         │
│                    `backend/services/threat_intel.py`                           │
│  [1. Local Blacklist] ──▶ [2. Allowlist] ──▶ [3. Heuristics] ──▶ [4. PhishTank]  │
│                                                                  │              │
│                           Passed All Static Filters (Zero-Day)   ▼ (VirusTotal) │
├──────────────────────────────────────────────────────────────────┴──────────────┤
│                         Machine Learning Pipeline Layer                         │
│  • Feature Extraction: `ml/features/extractor.py` (59 schema features)          │
│  • Inference & Cascade Thresholds: `backend/services/prediction.py`             │
│  • Background Explainability: `backend/services/explainer.py` (TreeSHAP)        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                   Active Learning & MLOps Ingestion Loop                        │
│  • Ground-truth Verification: `backend/services/learning.py`                    │
│  • Retraining & Auto-Promotion: `ml/pipelines/retrain.py`                       │
└─────────────────────────────────┬───────────────────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   PostgreSQL /   │    │  Redis Cache     │    │  Local Registry  │
│   SQLite DB      │    │  `backend/`      │    │  `ml/models/`    │
│  `backend.db`    │    │  `services/`     │    │  `store/`        │
│                  │    │  `cache.py`      │    │  `registry.json` │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|---|---|---|
| **API Entrypoint & Lifespan** | Configures middlewares, lifespan startup, singleton warming, Prometheus exporter | `backend/main.py` |
| **Pydantic Configuration** | Single source of truth for runtime settings and environment variables | `backend/core/config.py` |
| **Threat Intelligence** | Waterfall check: local blacklist, allowlists, heuristic regexes, PhishTank, VirusTotal | `backend/services/threat_intel.py` |
| **Feature Extractor** | Normalizes URLs and extracts 59 numerical, lexical, and structural features | `ml/features/extractor.py` |
| **Prediction Service** | Loads champion model from registry, runs inference, applies cascade thresholding | `backend/services/prediction.py` |
| **SHAP Explainer** | Calculates TreeSHAP feature attributions in background task for zero-day scans | `backend/services/explainer.py` |
| **Active Learning** | Pulls un-retrained zero-day scans, verifies labels against intel, formats training sets | `backend/services/learning.py` |
| **Retraining Pipeline** | Trains candidate XGBoost models, benchmarks against champion, updates registry | `ml/pipelines/retrain.py` |
| **Redis Cache Service** | Provides sha256 URL hashing and async caching with graceful failure degradation | `backend/services/cache.py` |
| **Database Session & Models** | Manages async engine, declarative base, User and ScanResult ORM models | `backend/database/models.py`, `backend/database/session.py` |
| **Browser Extension** | MV3 service worker, local tab interceptor, caching, and popup UI | `extension/background/service-worker.js`, `extension/popup/` |
| **Frontend Web Client** | React 19 dashboard with interactive URL scanner, live analytics, and MLOps metrics | `frontend/src/` |

## Pattern Overview

**Overall:** Modular Multi-Tier Microservice with Waterfall Pipeline and Active Learning Loop.

**Key Characteristics:**
- **Tiered Filtering Waterfall:** Requests hit the fastest, cheapest layers first (Redis cache ~0ms, local sets 0ms, heuristic regex 0ms, PhishTank feed 0ms) before invoking feature extraction and tree-model inference (< 15ms), and finally VirusTotal or heavy background SHAP calculations.
- **Zero-Downtime Model Hot-Reloading:** The `PredictionService.reload_model()` method allows the backend to switch active model weights in memory when the MLOps pipeline promotes a new champion, without restarting the FastAPI process.
- **Graceful Degradation:** Both Redis caching and external threat APIs fail open or degrade silently into baseline ML inference rather than interrupting the user request.
- **Strict Separation of Concerns:** Feature extraction logic in `ml/features/` is decoupled from HTTP transport and can be executed identically across batch pipelines, notebooks, and API endpoints.

## Layers

**API / Transport Layer:**
- Purpose: HTTP request validation, authentication, rate limiting, routing, and response serialization.
- Location: `backend/api/`
- Contains: FastAPI APIRouters, Pydantic schemas, Dependency injection functions.
- Depends on: `backend/services/`, `backend/database/`, `backend/core/`.
- Used by: Chrome Extension, React frontend, curl/external clients.

**Service / Business Logic Layer:**
- Purpose: Orchestrates threat intelligence, caching, ML inference, and ground-truth verification.
- Location: `backend/services/`
- Contains: `threat_intel.py`, `prediction.py`, `explainer.py`, `learning.py`, `cache.py`.
- Depends on: `ml/models/`, `ml/features/`, `backend/database/`.
- Used by: `backend/api/routers/`.

**Machine Learning Layer:**
- Purpose: Feature extraction, model training, hyperparameter tuning, evaluation, calibration, and artifact serialization.
- Location: `ml/`
- Contains: `features/`, `models/`, `pipelines/`, `tracking/`, `evaluation/`.
- Depends on: `configs/`, `datasets/processed/`.
- Used by: `backend/services/prediction.py`, `backend/services/explainer.py`, `ml/pipelines/retrain.py`.

**Data / Storage Layer:**
- Purpose: Relational persistence of users and scan history; caching and feature store storage.
- Location: `backend/database/`, `ml/feature_store/`.
- Contains: SQLAlchemy ORM models, Alembic migrations, Parquet files, SQLite/Postgres connections.
- Used by: `backend/services/`, `backend/api/dependencies.py`.

## Data Flow

### Primary Request Path (URL Scan)

1. Client submits URL (`POST /v1/scan`) (`backend/api/routers/scan.py:79`).
2. Rate limit evaluated by SlowAPI based on caller role (admin, user, anonymous) (`backend/api/routers/scan.py:98`).
3. Check Redis cache: If cached, return response immediately with `cache_hit=True` (`backend/api/routers/scan.py:107`).
4. Threat Intelligence waterfall:
   - Check local hardcoded blacklist (`backend/services/threat_intel.py:33`).
   - Check trusted allowlist (`backend/services/threat_intel.py:40`).
   - Check brand impersonation / heuristic regex rules (`backend/services/threat_intel.py:61`).
   - Check local PhishTank in-memory feed (`backend/services/threat_intel.py:176`).
   - Optional: Query VirusTotal API v3 (`backend/services/threat_intel.py:270`).
5. If threat detected by intel waterfall, set result and skip ML (`backend/api/routers/scan.py:128`).
6. If no static hit (Zero-Day URL):
   - Extract 59 canonical features via `FeatureExtractor` (`ml/features/extractor.py:100`).
   - Predict threat class and confidence via `PredictionService` (`backend/services/prediction.py:49`).
   - Cascade logic prioritizes malicious classes (`malware`, `phishing`, `defacement`) using class-specific thresholds from `configs/model_config.yaml`.
7. Cache prediction in Redis (`backend/services/cache.py:58`).
8. Persist scan to database with `is_zero_day=True` and raw feature vector JSON (`backend/api/routers/scan.py:145`).
9. Trigger asynchronous background task to compute SHAP attributions and update DB (`backend/api/routers/scan.py:161`).
10. Return JSON payload to client (`backend/schemas/payload.py:ScanResponse`).

### Autonomous Retraining Data Flow

1. Scheduled job or admin triggers `POST /v1/mlops/retrain` (`backend/api/routers/mlops.py:39`).
2. `ActiveLearningService.fetch_zero_day_samples()` queries database for un-retrained zero-day records (`backend/services/learning.py:35`).
3. `verify_sample_label()` validates each URL against fresh Threat Intel feeds to prevent data poisoning (`backend/services/learning.py:53`).
4. `run_retraining_pipeline()` augments base Parquet splits with verified zero-day samples (`ml/pipelines/retrain.py:43`).
5. Candidate XGBoost model trains and evaluates against current champion model on validation split (`ml/pipelines/retrain.py:117`).
6. If candidate improves F1-score/accuracy (or `force_promotion=True`), new pickle is serialized and `ml/models/store/registry.json` is updated atomically (`ml/pipelines/retrain.py:140`).
7. `PredictionService.reload_model()` hot-reloads model weights into memory (`backend/services/prediction.py:21`).

## Key Abstractions

**Model Wrapper (`ml.models.base.BaseModel`):**
- Abstract base class providing uniform `fit()`, `predict()`, `predict_proba()`, `save()`, and `load()` methods across XGBoost, Random Forest, and Logistic Regression models.
- Implementations: `ml/models/xgboost_model.py`, `ml/models/random_forest.py`, `ml/models/logistic.py`.

**Feature Extractor (`ml.features.extractor.FeatureExtractor`):**
- Unified façade aggregating `LexicalFeatures`, `StructuralFeatures`, `StatisticalFeatures`, and `KeywordFeatures`.
- Guarantees fail-safe extraction by returning zero-vectors if a URL is severely malformed.

**Threat Intelligence Service (`backend.services.threat_intel.ThreatIntelService`):**
- Singleton encapsulating static heuristics, allowlists, PhishTank feed hydration, and asynchronous HTTP calls to VirusTotal.

## Entry Points

**API Service:**
- Location: `backend/main.py`
- Command: `uvicorn backend.main:app --host 0.0.0.0 --port 8000`
- Responsibilities: Initializes DB session, warms up ML singletons, exposes REST and metrics endpoints.

**Dashboard Client:**
- Location: `frontend/src/main.tsx`
- Command: `npm run dev` (Vite)
- Responsibilities: Renders React component tree, handles client-side routing, and connects to `/v1/` endpoints.

**Extension Service Worker:**
- Location: `extension/background/service-worker.js`
- Command: Loaded as Chrome MV3 extension
- Responsibilities: Listens for tab updates, performs real-time URL checks, and updates badge color/icon.

**Batch Feature Pipeline:**
- Location: `ml/features/pipeline.py`
- Command: `python -m ml.features.pipeline`
- Responsibilities: Reads `datasets/processed/merged_dataset.csv` and outputs Parquet feature store files.

## Architectural Constraints

- **Single-Threaded Event Loop (FastAPI/asyncio):** CPU-bound feature extraction and XGBoost inference run synchronously inside route handlers; while typical inference is < 15ms, high concurrency under sustained load can saturate the loop unless scaled via multi-worker Uvicorn or separate inference workers.
- **Model In-Memory Serialization:** Models are stored and loaded as Python `pickle` files (`.pkl`). While performant for local deployment, this requires strict version alignment between the training environment and runtime libraries.
- **Global Singletons:** Services (`cache_service`, `threat_intel_service`, `learning_service`) are instantiated at module import time.
- **Database Divergence:** Dual support for SQLite (dev) and PostgreSQL (prod) means Alembic migrations and SQL queries must avoid database-specific vendor syntax.

## Anti-Patterns

### Hardcoded File Paths in Explainer Service

**What happens:** `ExplainerService` in `backend/services/explainer.py:21` hardcodes:
```python
uncalibrated_path = MODEL_DIR / "xgboost_optuna_best.pkl"
```
instead of referencing the dynamic registry (`settings.MODEL_PATH` or `registry.json`).
**Why it's wrong:** When autonomous retraining promotes a new model to `production`, `PredictionService` hot-reloads the new model, but `ExplainerService` continues computing SHAP attributions against the static initial model.
**Do this instead:** Pass the active model instance or dynamically resolve via `settings.MODEL_PATH`.

### Redundant Scaffolding Directory (`backend/app/`)

**What happens:** An empty directory tree `backend/app/{api,core,db,models,schemas,services,utils}` exists alongside active modules in `backend/`.
**Why it's wrong:** Violates single source of truth, causes confusion during onboarding and imports.
**Do this instead:** Remove `backend/app/` in a cleanup phase.

## Error Handling

**Strategy:** Fail-Safe with Defensive Graceful Degradation.

**Patterns:**
- **Cache Fail-Safe:** `backend/services/cache.py` wraps Redis operations in `try/except Exception` and logs warnings; if Redis disconnects, the API continues without interruption.
- **Threat Intel Degradation:** `backend/services/threat_intel.py` wraps remote calls in timeouts and `try/except Exception`; any network or quota error logs a warning and falls through to the ML model.
- **Zero-Vector Imputation:** `ml/features/extractor.py` catches parsing exceptions and returns a default zero-vector rather than crashing batch pipelines.
- **Background Task Error Isolation:** Background SHAP calculation (`backend/api/routers/scan.py:49`) catches `Exception` explicitly to ensure background failures never impact response lifecycle.

## Cross-Cutting Concerns

**Logging:** Centralized via `src/utils/logger.py` producing uniform timestamped console output.
**Validation:** Pydantic models validate incoming HTTP payloads (`ScanRequest`, `RegisterRequest`, `LoginRequest`).
**Authentication:** Dependency injection (`get_current_user`, `get_optional_user`) verifies Bearer JWT tokens in `backend/api/dependencies.py`.
**Rate Limiting:** Managed per endpoint with `SlowAPI`, dynamically configured by role (`limit_by_role`).

---

*Architecture analysis: 2026-09-10*
