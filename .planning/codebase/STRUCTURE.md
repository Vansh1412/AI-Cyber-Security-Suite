# Codebase Structure

**Analysis Date:** 2026-09-10

## Directory Layout

```text
AI-Cyber-Security-Suite/
├── .agent/                 # GSD workflows, agents, skills, and configuration
├── .agents/                # Standard Antigravity workspace skills directory
├── .github/                # GitHub CI/CD configuration
│   └── workflows/          # GitHub Actions (ci.yml)
├── backend/                # FastAPI application backend
│   ├── api/                # API routers, middleware, and dependency injection
│   │   ├── routers/        # Endpoint handlers (auth, scan, explain, mlops, etc.)
│   │   ├── dependencies.py # FastAPI dependencies (DB, auth, singletons)
│   │   └── middleware.py   # TimingMiddleware
│   ├── app/                # [DEPRECATED/EMPTY] Leftover scaffolding directories
│   ├── core/               # Configuration, security, exceptions, and rate limiting
│   │   ├── config.py       # Pydantic BaseSettings
│   │   ├── exceptions.py   # Global exception handlers
│   │   ├── rate_limit.py   # SlowAPI limiter instance
│   │   └── security.py     # JWT & password hashing utilities
│   ├── database/           # SQLAlchemy models and async session management
│   │   ├── models.py       # User and ScanResult ORM models
│   │   └── session.py      # Engine and sessionmaker setup
│   ├── schemas/            # Pydantic request & response schemas
│   │   ├── auth.py         # Authentication schemas (Login, Register, Token)
│   │   └── payload.py      # Scan, Explain, Stats, and History schemas
│   ├── services/           # Core business logic and integrations
│   │   ├── cache.py        # Redis cache client with graceful fallback
│   │   ├── explainer.py    # TreeSHAP feature attribution service
│   │   ├── feature_eng.py  # Feature engineering wrapper for FastAPI
│   │   ├── learning.py     # Ground-truth verification & active learning
│   │   ├── prediction.py   # Model inference and cascade thresholding
│   │   └── threat_intel.py # Threat intel waterfall (heuristics, PhishTank, VT)
│   ├── tests/              # [EMPTY] Backend-specific tests placeholder
│   └── main.py             # FastAPI entrypoint and lifespan definition
├── configs/                # Runtime configuration files
│   ├── model_config.yaml   # Multiclass cascade threshold configuration
│   └── training.yaml       # ML training hyperparameters and feature drop list
├── datasets/               # Dataset storage
│   ├── external/           # Raw third-party data downloads
│   ├── processed/          # Cleaned CSV datasets and merged_dataset.csv
│   └── raw/                # Unprocessed phishing and legitimate datasets
├── docker/                 # Deployment artifacts
│   ├── Dockerfile          # Backend container specification
│   └── prometheus.yml      # Prometheus scrape configuration
├── docs/                   # Architectural and developer documentation
│   ├── api/                # API documentation and endpoints
│   ├── architecture/       # Deep architecture guides
│   ├── DEPLOYMENT.md       # Deployment runbooks
│   ├── ML_PIPELINE.md      # ML feature and training guide
│   └── TROUBLESHOOTING.md  # Production troubleshooting guide
├── extension/              # Manifest V3 Chrome Extension
│   ├── background/         # Background service worker (service-worker.js)
│   ├── popup/              # Extension popup HTML/CSS/TS
│   ├── content/            # Content script for in-page threat indicators
│   ├── services/           # Extension API clients
│   ├── utils/              # Extension helper functions (badge, cache)
│   ├── build.mjs           # Extension build script
│   └── manifest.json       # Chrome extension manifest
├── frontend/               # React 19 SPA Dashboard
│   ├── src/
│   │   ├── assets/         # Static images, SVG icons, logos
│   │   ├── components/     # Reusable UI components (Navbar, Sidebar, Charts)
│   │   ├── contexts/       # React contexts (AuthContext, ThemeContext)
│   │   ├── hooks/          # Custom React hooks
│   │   ├── pages/          # View routes (Scan, Dashboard, Analytics, Admin)
│   │   ├── routes/         # AppRouter and ProtectedRoute logic
│   │   ├── services/       # Typed Axios API clients (api.ts, auth.ts, scan.ts)
│   │   ├── store/          # Client-side state management
│   │   ├── styles/         # CSS styles and Tailwind additions
│   │   ├── types/          # TypeScript interface definitions
│   │   └── main.tsx        # React client entrypoint
│   ├── package.json        # Frontend dependencies and scripts
│   ├── tailwind.config.js  # Tailwind CSS configuration
│   └── vite.config.ts      # Vite build configuration
├── migrations/             # Alembic database migration scripts
│   ├── versions/           # Versioned migration revision files
│   └── env.py              # Alembic async migration environment
├── ml/                     # Machine Learning engine
│   ├── datasets/           # ML dataset processing scripts
│   ├── evaluation/         # Model evaluation, benchmark, adversarial testing
│   ├── experiments/        # MLflow SQLite database and artifacts
│   ├── feature_store/      # Parquet feature tables and splits
│   ├── features/           # Feature extraction sub-modules
│   │   ├── catalog.py      # Feature definitions and documentation
│   │   ├── entropy.py      # Shannon entropy calculation
│   │   ├── extractor.py    # Unified FeatureExtractor façade
│   │   ├── keywords.py     # Suspicious keyword frequency features
│   │   ├── lexical.py      # URL character and lexical features
│   │   ├── pipeline.py     # Batch feature extraction engine
│   │   ├── statistical.py  # Statistical and character ratio features
│   │   ├── structural.py   # URL path, query, and domain structure features
│   │   └── validator.py    # Feature matrix schema validator
│   ├── models/             # Model definitions and trained weights
│   │   ├── base.py         # BaseModel abstract class
│   │   ├── calibrate.py    # Probability calibration (Platt/Isotonic)
│   │   ├── logistic.py     # Logistic Regression wrapper
│   │   ├── random_forest.py# Random Forest classifier wrapper
│   │   ├── store/          # Pickled model binaries and registry.json
│   │   ├── thresholds.py   # Precision/Recall threshold tuning
│   │   ├── tuner.py        # Optuna Bayesian hyperparameter search
│   │   └── xgboost_model.py# XGBoost classifier wrapper
│   ├── pipelines/          # Training and MLOps automation pipelines
│   │   └── retrain.py      # Autonomous retraining & champion benchmark
│   ├── schema/             # Canonical feature schemas
│   │   └── feature_schema.json # 59-feature list and dropped features
│   └── tracking/           # MLflow tracking and TreeSHAP analysis
│       ├── mlflow_manager.py # ExperimentManager wrapper
│       └── shap_analyzer.py  # Global and local TreeSHAP computation
├── notebooks/              # Jupyter exploratory data analysis notebooks
├── reports/                # Model evaluation and EDA generated reports
├── scripts/                # [EMPTY] Root utility scripts placeholder
├── src/                    # Legacy data ingestion and shared helpers
│   ├── config.py           # Shared cross-platform filesystem paths
│   ├── data/               # Data cleaning, inspection, and merging scripts
│   │   ├── clean.py        # Raw dataset cleaning script
│   │   ├── inspect.py      # Dataset inspection utilities
│   │   ├── merge.py        # Dataset merger script
│   │   ├── normalize.py    # URL normalization utilities
│   │   └── validate.py     # Dataset validation rules
│   └── utils/              # Shared utilities
│       └── logger.py       # Structured logging setup
└── tests/                  # Pytest test suite
    ├── conftest.py         # Shared pytest fixtures (URLs, extractor)
    ├── unit/               # Unit tests (features, extractor, retrain)
    ├── integration/        # [EMPTY] Integration tests placeholder
    └── e2e/                # [EMPTY] End-to-end tests placeholder
```

## Directory Purposes

**`backend/`:**
- Purpose: Houses the FastAPI REST microservice, API routes, database models, and service business logic.
- Contains: Python modules organized by layer (`api/`, `core/`, `database/`, `schemas/`, `services/`).
- Key files: `backend/main.py`, `backend/core/config.py`, `backend/services/threat_intel.py`, `backend/services/prediction.py`.

**`ml/`:**
- Purpose: Contains the machine learning architecture including feature engineering, model wrappers, training pipelines, evaluation, and artifact stores.
- Contains: Feature extraction algorithms, trained `.pkl` binaries, Parquet feature tables, and MLflow tracking.
- Key files: `ml/features/extractor.py`, `ml/models/xgboost_model.py`, `ml/pipelines/retrain.py`, `ml/models/store/registry.json`.

**`frontend/`:**
- Purpose: Single-page application dashboard built with React 19, Vite, and TailwindCSS.
- Contains: TypeScript components, pages for URL scanning and threat analytics, and API clients.
- Key files: `frontend/src/main.tsx`, `frontend/src/pages/Scan.tsx`, `frontend/src/pages/Dashboard.tsx`, `frontend/src/services/scan.ts`.

**`extension/`:**
- Purpose: Chrome Extension (Manifest V3) for passive real-time URL threat classification as users navigate.
- Contains: Service worker script, popup UI, sidepanel, content script, and build scripts.
- Key files: `extension/manifest.json`, `extension/background/service-worker.js`, `extension/popup/popup.html`.

**`src/`:**
- Purpose: Shared utility layer and legacy data processing scripts.
- Contains: Cross-platform directory constants (`src/config.py`), dataset cleaning pipelines (`src/data/`), and logger (`src/utils/logger.py`).
- Key files: `src/config.py`, `src/utils/logger.py`, `src/data/clean.py`.

**`tests/`:**
- Purpose: Comprehensive automated test suite executed by Pytest in CI/CD.
- Contains: Fixtures, unit tests for feature extraction and retraining pipeline.
- Key files: `tests/conftest.py`, `tests/unit/test_extractor.py`, `tests/unit/test_retrain.py`.

## Key File Locations

**Entry Points:**
- `backend/main.py`: Primary FastAPI application entrypoint.
- `frontend/src/main.tsx`: Web client dashboard entrypoint.
- `extension/background/service-worker.js`: Browser extension background daemon.
- `ml/features/pipeline.py`: Batch data processing entrypoint.

**Configuration:**
- `backend/core/config.py`: Application runtime settings loaded from `.env`.
- `configs/model_config.yaml`: Cascade probability threshold configuration.
- `configs/training.yaml`: Dataset split ratios and hyperparameter ranges.
- `ml/schema/feature_schema.json`: Master definition of the 59 canonical feature inputs.

**Core Logic:**
- `backend/services/threat_intel.py`: Threat intelligence waterfall engine.
- `backend/services/prediction.py`: Model loader and cascade prediction evaluator.
- `ml/features/extractor.py`: Unified URL feature extractor.
- `ml/pipelines/retrain.py`: Continuous MLOps autonomous retraining pipeline.

**Testing:**
- `tests/conftest.py`: Shared test fixtures and sample URLs.
- `tests/unit/test_retrain.py`: Tests for active learning and model promotion.
- `tests/unit/test_extractor.py`: Tests for URL feature extraction precision.

## Naming Conventions

**Files:**
- Python: `snake_case.py` (e.g., `threat_intel.py`, `xgboost_model.py`).
- TypeScript/React Components: `PascalCase.tsx` (e.g., `Scan.tsx`, `Dashboard.tsx`).
- TypeScript Utilities: `camelCase.ts` or `kebab-case.ts` (e.g., `api.ts`, `service-worker.js`).
- Configuration: `lowercase.yaml`, `lowercase.json` (e.g., `training.yaml`, `registry.json`).

**Directories:**
- Python & General: `snake_case/` or `lowercase/` (e.g., `threat_intel/`, `feature_store/`).
- Frontend Component Folders: `camelCase/` or `lowercase/` (e.g., `components/`, `routes/`).

## Where to Add New Code

**New Feature (Backend API):**
- Router: Create endpoint in `backend/api/routers/<feature>.py` and register in `backend/main.py`.
- Schema: Define Pydantic models in `backend/schemas/<feature>.py`.
- Business Logic: Implement service class in `backend/services/<feature>.py`.
- Tests: Add integration and unit tests in `tests/unit/` and `backend/tests/`.

**New ML Feature (Extraction):**
- Implement calculation in the appropriate module under `ml/features/` (`lexical.py`, `structural.py`, etc.).
- Update `ml/features/extractor.py` and register column name in `ml/schema/feature_schema.json`.
- Add unit tests verifying calculation against known malicious and benign URLs in `tests/unit/`.

**New Frontend Page / View:**
- Add component in `frontend/src/pages/<PageName>.tsx`.
- Register route in `frontend/src/routes/AppRouter.tsx`.
- Add API communication methods to `frontend/src/services/`.

## Special Directories

**`backend/app/`:**
- Purpose: Leftover scaffolding directory hierarchy (`api/`, `core/`, `db/`, `models/`, `schemas/`, `services/`, `utils/`).
- Generated: No (committed manually).
- Status: Dead code / empty directories. Should be pruned.

**`ml/models/store/`:**
- Purpose: Stores binary serialized model weights (`.pkl`) and `registry.json`.
- Generated: Yes, created/updated by training scripts and retraining pipeline.
- Committed: Yes, active champion models are committed to VCS for direct inference.

**`datasets/` & `ml/feature_store/`:**
- Purpose: Stores CSV source data and Parquet feature tables.
- Generated: Yes, generated by `src/data/` and `ml/features/pipeline.py`.
- Committed: Partial (splits and small samples committed; large raw datasets ignored).

---

*Structure analysis: 2026-09-10*
