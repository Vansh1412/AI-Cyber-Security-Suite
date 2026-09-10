# External Integrations

**Analysis Date:** 2026-09-10

## APIs & External Services

**Threat Intelligence Services:**
- **VirusTotal API v3:** Used for third-party reputation lookups and malicious vendor consensus checking during the Threat Intel waterfall (`backend/services/threat_intel.py`).
  - SDK/Client: `httpx.AsyncClient` (`https://www.virustotal.com/api/v3/urls/{url_id}`)
  - Auth: `VIRUSTOTAL_API_KEY` (Header `x-apikey: <key>`)
  - Behavior: Evaluates malicious engines against `VIRUSTOTAL_MALICIOUS_THRESHOLD` (default: 3 engines). Times out after 5.0s (`VIRUSTOTAL_TIMEOUT_S`) and fails open to allow ML inference to proceed.
- **PhishTank:** Public community phishing database downloaded and cached locally for rapid URL matching (`backend/services/threat_intel.py`).
  - SDK/Client: `httpx.AsyncClient` (`http://data.phishtank.com/data/online-valid.json`)
  - Auth: `PHISHTANK_API_KEY` (optional query parameter `app_key`)
  - Refresh Rate: Hydrated every 12 hours (`PHISHTANK_REFRESH_INTERVAL_S = 43200`) into an in-memory set.

## Data Storage

**Databases:**
- **PostgreSQL / SQLite:** Multi-environment relational database handled via SQLAlchemy Async (`backend/database/models.py`, `backend/database/session.py`).
  - Primary Production: PostgreSQL 16 (in Docker: `postgresql+asyncpg://postgres:postgres@db:5432/cybersec`).
  - Default Local Dev: SQLite 3 via `aiosqlite` (`sqlite+aiosqlite:///./backend.db`).
  - Connection: `DATABASE_URL` env variable.
  - Client: SQLAlchemy 2.0 with async engine `create_async_engine(settings.DATABASE_URL, echo=False)`.
  - Migrations: Alembic (`alembic.ini`, `migrations/`). Auto-creates SQLite tables on startup in `backend/main.py` lifespan.
- **MLflow Tracking Database:** SQLite backend for experiment metadata and metrics (`ml/experiments/mlflow.db`).
  - Connection: `MLFLOW_TRACKING_URI = "sqlite:///.../ml/experiments/mlflow.db"`.

**File Storage:**
- **Local Filesystem Only:**
  - Parquet feature store files in `ml/feature_store/` (`features_v1.parquet`, `features_train_100k.parquet`, splits in `ml/feature_store/splits/`).
  - Pickled model artifacts in `ml/models/store/` (`xgboost_calibrated.pkl`, `random_forest_v1.pkl`, `logistic_regression_v1.pkl`, `registry.json`).
  - Pre-built Chrome extension distribution files in `extension/dist/` streamed on demand via `backend/api/routers/download.py`.

**Caching:**
- **Redis 7 (Async):**
  - Service: `redis[asyncio]` via `aioredis.from_url` in `backend/services/cache.py`.
  - Connection: `REDIS_URL` (default `redis://localhost:6379/0`).
  - TTL: Configurable via `CACHE_TTL_SECONDS` (default: 3600 seconds / 1 hour).
  - Key Schema: `scan:v1:{sha256(url)[:16]}`.
  - Fallback: Gracefully catches connection failures; if Redis is down or disconnected, API falls back to uncached execution without errors.
- **Browser Local Cache:**
  - `chrome.storage.local` within the extension background service worker (`extension/background/service-worker.js`).
  - Keyed by normalized URL with local timestamp expiration to achieve < 2ms latency for repeated visits.

## Authentication & Identity

**Auth Provider:**
- Custom JWT-based Authentication (`backend/core/security.py`, `backend/api/routers/auth.py`):
  - Tokens: JSON Web Tokens signed with HMAC-SHA256 (`HS256`) via `python-jose`.
  - Password Hashing: Bcrypt with automatic salt via `passlib.context.CryptContext(schemes=["bcrypt"])`.
  - Expiry: Configurable via `ACCESS_TOKEN_EXPIRE_MINUTES` (default 60 min, recommended 1440 min in `.env.example`).
  - Roles: Role-based access control with `user` and `admin` levels in `backend/database/models.py`. Admins bypass scan rate limiting (`backend/api/routers/scan.py`).

## Monitoring & Observability

**Error Tracking & Logs:**
- Structured logging using `structlog` and standard library `logging` wrapper (`src/utils/logger.py`).
- Traceability via `CorrelationIdMiddleware` (`asgi-correlation-id`) attaching `X-Request-ID` to all HTTP responses.
- Timing metrics via custom `TimingMiddleware` (`backend/api/middleware.py`) exposing `X-Process-Time` headers.

**Metrics:**
- Prometheus integration via `prometheus-fastapi-instrumentator` exposing `/metrics` (`backend/main.py`).
- OpenTelemetry instrumentation via `opentelemetry-instrumentation-fastapi` (`FastAPIInstrumentor.instrument_app(app)`).

## CI/CD & Deployment

**Hosting:**
- Containerized deployment using Docker Compose (`docker-compose.yml`) containing:
  - `api`: FastAPI Python container on port 8000
  - `db`: PostgreSQL 16 Alpine on port 5432 with health check
  - `redis`: Redis 7 Alpine on port 6379 with health check
  - `prometheus`: Prometheus container on port 9090 reading `docker/prometheus.yml`

**CI Pipeline:**
- GitHub Actions workflow (`.github/workflows/ci.yml`):
  - Triggers on push to `main`, `develop` and PRs to `main`.
  - `backend-tests`: Installs Python 3.11, installs `requirements.txt`, executes `pytest ../tests/ -v`.
  - `frontend-tests`: Sets up Node.js 20, runs `npm ci`, and executes `npx vitest run --passWithNoTests`.
  - `lint`: Runs `ruff check backend/` and `npm run lint` in `frontend/`.

## Environment Configuration

**Required env vars:**
- `SECRET_KEY`: Secret string for signing JWT tokens (production blocker if unchanged).
- `DATABASE_URL`: Connection string for PostgreSQL or SQLite (`sqlite+aiosqlite:///./backend.db`).
- `REDIS_URL`: Connection string for Redis instance (`redis://localhost:6379/0`).

**Optional threat intelligence vars:**
- `VIRUSTOTAL_API_KEY`: API token for VirusTotal v3 URL lookups.
- `PHISHTANK_API_KEY`: API key for PhishTank authenticated access.
- `VITE_API_URL`: Exposed to frontend client (default: `http://localhost:8000`).

**Secrets location:**
- Stored locally in `.env` (ignored in `.gitignore`).
- Documented in template `.env.example`.

## Webhooks & Callbacks

**Incoming:**
- None currently configured in backend.

**Outgoing:**
- None configured (autonomous retraining hot-reloads model in-process via `PredictionService.reload_model()` rather than firing external webhooks).

---

*Integration audit: 2026-09-10*
