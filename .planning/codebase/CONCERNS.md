# Codebase Concerns

**Analysis Date:** 2026-09-10

## Tech Debt

**API Contract Discrepancies between Frontend and Backend:**
- Issue: `frontend/src/services/scan.ts` references endpoints that do not exist in the backend FastAPI application:
  - `GET /v2/report/${scanId}` (`scanService.getReport`) — Backend only exposes `/v1/` routes and has no `/v2/report/` handler.
  - `DELETE /v1/history/${id}` (`scanService.deleteHistoryItem`) — Backend `backend/api/routers/history.py` only implements `GET /v1/history` and `GET /v1/history/{scan_id}`.
- Files: `frontend/src/services/scan.ts`, `backend/api/routers/history.py`, `backend/main.py`.
- Impact: Calling report details or deleting history from the frontend will result in 404 Not Found HTTP errors.
- Fix approach: Implement `DELETE /v1/history/{scan_id}` and resolve the report endpoint contract or remove unused methods from `scanService`.

**Dead Scaffolding Hierarchy (`backend/app/`):**
- Issue: An empty directory structure `backend/app/{api,core,db,models,schemas,services,utils}` exists at the root of `backend/`. Active production code is housed under `backend/{api,core,database,schemas,services}/`.
- Files: `backend/app/**`
- Impact: Misleads developers into believing code is missing or split across parallel trees; risks import confusion.
- Fix approach: Safely delete the `backend/app/` directory tree.

**Static Uncalibrated Model Path in ExplainerService:**
- Issue: `backend/services/explainer.py:21` hardcodes:
  ```python
  uncalibrated_path = MODEL_DIR / "xgboost_optuna_best.pkl"
  ```
  instead of resolving through `settings.MODEL_PATH` or reading `ml/models/store/registry.json`.
- Files: `backend/services/explainer.py`.
- Impact: When autonomous retraining promotes a new candidate model to production, the `PredictionService` hot-reloads the new model weights, but `ExplainerService` continues computing SHAP attributions against the static initial model, causing an attribution/prediction mismatch.
- Fix approach: Update `ExplainerService` to dynamically load the uncalibrated counterpart of the active champion model.

## Known Bugs

**Async Event Loop Blocking During TreeSHAP / XGBoost Inference:**
- Symptoms: Latency spikes on concurrent API requests.
- Files: `backend/api/routers/scan.py:134`, `backend/services/prediction.py:55`.
- Trigger: Multiple concurrent requests triggering ML inference simultaneously on a single Uvicorn worker process.
- Workaround: Run Uvicorn with multiple worker processes (`--workers 4`) or run CPU-bound feature extraction and model inference via `asyncio.to_thread()`.

## Security Considerations

**Unpinned Python Dependencies:**
- Risk: `requirements.txt` does not pin exact library versions (e.g. `fastapi`, `xgboost`, `scikit-learn`, `pydantic`). Upstream major version releases could silently break builds or introduce vulnerabilities.
- Files: `requirements.txt`.
- Current mitigation: None in repo; CI installs latest available matching packages.
- Recommendations: Generate and maintain a pinned `requirements.lock` or migrate to a lockfile-backed package manager (like `uv` or `pip-tools`).

**CORS Wildcard Policy:**
- Risk: `backend/main.py:78` sets `allow_origins=["*"]` with `allow_credentials=True`.
- Files: `backend/main.py`.
- Current mitigation: Standard JWT headers required for protected routes.
- Recommendations: Restrict allowed origins to specific trusted domains and the browser extension ID in production.

**Default Insecure Secret Key:**
- Risk: `backend/core/config.py` defaults to `SECRET_KEY = "changeme-use-a-long-random-secret-in-production"`.
- Files: `backend/core/config.py`, `docker-compose.yml`.
- Current mitigation: `.env.example` warns users to generate a random key.
- Recommendations: Raise an application startup error in `backend/main.py` lifespan if `ENVIRONMENT == "production"` and `SECRET_KEY` matches the default placeholder.

## Performance Bottlenecks

**Feature Extraction Iteration in Batch Pipeline:**
- Problem: Extracting features row-by-row on 2.77M rows in `ml/features/pipeline.py` takes considerable time.
- Files: `ml/features/pipeline.py`.
- Cause: Uses Python `DataFrame.apply()` across complex string and regex operations rather than vectorized Cython or native C implementations.
- Improvement path: Leverage multiprocessing worker pools (`concurrent.futures.ProcessPoolExecutor`) or Polars.

**PhishTank In-Memory Full Feed Downloads:**
- Problem: Downloading and parsing the complete PhishTank JSON feed (`online-valid.json`) on hydration blocks memory and can be slow.
- Files: `backend/services/threat_intel.py:180`.
- Cause: Downloads whole multi-megabyte JSON payload into RAM.
- Improvement path: Stream parser or disk-backed SQLite lookup index.

## Fragile Areas

**Large Binary Model Files in Git:**
- Files: `ml/models/store/*.pkl` (e.g. `random_forest_v1.pkl` is ~83MB, `xgboost_calibrated.pkl` is ~18MB).
- Why fragile: Bloats Git repository history; approaching GitHub file size warnings (100MB limit).
- Safe modification: Use Git LFS or an external artifact storage bucket (S3/GCS or dedicated MLflow artifact store).
- Test coverage: Gaps in verifying binary pickle compatibility across differing scikit-learn / XGBoost minor versions.

**Pickle Deserialization:**
- Files: `backend/services/prediction.py`, `backend/services/explainer.py`, `ml/pipelines/retrain.py`.
- Why fragile: `pickle.load()` is vulnerable to arbitrary code execution if untrusted model files are introduced to the store.
- Safe modification: Validate model hashes before loading or export models to ONNX / Treelite / SafeTensors.

## Scaling Limits

**SQLite Default Persistence:**
- Current capacity: Single-file database (`backend.db`) using `aiosqlite`.
- Limit: File-lock concurrency bottlenecks under high write volume (e.g. continuous scan logging).
- Scaling path: Switch to PostgreSQL (already supported in `docker-compose.yml` and `backend/database/session.py` via `DATABASE_URL`).

**Zero-Day Retraining Data Threshold:**
- Current capacity: Fixed threshold `RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD = 50`.
- Limit: Retraining triggered frequently under heavy scan volume could saturate server resources.
- Scaling path: Decouple retraining into an external Celery/Argo workflow running on dedicated compute.

## Dependencies at Risk

**`python-jose`:**
- Risk: `python-jose` has seen minimal recent maintenance and can conflict with newer cryptographic backend versions.
- Impact: Potential future deprecation warnings or compatibility issues with Python 3.12+.
- Migration plan: Migrate to `PyJWT` with cryptography backend.

**`passlib`:**
- Risk: `passlib` has not had a release in several years and produces internal deprecation warnings with `bcrypt` 4.0+.
- Impact: Potential breakage on future Python / bcrypt upgrades.
- Migration plan: Use `bcrypt` directly or migrate to `pwdlib`.

## Missing Critical Features

**Missing Endpoint Implementations in Backend:**
- Problem: `DELETE /v1/history/{id}` and `/v2/report/{id}` are missing in backend, despite frontend calls.
- Blocks: History item deletion from dashboard and detailed scan reports.

**Automated Frontend & Extension Test Suites:**
- Problem: Zero test files in `frontend/` or `extension/`.
- Blocks: Automated regression verification for UI and extension before releases.

## Test Coverage Gaps

**API Router Integration Tests:**
- What's not tested: HTTP requests to `/v1/scan`, `/v1/auth/register`, `/v1/auth/login`, `/v1/explain`, `/v1/history`, `/v1/mlops/retrain`.
- Files: `backend/api/routers/*.py`, `tests/integration/` (currently empty).
- Risk: Regressions in authentication headers, payload validation, or database transactions go undetected in CI.
- Priority: High.

**Threat Intelligence Fallback and Timeout Handling:**
- What's not tested: Real network timeout and rate limit scenarios in VirusTotal and PhishTank integrations.
- Files: `backend/services/threat_intel.py`.
- Risk: Unhandled HTTP errors could degrade user scan response times.
- Priority: Medium.

---

*Concerns audit: 2026-09-10*
