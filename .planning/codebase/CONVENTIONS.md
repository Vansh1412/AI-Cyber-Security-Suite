# Coding Conventions

**Analysis Date:** 2026-09-10

## Naming Patterns

**Files:**
- Python: `snake_case.py` (e.g., `prediction.py`, `threat_intel.py`, `test_retrain.py`).
- TypeScript (React Components): `PascalCase.tsx` (e.g., `Dashboard.tsx`, `Scan.tsx`, `AppRouter.tsx`).
- TypeScript (Services & Utilities): `camelCase.ts` or `kebab-case.ts` (e.g., `api.ts`, `scan.ts`, `service-worker.js`).
- Test Files: `test_<module>.py` in Python; `*.test.ts` / `*.spec.ts` in TypeScript.

**Functions:**
- Python: `snake_case()` (e.g., `verify_sample_label()`, `extract_features()`, `run_retraining_pipeline()`). Private helper functions start with an underscore `_` (e.g., `_normalise_url()`, `_compute_shap_and_store()`).
- TypeScript: `camelCase()` (e.g., `scanUrl()`, `getReport()`, `handleScan()`).

**Variables:**
- Python: `snake_case` for local variables and instances (e.g., `feature_vector`, `predicted_class`, `cache_service`).
- Constants / Globals: `UPPER_SNAKE_CASE` (e.g., `LOCAL_BLACKLIST`, `TRUSTED_DOMAINS`, `API_V1_STR`, `TRAINING_CONFIG`).
- TypeScript: `camelCase` for variables and object keys; `UPPER_SNAKE_CASE` for global configuration constants.

**Types & Classes:**
- Python: `PascalCase` for classes, Pydantic schemas, and SQLAlchemy models (e.g., `FeatureExtractor`, `PredictionService`, `ScanResult`, `User`, `ScanRequest`, `ScanResponse`).
- TypeScript: `PascalCase` for interfaces and type aliases (e.g., `ScanResult`, `HistoryItem`, `StatsResponse`, `FullReport`).

## Code Style

**Formatting:**
- Python: Managed via Ruff (`pyproject.toml`) targeting Python 3.10 syntax (`target-version = "py310"`).
- Line Length: 100 characters (`line-length = 100`).
- Quotes: Double quotes preferred in Python files, single quotes in TypeScript files.

**Linting:**
- Python: Ruff configured with selected rules:
  - `E`, `F`: Pyflakes & pycodestyle standard rules.
  - `I`: isort import sorting rules.
  - `UP`: Pyupgrade (modern Python 3.10+ typing/syntax).
  - `B`: flake8-bugbear (common bug patterns).
  - `BLE`: flake8-blind-except.
  - `SIM`: flake8-simplify.
  - `PLC`: Pylint conventions.
- Explicit Ruff Ignored Rules (`pyproject.toml`):
  - `B008`: Allows FastAPI dependency injection default arguments (`Depends(...)`).
  - `BLE001`: Allows broad exception catches in top-level error-handling middlewares and resilient background services.
  - `E501`: Line length violations (delegated to Ruff formatter).
  - `PLC0415`: Deferred/lazy imports inside functions to avoid circular import issues.
  - `B904`: Exception chaining syntax inside `except` blocks.
- TypeScript / Frontend: ESLint 9 (`frontend/eslint.config.js`) with `@eslint/js`, `typescript-eslint`, and React hooks plugins.

## Import Organization

**Python Order:**
1. Standard library imports (e.g., `from __future__ import annotations`, `import json`, `import time`, `from pathlib import Path`).
2. Third-party packages (e.g., `fastapi`, `pydantic`, `sqlalchemy`, `pandas`, `xgboost`, `shap`).
3. Local application first-party imports (`known-first-party = ["backend", "src", "ml"]`):
   - `from backend.core.config import settings`
   - `from backend.database.models import ScanResult`
   - `from src.utils.logger import logger`

**Import Directives:**
- `from __future__ import annotations` is placed at the very top of modern backend Python files for clean type union syntax (`int | None`).
- Combined `isort` imports: `combine-as-imports = true`.

**Path Aliases:**
- Frontend: `@/*` resolves to `frontend/src/*` configured via `vite.config.ts` and `tsconfig.json`.

## Error Handling

**Patterns:**
- **Custom HTTP Exceptions:** Route handlers validate inputs and raise explicit `HTTPException(status_code=..., detail=...)`.
- **Defensive Fallback & Degradation:**
  - Network and external service integrations (Redis, VirusTotal, PhishTank) wrap operations in `try/except` and catch exceptions gracefully, logging a warning rather than crashing.
  - If Redis is unreachable, `cache_service` sets `self._client = None` and silently returns `None` for all reads and writes.
  - If a model file is missing or corrupted, `PredictionService` raises a descriptive `RuntimeError`.
- **Global Error Handler:** `general_exception_handler` in `backend/core/exceptions.py` catches uncaught errors and returns standardized JSON `{ "detail": "Internal server error" }` with 500 status.

## Logging

**Framework:**
- Structured logging using `structlog` and Python's built-in `logging` wrapper (`src/utils/logger.py`).
- Imported consistently as:
  ```python
  from src.utils.logger import logger
  ```

**Patterns:**
- Use parameterized formatting rather than string concatenation:
  ```python
  logger.info("PredictionService: Loaded model '%s' from %s", self.wrapper.name, settings.MODEL_PATH.name)
  logger.warning("Failed to load thresholds, falling back to argmax: %s", exc)
  logger.error("Retraining failed: %s", exc)
  ```
- Startup / Lifespan banners use explicit section headers:
  ```python
  logger.info("=" * 60)
  logger.info("Starting Autonomous Retraining Loop")
  logger.info("=" * 60)
  ```

## Comments

**When to Comment:**
- File headers with multi-line docstrings detailing module purpose, design rationale, and public APIs.
- Header dividers using unicode box-drawing characters (e.g., `# ── 1. Load source data ───────`).
- Complex algorithms (e.g., cascade threshold ordering in `PredictionService`, ground-truth verification rules in `ActiveLearningService`).
- Explain why specific exceptions are suppressed (`# noqa: BLE001`).

**Docstrings:**
- Google / NumPy style docstrings for classes and critical functions specifying `Parameters`, `Returns`, and `Design`.

## Function Design

**Size:**
- Targeted and single-purpose (< 50 lines typical). Longer batch processing pipelines use sequentially organized private helper methods.

**Parameters:**
- Explicit type annotations on all parameters (`url: str`, `db: AsyncSession`, `limit: int = 1000`).
- Keyword-only or default arguments for optional flags (`force_promotion: bool = False`).

**Return Values:**
- Strictly typed return signatures (`-> tuple[str, float]`, `-> ScanResponse`, `-> None`).

## Module Design

**Exports:**
- Services define module-level singletons where appropriate (e.g., `cache_service = CacheService()`, `threat_intel_service = ThreatIntelService()`, `learning_service = ActiveLearningService()`).
- Single-point façade exports: `ml/features/extractor.py` provides `FeatureExtractor` as the single public API hiding the 4 underlying feature submodules.

**Barrel Files:**
- Used in `backend/api/routers/__init__.py` and `ml/features/__init__.py` to re-export clean namespaces for external callers.

---

*Convention analysis: 2026-09-10*
