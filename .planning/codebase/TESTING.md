# Testing Patterns

**Analysis Date:** 2026-09-10

## Test Framework

**Runner:**
- Python: `pytest` 8.x + `pytest-asyncio` (`requirements.txt`)
- Config: `pytest.ini` at project root
- Frontend: `vitest` 2.1.1 (`frontend/package.json`)

**Assertion Library:**
- Python: Standard `assert` statements enriched by pytest introspective reporting
- Frontend: Vitest built-in assertions (`expect`)

**Run Commands:**
```bash
# Run all Python backend & ML tests
pytest

# Run with verbose output and short tracebacks (default in pytest.ini)
pytest -v --tb=short

# Run a specific test suite
pytest tests/unit/test_retrain.py -v

# Run frontend tests (vitest configured to pass with no tests currently)
cd frontend && npx vitest run --passWithNoTests
```

## Test File Organization

**Location:**
- Separate root `tests/` directory:
  - `tests/conftest.py`: Root fixtures for shared URL lists and feature extractors
  - `tests/unit/`: Active unit tests for feature extractors and retraining loops
  - `tests/integration/`: Integration test placeholder (`.gitkeep` only)
  - `tests/e2e/`: End-to-end test placeholder (`.gitkeep` only)
  - `backend/tests/`: Backend endpoint test placeholder (`.gitkeep` only)

**Naming:**
- Python test files: `test_<module_name>.py` (e.g., `test_extractor.py`, `test_retrain.py`, `test_lexical.py`).
- Test functions: `test_<functionality>_<expected_outcome>()` (e.g., `test_verify_sample_label_hit()`, `test_build_zero_day_dataset_empty()`).

**Structure:**
```text
tests/
├── conftest.py              # Session-scoped shared fixtures
├── unit/
│   ├── test_edge_cases.py   # Malformed URLs, internationalized domains (punycode)
│   ├── test_extractor.py    # Master FeatureExtractor output format and schema
│   ├── test_keywords.py     # Suspicious brand/action keyword detection tests
│   ├── test_lexical.py      # Character counting and lexical ratio tests
│   ├── test_retrain.py      # ActiveLearningService & retraining pipeline tests
│   ├── test_statistical.py  # Entropy, vowel, and symbol ratio tests
│   └── test_structural.py   # Domain, path, and port structural tests
├── integration/             # [EMPTY - Gaps identified]
└── e2e/                     # [EMPTY - Gaps identified]
```

## Test Structure

**Suite Organization Example:**
```python
"""
tests/unit/test_retrain.py
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pandas as pd
from backend.services.learning import ActiveLearningService

def test_verify_sample_label_hit():
    """Verify ground-truth labeling returns threat prediction when threat intel hits."""
    async def _test():
        service = ActiveLearningService()
        mock_hit = {"prediction": "phishing", "confidence": 0.99, "reason": "test", "source": "phishtank"}
        with patch("backend.services.learning.threat_intel_service.check_url", AsyncMock(return_value=mock_hit)):
            label = await service.verify_sample_label("http://phish.com", "phishing")
            assert label == "phishing"

    asyncio.run(_test())
```

**Patterns:**
- Async testing pattern: Wrapped helper functions executed via `asyncio.run(_test())` or `@pytest.mark.asyncio`.
- Setup/Teardown: Handled via pytest fixtures (`tmp_path` for temporary files, session fixtures for immutable extractors).

## Mocking

**Framework:**
- Standard library `unittest.mock` (`AsyncMock`, `MagicMock`, `patch`).

**Patterns:**
- Mocking asynchronous database sessions:
```python
mock_db = AsyncMock(spec=AsyncSession)
mock_res = MagicMock()
mock_res.scalars.return_value.all.return_value = [sample_scan]
mock_db.execute.return_value = mock_res
```
- Mocking external HTTP threat intelligence services:
```python
with patch("backend.services.learning.threat_intel_service.check_url", AsyncMock(return_value=mock_hit)):
    label = await service.verify_sample_label(url, prediction)
```

**What to Mock:**
- External network requests (VirusTotal API, PhishTank remote downloads).
- Database calls when testing isolated business logic units.
- MLflow remote tracking servers.

**What NOT to Mock:**
- Feature extraction calculations (`FeatureExtractor` should always execute against real URL strings).
- Pydantic schema validation.
- Model serialization format verification.

## Fixtures and Factories

**Test Data (`tests/conftest.py`):**
```python
@pytest.fixture(scope="session")
def phishing_urls() -> list[str]:
    return [
        "http://paypal-login.evil.com/verify?id=123&token=abc",
        "https://secure-login.bankofamerica.com.ru/signin/verify",
        "http://192.168.1.1/login?user=admin&pass=1234",
        "http://xn--pypal-4ve.com/update/account",
        "http://malware.download.win/payload.exe",
    ]

@pytest.fixture(scope="session")
def legitimate_urls() -> list[str]:
    return [
        "https://www.google.com",
        "https://www.github.com/openai/gpt-4",
        "https://stackoverflow.com/questions/1234567",
        "http://example.com",
    ]
```

## Coverage

**Requirements:**
- No strict minimum coverage threshold enforced in CI yet.
- Coverage can be inspected manually via:
```bash
pytest --cov=backend --cov=ml tests/
```

## Test Types

**Unit Tests:**
- Heavy focus on URL feature extraction logic (`ml/features/`) and active learning verification logic (`backend/services/learning.py`).
- Fast execution (< 5 seconds total for all unit tests).

**Integration Tests:**
- **Current Status: GAP.** `tests/integration/` is empty (`.gitkeep`).
- Needs tests for FastAPI endpoints (`TestClient`/`httpx.AsyncClient`) exercising the full route from `/v1/scan` to database commit.

**E2E Tests:**
- **Current Status: GAP.** `tests/e2e/` is empty (`.gitkeep`).
- Extension and dashboard automated UI testing is currently manual.

---

*Testing analysis: 2026-09-10*
