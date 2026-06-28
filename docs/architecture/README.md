# System Architecture

The AI Cyber Security Suite is a modular, event-driven ecosystem composed of three major pillars: the Backend, the Frontend, and the Browser Extension.

## 1. FastAPI Backend
The core of the system is a Python 3.10+ FastAPI application.
- **Routing**: Separated via `APIRouter` into domain-specific endpoints (`/scan`, `/auth`, `/history`, etc.).
- **Dependency Injection**: Uses FastAPI's `Depends` for authentication (JWT), database sessions (SQLAlchemy async), and Machine Learning models (singleton instances).
- **Rate Limiting**: Integrated with `SlowAPI` to prevent DoS on the CPU-heavy ML inference layers.
- **Database**: SQLite (async) via SQLAlchemy and Alembic for migrations.
- **Logging**: `Structlog` provides structured JSON logging with correlation IDs.

## 2. Machine Learning Pipeline
- **Heuristic Engine (`threat_intel.py`)**: Runs before ML inference. Uses a fast O(1) allowlist (Rule 0) for domains like `google.com` to prevent false positives and bypass heavy ML processing, reducing latency to < 2ms.
- **XGBoost Inference**: URLs not caught by heuristics are vectorized (TF-IDF + structural features) and passed to a pre-trained XGBoost model.
- **SHAP Explainability**: A BackgroundTask computes SHAP attributions *after* the scan request completes, allowing for ultra-fast primary latency while delivering Deep Explainability asynchronously.

## 3. Browser Extension (Manifest V3)
- **Service Worker (`service-worker.ts`)**: Orchestrates the scanning flow. Listens to `chrome.tabs.onUpdated` and `onActivated`. Manages an in-flight request tracker to prevent duplicate concurrent scans.
- **Local Cache**: Caches recent scan results in `chrome.storage.local` with a TTL to prevent hammering the backend when switching tabs.
- **Popup UI**: Reacts to `chrome.storage.onChanged` to paint the Safe/Risk/Offline UI without blocking the main browser thread.

## 4. React Dashboard
- Built with React 18, Vite, and TailwindCSS.
- Exposes user authentication, aggregated historical scan data (via Recharts), and a direct manual URL scanning interface.
