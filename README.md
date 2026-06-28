<h1 align="center">
  🛡️ AI Cyber Security Suite
</h1>

<p align="center">
  <strong>Real-time AI-powered URL threat detection for the modern web.</strong><br/>
  XGBoost classification · SHAP explainability · Browser extension · FastAPI backend · React dashboard
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-yellow?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
</p>

---

## 📸 Preview

| Extension Popup | Dashboard Analytics | Threat Report |
|:---:|:---:|:---:|
| ![Extension](docs/diagrams/extension-preview.png) | ![Dashboard](docs/diagrams/dashboard-preview.png) | ![Report](docs/diagrams/report-preview.png) |

> **Replace these placeholders** with real screenshots before publishing.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Real-time Scanning** | Scans every URL you visit via the Chrome extension in < 15ms |
| 🤖 **XGBoost Classifier** | 97%+ accuracy across phishing, malware, defacement, and legitimate classes |
| 🧠 **SHAP Explainability** | Explains *why* a URL was flagged using TreeSHAP feature attributions |
| 🛡️ **Threat Intel Waterfall** | Heuristic engine + local blacklist before expensive ML — no false positives on major domains |
| ⚡ **Local Cache (Extension)** | TTL-based cache in `chrome.storage.local` — instant results for repeated URLs |
| 🗂️ **Scan History** | Authenticated users get a full audit trail of all scanned URLs |
| 📊 **Analytics Dashboard** | Interactive charts showing threat trends, class distribution, and latency metrics |
| 🐳 **Docker Stack** | One-command deployment with FastAPI + PostgreSQL + Redis + Prometheus |
| 🔐 **JWT Auth** | Secure bcrypt-hashed user accounts with role-based rate limiting |
| 📈 **Prometheus Metrics** | API latency and request count metrics exposed at `/metrics` |

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Chrome Browser                            │
│                                                                  │
│  ┌─────────────────┐         ┌──────────────────────────────┐   │
│  │  Browser        │         │   React Dashboard             │   │
│  │  Extension MV3  │         │   (Vite + TailwindCSS)        │   │
│  │                 │         │                              │   │
│  │  • Popup UI     │         │  • Auth (JWT)               │   │
│  │  • Service SW   │         │  • Scan History             │   │
│  │  • Local Cache  │         │  • Analytics (Recharts)     │   │
│  └────────┬────────┘         └────────────┬─────────────────┘   │
└───────────┼──────────────────────────────┼────────────────────┘
            │ POST /v1/scan                │ REST API Calls
            ▼                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (Python 3.10)                  │
│                                                                  │
│   ┌─────────────┐   ┌──────────────┐   ┌───────────────────┐   │
│   │  Threat Intel│   │  XGBoost ML  │   │  SHAP Explainer   │   │
│   │  Waterfall   │──▶│  Inference   │──▶│  (BackgroundTask) │   │
│   │              │   │  (< 5ms)     │   │                   │   │
│   └─────────────┘   └──────────────┘   └───────────────────┘   │
│                                                                  │
│   SlowAPI Rate Limiting · JWT Auth · Structlog · OpenTelemetry  │
│                                                                  │
│   ┌─────────────┐   ┌──────────────┐   ┌───────────────────┐   │
│   │  SQLAlchemy  │   │  Redis Cache │   │  Prometheus       │   │
│   │  + Alembic   │   │              │   │  /metrics         │   │
│   └─────────────┘   └──────────────┘   └───────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🧠 ML Pipeline

```
Raw URLs (PhishTank + Alexa + ISCX-URL-2016)
         ↓
  Data Cleaning & Deduplication
         ↓
  Feature Extraction (20+ URL structural features)
         ↓
  Train / Validation / Test Split (70/15/15)
         ↓
  XGBoost + Optuna Hyperparameter Tuning (100 trials)
         ↓
  Evaluation: 97.1% accuracy · 0.992 AUC-ROC · ≤1.8% FPR
         ↓
  TreeSHAP Explainability · Calibration · Joblib Serialization
         ↓
  FastAPI /v1/scan Inference
```

See [docs/ML_PIPELINE.md](docs/ML_PIPELINE.md) for full details.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **ML** | XGBoost, Scikit-learn, SHAP, Optuna, MLflow, Pandas, NumPy |
| **Backend** | FastAPI, SQLAlchemy (Async), Alembic, Uvicorn, SlowAPI, Structlog |
| **Auth** | JWT (`python-jose`), Bcrypt (`passlib`) |
| **Caching** | Redis (async), `chrome.storage.local` |
| **Observability** | Prometheus, OpenTelemetry, `asgi-correlation-id` |
| **Frontend** | React 18, TypeScript, Vite, TailwindCSS, Recharts, Framer Motion |
| **Extension** | Manifest V3, TypeScript, Chrome Extensions API |
| **Database** | SQLite (dev) / PostgreSQL (prod) via SQLAlchemy |
| **Container** | Docker, Docker Compose |

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+** and **pip**
- **Node.js 18+** and **npm**
- **Git**

### 1. Clone

```bash
git clone https://github.com/yourusername/ai-cyber-security-suite.git
cd ai-cyber-security-suite
```

### 2. Backend

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env: set a secure SECRET_KEY

# Initialize database
alembic upgrade head

# Start API (http://localhost:8000)
uvicorn backend.main:app --reload --port 8000
```

**API docs:** `http://localhost:8000/v1/docs`

### 3. Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

### 4. Browser Extension

```bash
cd extension
npm install
npm run build        # Outputs to extension/dist/
```

**Load in Chrome:**
1. Go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select `extension/dist/`

---

## 🐳 Docker (Full Stack)

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY

docker-compose up --build
```

Services:
| Service | URL |
|---|---|
| FastAPI API | `http://localhost:8000` |
| API Docs | `http://localhost:8000/v1/docs` |
| Prometheus | `http://localhost:9090` |

---

## 📚 API Overview

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/v1/auth/register` | Create user account | None |
| `POST` | `/v1/auth/login` | Get JWT token | None |
| `POST` | `/v1/scan` | Scan a URL for threats | Optional |
| `POST` | `/v1/explain` | Get SHAP attributions for a URL | Optional |
| `GET` | `/v1/history` | Get user scan history | Required |
| `GET` | `/v1/stats` | Get aggregated dashboard stats | Required |
| `GET` | `/v1/health` | API + service health check | None |

See [docs/api/README.md](docs/api/README.md) for full documentation.

---

## 📁 Project Structure

```
ai-cyber-security-suite/
├── backend/                  # FastAPI application
│   ├── api/
│   │   ├── routers/          # Endpoint handlers (scan, auth, history…)
│   │   ├── dependencies.py   # DI: DB sessions, ML singletons
│   │   └── middleware.py     # Timing middleware
│   ├── core/
│   │   ├── config.py         # Pydantic settings (env-driven)
│   │   ├── rate_limit.py     # SlowAPI limiter instance
│   │   ├── security.py       # JWT helpers
│   │   └── exceptions.py     # Global exception handlers
│   ├── database/             # SQLAlchemy models & session
│   ├── schemas/              # Pydantic request/response models
│   ├── services/             # Business logic (ML, cache, threat intel)
│   └── main.py               # App entry point
│
├── ml/                       # ML training pipeline
│   ├── datasets/             # Dataset versioning
│   ├── features/             # Feature extraction module
│   ├── models/               # Model store & registry
│   ├── pipelines/            # Training scripts
│   └── evaluation/           # Metrics & reports
│
├── frontend/                 # React 18 dashboard (Vite)
│   └── src/
│       ├── pages/            # Route-level components
│       ├── components/       # Reusable UI components
│       └── services/         # Typed API client (axios)
│
├── extension/                # Manifest V3 Chrome extension
│   ├── background/           # Service worker
│   ├── popup/                # Popup UI (HTML/CSS/TS)
│   ├── content/              # Content script
│   ├── services/             # API wrappers
│   └── utils/                # Badge & cache helpers
│
├── docs/                     # Documentation
│   ├── api/README.md
│   ├── architecture/README.md
│   ├── ML_PIPELINE.md
│   ├── DEPLOYMENT.md
│   └── TROUBLESHOOTING.md
│
├── docker/                   # Dockerfile & Prometheus config
├── configs/                  # ML model config YAMLs
├── migrations/               # Alembic migration files
├── tests/                    # Unit & integration tests
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## 📊 Performance

| Metric | Value |
|---|---|
| Scan latency (cache hit) | < 2ms |
| Scan latency (ML inference) | < 20ms |
| ML model accuracy | ~97.1% |
| AUC-ROC | ~0.992 |
| False positive rate | ≤ 1.8% |

---

## 🔐 Security

- All secrets are environment-variable driven — nothing is hardcoded.
- Passwords are hashed with bcrypt.
- JWTs are signed with HS256 and configurable expiry.
- Rate limiting prevents DoS on the inference engine.
- Trusted domain allowlist eliminates false positives on major platforms.

---

## 🛣️ Roadmap

- [ ] Real-time VirusTotal API integration for enhanced threat intel
- [ ] Firefox Extension support (WebExtensions API)
- [ ] Redis-backed distributed cache (replace per-pod in-memory cache)
- [ ] Admin panel for managing users and reviewing scan logs
- [ ] Sandboxed URL rendering for deep-link analysis
- [ ] Model retraining pipeline via MLflow webhook

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

Built with ❤️ as a portfolio project demonstrating full-stack AI security engineering.

- GitHub: [@yourusername](https://github.com/yourusername)

---

*If you find this project useful, please consider giving it a ⭐ on GitHub!*
