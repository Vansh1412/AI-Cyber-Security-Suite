# System Architecture — AI Cyber Security Suite

## Overview

The system follows a **3-tier architecture**: Client → API → Data/ML.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│   React Web App (Tailwind)    Chrome Extension (Manifest V3)     │
└──────────────────────────────────────┬──────────────────────────┘
                                       │ REST API (HTTPS)
┌──────────────────────────────────────▼──────────────────────────┐
│                    API LAYER — FastAPI                           │
│   Auth  │  Scan  │  History  │  Admin  │  Reports               │
│   JWT Middleware  │  Rate Limiting  │  CORS                      │
└──────┬──────────────────────────┬────────────────────────────────┘
       │                          │
┌──────▼──────┐       ┌───────────▼──────────┐
│  PostgreSQL │       │  ML Inference Engine  │
│  (SQLAlchemy│       │  XGBoost + SHAP       │
│   + Alembic)│       │  Feature Extractor    │
└─────────────┘       └───────────────────────┘
```

## Key Design Decisions

### 1. Stateless API (JWT)
- No server-side sessions
- Horizontally scalable
- Tokens expire in 24h (configurable)

### 2. ML as a Service
- Model loaded at startup into memory
- Inference is synchronous (sub-second)
- Model versioning via MLflow

### 3. Feature-Based Detection
- No URL fetching required (privacy-preserving)
- Works on URL string alone
- Optional: Page content features (Phase 3+)

### 4. SHAP Explainability
- TreeSHAP for XGBoost (fast, exact)
- Top-5 features returned per prediction
- Visualized as horizontal bar chart in frontend

## Database Schema (Logical)

```
users
  id, email, hashed_password, role, created_at, is_active

scan_logs
  id, user_id, url, verdict, confidence, features_json, shap_json, created_at

blacklist
  id, url_pattern, added_by, reason, created_at

whitelist
  id, url_pattern, added_by, reason, created_at

admin_logs
  id, admin_id, action, target, metadata, created_at
```

## Security Architecture

- All passwords hashed with **bcrypt** (cost factor 12)
- JWT signed with **HS256**, expiry 24h
- Rate limiting: **60 requests/minute** per IP
- HTTPS enforced in production
- No raw URLs stored in logs by default (hashed)
- Admin actions fully audited

## Deployment Architecture

```
GitHub (source) 
    ↓ Push to main
GitHub Actions (CI/CD)
    ↓ Tests pass
    ├── Render.com (Backend Docker container)
    └── Vercel (Frontend static build)
```
