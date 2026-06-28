# Deployment Guide

This guide covers deploying the AI Cyber Security Suite in both local development and production Docker environments.

---

## Option 1: Local Development (Recommended for Development)

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/ai-cyber-security-suite.git
cd ai-cyber-security-suite
```

### 2. Backend Setup
```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env and set a secure SECRET_KEY

# Initialize the database
alembic upgrade head

# Start the API server
uvicorn backend.main:app --reload --port 8000
```

The API is now running at `http://localhost:8000`
Interactive API docs available at `http://localhost:8000/v1/docs`

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

The React dashboard is now running at `http://localhost:3000`

### 4. Browser Extension Setup
```bash
cd extension
npm install
npm run build
```

Load the extension in Chrome:
1. Navigate to `chrome://extensions/`
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the `extension/dist/` directory

---

## Option 2: Docker (Production)

### Prerequisites
- Docker Engine 24+
- Docker Compose v2+

### 1. Configure Secrets
```bash
cp .env.example .env
```

Edit `.env` and set:
```env
SECRET_KEY=your-very-long-random-secret-key
```

**Generate a secure key:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Start All Services
```bash
docker-compose up --build
```

This starts:
- `api` — FastAPI backend on port 8000
- `db` — PostgreSQL 16 on port 5432
- `redis` — Redis 7 on port 6379
- `prometheus` — Metrics scraper on port 9090

### 3. Verify Deployment
```bash
curl http://localhost:8000/v1/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "connected",
  "redis": "connected",
  "model": "loaded",
  "version": "1.0.0"
}
```

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `changeme-...` | JWT signing key — **change in production!** |
| `DATABASE_URL` | `sqlite+aiosqlite:///./backend.db` | SQLAlchemy DB connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | JWT expiry (minutes) |
| `VITE_API_URL` | `http://localhost:8000` | Frontend API base URL |

---

## Monitoring

When running via Docker, Prometheus scrapes the `/metrics` endpoint.

Access the Prometheus UI at: `http://localhost:9090`

Key metrics exposed:
- `http_request_duration_seconds` — API latency
- `http_requests_total` — Request count by endpoint and status
