FROM python:3.10-slim

# ── Environment ───────────────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# ── System Dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# ── Python Dependencies ───────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# ── Application Source ────────────────────────────────────────────────────────
COPY . .

EXPOSE 8000

# ── Entry Point ───────────────────────────────────────────────────────────────
# Runs DB migrations then starts the API server
CMD alembic upgrade head && uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 2
