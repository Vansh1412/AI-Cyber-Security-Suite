"""
backend/core/config.py
───────────────────────
Centralised settings via Pydantic BaseSettings.

All values can be overridden by environment variables or a .env file.
"""

from __future__ import annotations

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── API ───────────────────────────────────────────────────────────────────
    PROJECT_NAME: str = "AI Cyber Security Suite API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/v1"

    # ── Security / JWT ────────────────────────────────────────────────────────
    SECRET_KEY: str = "changeme-use-a-long-random-secret-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Database ──────────────────────────────────────────────────────────────
    # Default: SQLite (zero-config local dev)
    # Override: DATABASE_URL=postgresql+asyncpg://user:pass@localhost/dbname
    DATABASE_URL: str = "sqlite+aiosqlite:///./backend.db"

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_SECONDS: int = 3600   # 1 hour

    # ── ML Model Paths ────────────────────────────────────────────────────────
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    MODEL_ENV: str = "production"
    REGISTRY_PATH: Path = BASE_DIR / "ml" / "models" / "store" / "registry.json"
    CONFIG_PATH: Path = BASE_DIR / "configs" / "model_config.yaml"
    SCHEMA_PATH: Path = BASE_DIR / "ml" / "schema" / "feature_schema.json"

    @property
    def MODEL_PATH(self) -> Path:
        """Resolve model path via registry."""
        import json
        if self.REGISTRY_PATH.exists():
            with open(self.REGISTRY_PATH, "r") as f:
                registry = json.load(f)
            model_file = registry.get(self.MODEL_ENV, "xgboost_calibrated.pkl")
        else:
            model_file = "xgboost_calibrated.pkl"
        return self.BASE_DIR / "ml" / "models" / "store" / model_file

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
