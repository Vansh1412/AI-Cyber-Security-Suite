"""
backend/services/cache.py
──────────────────────────
Async Redis cache wrapper with graceful degradation.

If Redis is unavailable, all operations silently no-op so the rest
of the API continues working without interruption.
"""

from __future__ import annotations

import json
import hashlib

import redis.asyncio as aioredis

from backend.core.config import settings
from src.utils.logger import logger


class CacheService:
    def __init__(self):
        self._client: aioredis.Redis | None = None

    async def connect(self) -> None:
        try:
            self._client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=1,
            )
            await self._client.ping()
            logger.info("Redis connected: %s", settings.REDIS_URL)
        except Exception as e:
            logger.warning("Redis unavailable — caching disabled: %s", e)
            self._client = None

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()

    def _make_key(self, url: str) -> str:
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        return f"scan:v1:{url_hash}"

    async def get(self, url: str) -> dict | None:
        if not self._client:
            return None
        try:
            raw = await self._client.get(self._make_key(url))
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.warning("Cache GET error: %s", e)
        return None

    async def set(self, url: str, data: dict) -> None:
        if not self._client:
            return
        try:
            await self._client.setex(
                self._make_key(url),
                settings.CACHE_TTL_SECONDS,
                json.dumps(data),
            )
        except Exception as e:
            logger.warning("Cache SET error: %s", e)

    @property
    def available(self) -> bool:
        return self._client is not None


# Module-level singleton — initialised on app startup
cache_service = CacheService()
