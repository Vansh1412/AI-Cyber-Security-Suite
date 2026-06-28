"""
backend/api/dependencies.py
────────────────────────────
FastAPI dependency injection — singletons and per-request dependencies.
"""

from __future__ import annotations

from functools import lru_cache
from typing import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.core.security import decode_access_token
from backend.database.session import AsyncSessionLocal
from backend.database.models import User
from backend.services.feature_eng import FeatureService
from backend.services.prediction import PredictionService
from backend.services.explainer import ExplainerService
from backend.services.cache import cache_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login", auto_error=False)


# ── ML Service Singletons ─────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_feature_service() -> FeatureService:
    return FeatureService()


@lru_cache(maxsize=1)
def get_prediction_service() -> PredictionService:
    return PredictionService()


@lru_cache(maxsize=1)
def get_explainer_service() -> ExplainerService:
    return ExplainerService()


# ── Database Session ──────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


# ── Auth Dependencies ─────────────────────────────────────────────────────────

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Requires a valid Bearer token. Raises 401 if missing or invalid."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exc
    try:
        user_id = decode_access_token(token)
    except JWTError:
        raise credentials_exc

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exc
    return user


async def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Optionally resolves the current user — returns None for anonymous requests."""
    if not token:
        return None
    try:
        user_id = decode_access_token(token)
        result = await db.execute(select(User).where(User.id == int(user_id)))
        return result.scalar_one_or_none()
    except Exception:
        return None


async def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """Requires the current user to be an admin."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user
