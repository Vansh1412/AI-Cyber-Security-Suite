"""
backend/database/session.py
────────────────────────────
Async SQLAlchemy engine + session factory.

Defaults to SQLite (aiosqlite) for zero-config local dev.
Set DATABASE_URL=postgresql+asyncpg://... in .env to use PostgreSQL.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    # For SQLite only — disable check_same_thread restriction
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def init_db() -> None:
    """Create all tables on startup (dev/test only; prod uses Alembic)."""
    from backend.database.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
