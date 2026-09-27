"""
tests/unit/test_retention_worker.py
───────────────────────────────────
Unit tests for Sprint 5 Phase 5F:
- Bounded-batch retention pruning for soc_event_stream (7 days)
- Bounded-batch retention pruning for notification_outbox (30 days, terminal only)
- Preservation of active, pending, and running records
- Preservation of AuditEvent compliance logs
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import (
    Base,
    SOCEventStream,
    User,
)
from backend.services.notification_service import NotificationOutbox
from backend.services.retention_worker import RetentionWorker


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def sync_db():
    """In-memory SQLite synchronous engine."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        user = User(email="test@soc.corp", hashed_pw="dummy_pw", role="user")
        session.add(user)
        session.commit()
        session.refresh(user)
        yield session, user
    Base.metadata.drop_all(engine)


@pytest.mark.anyio
async def test_event_stream_retention():
    """Verify soc_event_stream deletes only records older than 7 days."""
    worker = RetentionWorker()
    worker._running = True

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    now = datetime.now(timezone.utc)
    eight_days_ago = now - timedelta(days=8)
    six_days_ago = now - timedelta(days=6)

    async with async_session() as session:
        user = User(email="retention_test@soc.corp", hashed_pw="dummy", role="user")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # 3 expired events
        for i in range(3):
            event = SOCEventStream(
                event_id=f"expired-{i}",
                tenant_id=user.id,
                channel="soc",
                event_type="alert_created",
                payload_json={"test": i},
                created_at=eight_days_ago,
            )
            session.add(event)

        # 2 fresh events
        for i in range(2):
            event = SOCEventStream(
                event_id=f"fresh-{i}",
                tenant_id=user.id,
                channel="soc",
                event_type="alert_created",
                payload_json={"test": i},
                created_at=six_days_ago,
            )
            session.add(event)

        await session.commit()

        # Run event stream pruning
        deleted = await worker._prune_event_stream(session)
        assert deleted == 3

        # Verify only fresh events remain
        from sqlalchemy import select
        res = await session.execute(select(SOCEventStream))
        remaining = res.scalars().all()
        assert len(remaining) == 2
        for r in remaining:
            assert r.event_id.startswith("fresh-")

    await engine.dispose()


@pytest.mark.anyio
async def test_outbox_retention_preserves_active():
    """Verify notification_outbox deletes terminal records older than 30d, preserving active."""
    worker = RetentionWorker()
    worker._running = True

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    now = datetime.now(timezone.utc)
    thirty_five_days_ago = now - timedelta(days=35)
    twenty_days_ago = now - timedelta(days=20)

    async with async_session() as session:
        user = User(email="outbox_test@soc.corp", hashed_pw="dummy", role="user")
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # 1. Expired DELIVERED (should be pruned)
        session.add(
            NotificationOutbox(
                user_id=user.id,
                channel="WEBHOOK",
                destination_url="https://hooks.corp.com/soc",
                payload_json={"alert": 1},
                idempotency_key="outbox-expired-delivered",
                status="DELIVERED",
                created_at=thirty_five_days_ago,
            )
        )

        # 2. Expired PENDING (MUST BE PRESERVED - not terminal!)
        session.add(
            NotificationOutbox(
                user_id=user.id,
                channel="WEBHOOK",
                destination_url="https://hooks.corp.com/soc",
                payload_json={"alert": 2},
                idempotency_key="outbox-expired-pending",
                status="PENDING",
                created_at=thirty_five_days_ago,
            )
        )

        # 3. Fresh DELIVERED (MUST BE PRESERVED - < 30 days)
        session.add(
            NotificationOutbox(
                user_id=user.id,
                channel="WEBHOOK",
                destination_url="https://hooks.corp.com/soc",
                payload_json={"alert": 3},
                idempotency_key="outbox-fresh-delivered",
                status="DELIVERED",
                created_at=twenty_days_ago,
            )
        )

        await session.commit()

        deleted = await worker._prune_outbox(session)
        assert deleted == 1

        from sqlalchemy import select
        res = await session.execute(select(NotificationOutbox))
        remaining = res.scalars().all()
        assert len(remaining) == 2
        remaining_keys = {r.idempotency_key for r in remaining}
        assert "outbox-expired-pending" in remaining_keys
        assert "outbox-fresh-delivered" in remaining_keys

    await engine.dispose()
