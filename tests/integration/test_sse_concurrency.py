"""
tests/integration/test_sse_concurrency.py
─────────────────────────────────────────
Sprint 5 Phase 5E: Concurrency, Quota & Leak Testing for SSE Streaming Gateway.

Verifies:
  1. Per-user stream limit (MAX_STREAMS_PER_USER=5) -> HTTP 429 Too Many Requests.
  2. Pod stream limit (MAX_STREAMS_PER_POD=1000) -> HTTP 503 Service Unavailable.
  3. 50 concurrent streams fan-out with strict tenant isolation.
  4. Disconnect cleanup and zero listener leak verification.
  5. Bounded queue overflow handling (non-critical drop, critical overflow sentinel).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Base, User
from backend.main import app
from backend.schemas.stream import SSEEventEnvelope
from backend.services.event_broadcaster import event_broadcaster


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
async def reset_broadcaster_state():
    """Ensure complete isolation between concurrency test runs."""
    yield
    async with event_broadcaster._lock:
        event_broadcaster._local_subscribers.clear()
        event_broadcaster._admin_subscribers.clear()
        event_broadcaster._queue_metadata.clear()
        event_broadcaster._local_stream_count = 0
        event_broadcaster._user_connection_counts.clear()
        event_broadcaster._admin_connection_counts.clear()
        event_broadcaster.MAX_STREAMS_PER_POD = 1000
        event_broadcaster.MAX_POD_STREAMS = 1000


@pytest.fixture
async def async_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(async_engine):
    return async_sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def seeded_users(session_factory):
    async with session_factory() as session:
        users = [
            User(id=i, email=f"user{i}@soc.test", hashed_pw=f"pw{i}", role="user", is_active=True)
            for i in range(1, 15)
        ]
        session.add_all(users)
        await session.commit()
    return {u.id: u for u in users}


# ── 1. Per-User Connection Quota (HTTP 429) ───────────────────────────────────

@pytest.mark.anyio
async def test_per_user_stream_limit_429(session_factory, seeded_users):
    """A user cannot exceed MAX_STREAMS_PER_USER (5). The 6th attempt raises HTTP 429."""
    u1 = seeded_users[1]
    active_queues: list[asyncio.Queue] = []

    try:
        # Register up to the limit (5 streams)
        for _ in range(event_broadcaster.MAX_STREAMS_PER_USER):
            q = await event_broadcaster.register_listener(user=u1, channel="alerts")
            active_queues.append(q)

        assert len(active_queues) == 5

        # 6th attempt MUST raise HTTP 429
        with pytest.raises(HTTPException) as exc_info:
            await event_broadcaster.register_listener(user=u1, channel="alerts")
        assert exc_info.value.status_code == 429
        assert "exceeded" in exc_info.value.detail.lower()

        # Verify via API route: HTTP 429 returned to client
        async def override_get_db():
            async with session_factory() as s:
                yield s

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_user] = lambda: u1
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/alerts/stream?max_events=0", headers={"Authorization": "Bearer tok"})
            assert resp.status_code == 429

    finally:
        app.dependency_overrides.clear()
        for q in active_queues:
            await event_broadcaster.unregister_listener(user=u1, q=q)
        assert event_broadcaster.get_active_stream_count(u1.id) == 0


# ── 2. Pod-Level Stream Limit (HTTP 503) ──────────────────────────────────────

@pytest.mark.anyio
async def test_pod_stream_limit_503(seeded_users):
    """When the pod capacity is exhausted, additional connections return HTTP 503."""
    orig_pod_limit = event_broadcaster.MAX_STREAMS_PER_POD
    event_broadcaster.MAX_STREAMS_PER_POD = 4
    event_broadcaster.MAX_POD_STREAMS = 4

    active_listeners: list[tuple[User, asyncio.Queue]] = []

    try:
        # Register 4 listeners across distinct users
        for i in range(1, 5):
            u = seeded_users[i]
            q = await event_broadcaster.register_listener(user=u, channel="soc")
            active_listeners.append((u, q))

        # 5th connection on the pod MUST raise HTTP 503
        u5 = seeded_users[5]
        with pytest.raises(HTTPException) as exc_info:
            await event_broadcaster.register_listener(user=u5, channel="soc")
        assert exc_info.value.status_code == 503
        assert "capacity reached" in exc_info.value.detail.lower() or "503" in str(exc_info.value.status_code)

    finally:
        event_broadcaster.MAX_STREAMS_PER_POD = orig_pod_limit
        event_broadcaster.MAX_POD_STREAMS = orig_pod_limit
        for u, q in active_listeners:
            await event_broadcaster.unregister_listener(user=u, q=q)


# ── 3. 50 Concurrent Streams Fan-Out & Tenant Isolation ───────────────────────

@pytest.mark.anyio
async def test_50_concurrent_streams_fanout(seeded_users):
    """
    Registers 50 concurrent listener queues across 10 distinct tenants (5 per tenant).
    Publishes an event to tenant 1 and verifies:
      - All 5 of tenant 1's queues receive the event.
      - None of the remaining 45 queues receive the event (strict isolation).
    """
    tenant_queues: dict[int, list[asyncio.Queue]] = {i: [] for i in range(1, 11)}

    try:
        # Register 50 streams (5 per tenant across 10 tenants)
        for tenant_id in range(1, 11):
            user = seeded_users[tenant_id]
            for _ in range(5):
                q = await event_broadcaster.register_listener(user=user, channel="alerts")
                tenant_queues[tenant_id].append(q)

        assert event_broadcaster.total_active_connections == 50

        # Create test event for Tenant 1
        test_event = SSEEventEnvelope(
            cursor_id=1001,
            event_id=str(uuid.uuid4()),
            tenant_id=1,
            channel="alerts",
            event_type="alert_created",
            aggregate_id="alt-1001",
            data={"severity": "CRITICAL", "threat": "Ransomware"},
        )

        # Broadcast event to Tenant 1
        delivered = await event_broadcaster.publish_event(test_event)
        assert delivered == 5

        # Verify all 5 queues of Tenant 1 received the event
        for q in tenant_queues[1]:
            assert not q.empty()
            item = q.get_nowait()
            assert item.cursor_id == 1001
            assert item.tenant_id == 1

        # Verify all other 45 queues remain completely empty
        for tenant_id in range(2, 11):
            for q in tenant_queues[tenant_id]:
                assert q.empty()

    finally:
        # Cleanly unregister all 50 streams
        for tenant_id, queues in tenant_queues.items():
            user = seeded_users[tenant_id]
            for q in queues:
                await event_broadcaster.unregister_listener(user=user, q=q)

        assert event_broadcaster.total_active_connections == 0


# ── 4. Disconnect Cleanup and Zero Listener Leak ─────────────────────────────

@pytest.mark.anyio
async def test_disconnect_cleanup_no_leaks(seeded_users):
    """Unregistering listeners completely removes state and leaves no lingering references."""
    u1 = seeded_users[1]
    q1 = await event_broadcaster.register_listener(user=u1, channel="alerts")
    q2 = await event_broadcaster.register_listener(user=u1, channel="soc")

    assert event_broadcaster.get_active_stream_count(u1.id) == 2
    assert event_broadcaster.total_active_connections == 2

    # Unregister first queue
    await event_broadcaster.unregister_listener(user=u1, q=q1)
    assert event_broadcaster.get_active_stream_count(u1.id) == 1
    assert event_broadcaster.total_active_connections == 1

    # Unregister second queue
    await event_broadcaster.unregister_listener(user=u1, q=q2)
    assert event_broadcaster.get_active_stream_count(u1.id) == 0
    assert event_broadcaster.total_active_connections == 0
    assert u1.id not in event_broadcaster._local_subscribers


# ── 5. Bounded Queue Non-Critical Overflow Handling ──────────────────────────

@pytest.mark.anyio
async def test_queue_overflow_non_critical_dropped(seeded_users):
    """
    When the bounded queue (maxsize=100) fills up:
      - Low/Medium/Info events are evicted to make room for incoming events.
      - Total queue size never exceeds maxsize.
    """
    u1 = seeded_users[1]
    q = await event_broadcaster.register_listener(user=u1, channel="soc")

    try:
        # Fill queue to capacity (100 items) with LOW severity events
        for i in range(100):
            ev = SSEEventEnvelope(
                cursor_id=i,
                event_id=str(uuid.uuid4()),
                tenant_id=u1.id,
                channel="soc",
                event_type="alert_created",
                aggregate_id=f"alt-{i}",
                data={"severity": "LOW", "seq": i},
            )
            q.put_nowait(ev)

        assert q.full()
        assert q.qsize() == 100

        # Now broadcast a new event
        new_event = SSEEventEnvelope(
            cursor_id=999,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="soc",
            event_type="alert_created",
            aggregate_id="alt-999",
            data={"severity": "HIGH", "seq": 999},
        )

        delivered = await event_broadcaster.publish_event(new_event)
        assert delivered == 1
        assert q.qsize() == 100  # Queue did not overflow beyond 100

    finally:
        await event_broadcaster.unregister_listener(user=u1, q=q)


# ── 6. Bounded Queue Critical Overflow Sentinel ──────────────────────────────

@pytest.mark.anyio
async def test_critical_overflow_sentinel(seeded_users):
    """
    When the bounded queue contains 100 CRITICAL events and a new CRITICAL event arrives:
      - An overflow sentinel control frame is placed in the queue.
      - Client is signaled to reconnect and resynchronize via Last-Event-ID.
    """
    u1 = seeded_users[1]
    q = await event_broadcaster.register_listener(user=u1, channel="soc")

    try:
        # Fill queue to capacity with CRITICAL events
        for i in range(100):
            ev = SSEEventEnvelope(
                cursor_id=i,
                event_id=str(uuid.uuid4()),
                tenant_id=u1.id,
                channel="soc",
                event_type="alert_created",
                aggregate_id=f"alt-{i}",
                data={"severity": "CRITICAL", "seq": i},
            )
            q.put_nowait(ev)

        assert q.full()

        # Broadcast one more CRITICAL event
        overflow_event = SSEEventEnvelope(
            cursor_id=999,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="soc",
            event_type="alert_created",
            aggregate_id="alt-999",
            data={"severity": "CRITICAL", "seq": 999},
        )

        await event_broadcaster.publish_event(overflow_event)

        # The queue must now contain a stream_overflow sentinel
        items: list[Any] = []
        while not q.empty():
            items.append(q.get_nowait())

        sentinel_found = any(
            isinstance(item, dict) and item.get("control") == "stream_overflow"
            for item in items
        )
        assert sentinel_found is True

    finally:
        await event_broadcaster.unregister_listener(user=u1, q=q)
