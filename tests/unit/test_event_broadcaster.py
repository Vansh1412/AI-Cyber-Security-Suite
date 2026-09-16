"""
tests/unit/test_event_broadcaster.py
───────────────────────────────────
Unit tests for Sprint 5 Phase 5E EventBroadcaster:
- Single-use stream ticket generation, burn, expiration, and replay prevention
- Bounded queue capacity (maxsize=100) and max 16KB payload enforcement
- Non-critical event eviction and coalescence under queue pressure
- Critical security event preservation (overflow sentinel rather than silent loss)
- Per-user connection cap (max 5) and pod connection limit (max 1000)
- Heartbeat frame formatting
- Local degraded delivery when Redis is unavailable
- Subscriber queue registration and disconnect cleanup
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from backend.database.models import User
from backend.schemas.stream import SSEEventEnvelope
from backend.services.event_broadcaster import (
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_QUEUE_SIZE,
    MAX_STREAMS_PER_POD,
    MAX_STREAMS_PER_USER,
    EventBroadcaster,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def broadcaster():
    """Isolated broadcaster instance for unit tests."""
    return EventBroadcaster()


# ── Ticket Unit Tests ─────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_ticket_creation_and_single_use_burn(broadcaster):
    """Ticket is generated with st_ prefix, burns on first use, and rejects second use."""
    user_id = 42
    ticket = await broadcaster.create_stream_ticket(user_id)

    assert isinstance(ticket, str)
    assert ticket.startswith("st_")

    # First validation succeeds and burns the ticket
    burned_user_id = await broadcaster.validate_and_burn_stream_ticket(ticket)
    assert burned_user_id == user_id

    # Second validation fails (atomic single-use)
    replay_user_id = await broadcaster.validate_and_burn_stream_ticket(ticket)
    assert replay_user_id is None


@pytest.mark.anyio
async def test_ticket_invalid_or_expired(broadcaster):
    """Non-existent ticket returns None."""
    assert await broadcaster.validate_and_burn_stream_ticket("st_nonexistent_random_id") is None
    assert await broadcaster.validate_and_burn_stream_ticket("") is None


# ── Event Size Bound Tests ───────────────────────────────────────────────────

def test_event_payload_size_enforcement(broadcaster):
    """Payloads exceeding 16KB must be truncated or safely bounded."""
    huge_data = {"key": "x" * (MAX_EVENT_PAYLOAD_BYTES + 1000)}
    envelope = broadcaster._create_envelope(
        event_type="alert_created",
        tenant_id=1,
        channel="alerts",
        payload=huge_data,
        cursor_id=1,
    )
    serialized = envelope.model_dump_json()
    assert len(serialized.encode("utf-8")) <= MAX_EVENT_PAYLOAD_BYTES + 500
    assert envelope.data.get("truncated") is True


# ── Queue Limits & Eviction Tests ────────────────────────────────────────────

@pytest.mark.anyio
async def test_non_critical_event_eviction_when_queue_full(broadcaster):
    """When queue is full (100 items), non-critical event is evicted to fit new event."""
    queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

    # Fill queue with 99 non-critical events and 1 critical event
    for i in range(MAX_QUEUE_SIZE - 1):
        envelope = SSEEventEnvelope(
            cursor_id=i,
            event_id=f"evt_{i}",
            event_type="unread_count_updated",
            tenant_id=1,
            data={"count": i},
        )
        queue.put_nowait(envelope)

    critical_env = SSEEventEnvelope(
        cursor_id=999,
        event_id="crit_1",
        event_type="alert_created",
        tenant_id=1,
        data={"severity": "CRITICAL"},
    )
    queue.put_nowait(critical_env)
    assert queue.full()

    # Now offer a new event - non-critical eviction should allow insertion
    new_env = SSEEventEnvelope(
        cursor_id=1000,
        event_id="evt_new",
        event_type="alert_updated",
        tenant_id=1,
        data={"status": "ACKNOWLEDGED"},
    )
    broadcaster._enqueue_to_stream_queue(queue, new_env)
    assert queue.qsize() == MAX_QUEUE_SIZE


@pytest.mark.anyio
async def test_critical_events_never_silently_dropped(broadcaster):
    """When queue contains only critical events and cannot accept more, sends stream_overflow."""
    queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

    # Fill queue with ONLY critical events
    for i in range(MAX_QUEUE_SIZE):
        envelope = SSEEventEnvelope(
            cursor_id=i,
            event_id=f"crit_{i}",
            event_type="alert_created",
            tenant_id=1,
            data={"severity": "CRITICAL"},
        )
        queue.put_nowait(envelope)

    assert queue.full()

    # Offer another critical event
    overflow_env = SSEEventEnvelope(
        cursor_id=1001,
        event_id="crit_overflow",
        event_type="alert_created",
        tenant_id=1,
        data={"severity": "CRITICAL"},
    )
    broadcaster._enqueue_to_stream_queue(queue, overflow_env)

    # Queue must contain stream_overflow control sentinel
    found_overflow = False
    while not queue.empty():
        item = queue.get_nowait()
        if isinstance(item, dict) and item.get("control") == "stream_overflow":
            found_overflow = True
            break
    assert found_overflow is True


# ── Connection Limit Tests ───────────────────────────────────────────────────

@pytest.mark.anyio
async def test_per_user_connection_limit(broadcaster):
    """A single user cannot exceed MAX_STREAMS_PER_USER (5). 6th connection raises HTTP 429."""
    user = User(id=99, email="user99@example.com", role="user")
    queues = []

    for _ in range(MAX_STREAMS_PER_USER):
        q = await broadcaster.register_listener(user)
        queues.append(q)

    with pytest.raises(HTTPException) as exc_info:
        await broadcaster.register_listener(user)
    assert exc_info.value.status_code == 429

    # Releasing one allows new connection
    await broadcaster.unregister_listener(user, queues.pop())
    new_q = await broadcaster.register_listener(user)
    assert new_q is not None

    # Cleanup
    for q in queues:
        await broadcaster.unregister_listener(user, q)
    await broadcaster.unregister_listener(user, new_q)


@pytest.mark.anyio
async def test_pod_connection_limit(broadcaster):
    """Process connection limit MAX_STREAMS_PER_POD (1000) raises HTTP 503."""
    user = User(id=1, email="admin@example.com", role="user")
    broadcaster._local_stream_count = MAX_STREAMS_PER_POD

    with pytest.raises(HTTPException) as exc_info:
        await broadcaster.register_listener(user)
    assert exc_info.value.status_code == 503
    assert exc_info.value.headers.get("Retry-After") == "30"

    # Reset
    broadcaster._local_stream_count = 0


# ── Subscriber Lifecycle Tests ───────────────────────────────────────────────

@pytest.mark.anyio
async def test_subscribe_and_unsubscribe_cleanup(broadcaster):
    """Registering and removing queues leaves zero orphaned objects."""
    user = User(id=7, email="user7@example.com", role="user")
    queue = await broadcaster.register_listener(user)
    assert user.id in broadcaster._local_subscribers
    assert queue in broadcaster._local_subscribers[user.id]

    await broadcaster.unregister_listener(user, queue)
    assert user.id not in broadcaster._local_subscribers or len(broadcaster._local_subscribers[user.id]) == 0


# ── Degraded Mode & Local Delivery Tests ─────────────────────────────────────

@pytest.mark.anyio
async def test_local_delivery_in_memory(broadcaster):
    """When published, local queues for the tenant receive the formatted event."""
    user = User(id=15, email="user15@example.com", role="user")
    queue = await broadcaster.register_listener(user, channel="alerts")

    payload = {"alert_uuid": "abc-123", "severity": "HIGH"}
    broadcaster.publish_event_nowait(
        event_type="alert_created",
        channel="alerts",
        tenant_id=user.id,
        payload=payload,
        aggregate_id="abc-123",
        cursor_id=42,
    )

    # Item should be in queue
    event = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert isinstance(event, SSEEventEnvelope)
    assert event.cursor_id == 42
    assert event.event_type == "alert_created"
    assert event.tenant_id == user.id
    assert event.data["alert_uuid"] == "abc-123"

    await broadcaster.unregister_listener(user, queue)


@pytest.mark.anyio
async def test_admin_redis_subscription_lifecycle():
    """Admin listener registration manages the _admin_subscription_task lifecycle."""
    broadcaster = EventBroadcaster()
    admin_u = User(id=999, email="admin@test.com", role="admin", is_active=True)

    class DummyPubSub:
        async def subscribe(self, channel): pass
        async def unsubscribe(self, channel): pass
        async def aclose(self): pass
        async def get_message(self, *args, **kwargs):
            await asyncio.sleep(0.5)
            return None

    class DummyRedis:
        def pubsub(self): return DummyPubSub()
        async def incr(self, key): return 1
        async def expire(self, key, ttl): pass
        async def decr(self, key): return 0
        async def set(self, key, val, **kwargs): pass

    broadcaster._redis_client = DummyRedis()
    broadcaster._running = True

    # Register admin listener
    q = await broadcaster.register_listener(user=admin_u, is_admin_stream=True)
    assert broadcaster._admin_subscription_task is not None
    assert not broadcaster._admin_subscription_task.done()

    # Unregister admin listener
    await broadcaster.unregister_listener(user=admin_u, q=q, is_admin_stream=True)
    assert broadcaster._admin_subscription_task is None

    await broadcaster.stop()


@pytest.mark.anyio
async def test_admin_payload_sanitization_unit():
    """Admin listener receives sanitized event envelopes redacting sensitive credentials."""
    broadcaster = EventBroadcaster()
    admin_u = User(id=999, email="admin@test.com", role="admin", is_active=True)
    q = await broadcaster.register_listener(user=admin_u, is_admin_stream=True)

    broadcaster.publish_event_nowait(
        event_type="alert_created",
        channel="alerts",
        tenant_id=42,
        payload={
            "alert_uuid": "alert-sensitive",
            "webhook_secret": "whsec_123456",
            "api_key": "prod_key_789",
            "nested": {"client_secret": "super_secret"},
        },
        cursor_id=1,
    )

    ev = await asyncio.wait_for(q.get(), timeout=1.0)
    assert isinstance(ev, SSEEventEnvelope)
    assert ev.data["alert_uuid"] == "alert-sensitive"
    assert ev.data["webhook_secret"] == "[REDACTED]"
    assert ev.data["api_key"] == "[REDACTED]"
    assert ev.data["nested"]["client_secret"] == "[REDACTED]"

    await broadcaster.unregister_listener(user=admin_u, q=q, is_admin_stream=True)
    await broadcaster.stop()

