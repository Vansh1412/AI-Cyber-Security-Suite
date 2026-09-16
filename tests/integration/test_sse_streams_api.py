"""
tests/integration/test_sse_streams_api.py
─────────────────────────────────────────
Sprint 5 Phase 5E: Integration tests for Real-Time SSE Streams API.

Endpoints tested:
  - POST /v1/streams/ticket
  - GET  /v1/alerts/stream
  - GET  /v1/notifications/stream
  - GET  /v1/soc/stream
  - GET  /v1/admin/soc/stream
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Base, SOCEventStream, User
from backend.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_engine():
    """Create in-memory SQLite async engine with StaticPool."""
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
        u1 = User(id=1, email="user1@soc.test", hashed_pw="pw1", role="user", is_active=True)
        u2 = User(id=2, email="user2@soc.test", hashed_pw="pw2", role="user", is_active=True)
        admin = User(id=99, email="admin@soc.test", hashed_pw="pwa", role="admin", is_active=True)
        session.add_all([u1, u2, admin])
        await session.commit()
    return {"u1": u1, "u2": u2, "admin": admin}


# ── 1. Security: Rejection of Query Parameter JWTs ───────────────────────────

@pytest.mark.anyio
async def test_query_token_rejection(session_factory, seeded_users):
    """Query parameter ?token=... is strictly rejected with HTTP 400."""
    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/alerts/stream?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy")
            assert resp.status_code == 400
            assert "prohibited" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


# ── 2. Stream Ticket Creation and Atomic Single-Use Burn ─────────────────────

@pytest.mark.anyio
async def test_stream_ticket_create_and_burn(session_factory, seeded_users):
    """Ticket is created with Bearer auth, consumed once by stream, and cannot be replayed."""
    u1 = seeded_users["u1"]

    async def override_get_db():
        async with session_factory() as s:
            yield s

    async def override_get_user():
        return u1

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_user

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create ticket
            ticket_resp = await client.post("/v1/streams/ticket")
            assert ticket_resp.status_code == 200
            data = ticket_resp.json()
            ticket = data["ticket"]
            assert ticket.startswith("st_")
            assert data["expires_in"] == 30

            # 2. Use ticket to connect (first time succeeds)
            app.dependency_overrides.pop(get_current_user, None)  # Ensure no Bearer auth fallback
            stream_resp = await client.get(f"/v1/soc/stream?ticket={ticket}&max_events=0")
            assert stream_resp.status_code == 200
            assert "text/event-stream" in stream_resp.headers["content-type"]
            assert "no-cache" in stream_resp.headers["cache-control"]
            assert stream_resp.headers.get("x-accel-buffering") == "no"
            assert ": connected" in stream_resp.text

            # 3. Replay with same ticket MUST fail with HTTP 401
            replay_resp = await client.get(f"/v1/soc/stream?ticket={ticket}&max_events=0")
            assert replay_resp.status_code == 401
            detail_lower = replay_resp.json()["detail"].lower()
            assert any(word in detail_lower for word in ["consumed", "expired", "invalid"])

    finally:
        app.dependency_overrides.clear()


# ── 3. Invalid or Expired Ticket ─────────────────────────────────────────────

@pytest.mark.anyio
async def test_invalid_stream_ticket(session_factory):
    """Connecting with a bogus ticket returns HTTP 401."""
    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/soc/stream?ticket=st_bogus_ticket_123&max_events=0")
            assert resp.status_code == 401
    finally:
        app.dependency_overrides.clear()


# ── 4. Admin Stream RBAC & Audit Logging ─────────────────────────────────────

@pytest.mark.anyio
async def test_admin_stream_rbac(session_factory, seeded_users):
    """Standard user is denied (HTTP 403) from /v1/admin/soc/stream; Admin succeeds."""
    u1 = seeded_users["u1"]
    admin = seeded_users["admin"]

    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    auth_headers = {"Authorization": "Bearer dummy_token"}

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Non-admin user gets HTTP 403
            app.dependency_overrides[get_current_user] = lambda: u1
            resp = await client.get("/v1/admin/soc/stream?max_events=0", headers=auth_headers)
            assert resp.status_code == 403

            # 2. Admin user gets HTTP 200 stream
            app.dependency_overrides[get_current_user] = lambda: admin
            stream_resp = await client.get("/v1/admin/soc/stream?max_events=0", headers=auth_headers)
            assert stream_resp.status_code == 200
            assert ": connected" in stream_resp.text
    finally:
        app.dependency_overrides.clear()


# ── 5. Durable Last-Event-ID Replay ──────────────────────────────────────────

@pytest.mark.anyio
async def test_last_event_id_replay_ordering_and_tenant_isolation(session_factory, seeded_users):
    """Missed events replay in exact ascending cursor order and strictly isolated by tenant."""
    u1 = seeded_users["u1"]
    u2 = seeded_users["u2"]
    now = datetime.now(timezone.utc)

    # Seed events into soc_event_stream
    async with session_factory() as session:
        # u1 events: cursors 10, 12, 15
        e1 = SOCEventStream(
            cursor_id=10,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="alerts",
            event_type="alert_created",
            aggregate_id="alt-1",
            payload_json=json.dumps({"id": "alt-1", "severity": "HIGH", "seq": 1}),
            created_at=now,
        )
        # u2 event: cursor 11 (foreign tenant)
        e2_foreign = SOCEventStream(
            cursor_id=11,
            event_id=str(uuid.uuid4()),
            tenant_id=u2.id,
            channel="alerts",
            event_type="alert_created",
            aggregate_id="alt-foreign",
            payload_json=json.dumps({"id": "alt-foreign", "severity": "CRITICAL", "seq": "foreign"}),
            created_at=now,
        )
        e3 = SOCEventStream(
            cursor_id=12,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="alerts",
            event_type="alert_updated",
            aggregate_id="alt-1",
            payload_json=json.dumps({"id": "alt-1", "status": "ACKNOWLEDGED", "seq": 2}),
            created_at=now,
        )
        e4 = SOCEventStream(
            cursor_id=15,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="alerts",
            event_type="alert_updated",
            aggregate_id="alt-1",
            payload_json=json.dumps({"id": "alt-1", "status": "RESOLVED", "seq": 3}),
            created_at=now,
        )
        session.add_all([e1, e2_foreign, e3, e4])
        await session.commit()

    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: u1

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Connect with Last-Event-ID: 10 (should replay 12 and 15, but NEVER 11)
            headers = {"Last-Event-ID": "10", "Authorization": "Bearer dummy_token"}
            stream_resp = await client.get("/v1/alerts/stream?max_events=2", headers=headers)
            assert stream_resp.status_code == 200

            replayed_ids: list[int] = []
            for line in stream_resp.text.splitlines():
                if line.startswith("id: "):
                    cid = int(line.split("id: ")[1].strip())
                    replayed_ids.append(cid)

            # Assert strict ascending order and zero foreign tenant leakage
            assert replayed_ids == [12, 15]
            assert 11 not in replayed_ids
    finally:
        app.dependency_overrides.clear()


# ── 6. Stream Reset When Cursor Is Expired ───────────────────────────────────

@pytest.mark.anyio
async def test_stream_reset_on_outdated_cursor(session_factory, seeded_users):
    """If Last-Event-ID is 0 and events exist with much higher cursors, or cursor is expired, emit stream_reset."""
    u1 = seeded_users["u1"]
    now = datetime.now(timezone.utc)

    # Seed events with high cursor
    async with session_factory() as session:
        e = SOCEventStream(
            cursor_id=50000,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="alerts",
            event_type="alert_created",
            aggregate_id="alt-high",
            payload_json=json.dumps({"id": "alt-high"}),
            created_at=now,
        )
        session.add(e)
        await session.commit()

    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: u1

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Last-Event-ID is 10, but earliest cursor is 50000 (cursor expired / window exceeded)
            headers = {"Last-Event-ID": "10", "Authorization": "Bearer dummy_token"}
            stream_resp = await client.get("/v1/alerts/stream?max_events=1", headers=headers)
            assert stream_resp.status_code == 200
            assert "stream_reset" in stream_resp.text or "resync_required" in stream_resp.text
    finally:
        app.dependency_overrides.clear()


# ── 7. Admin Stream Cross-Tenant Replay & Sensitive Field Redaction ────────────

@pytest.mark.anyio
async def test_admin_stream_cross_tenant_replay_and_redaction(session_factory, seeded_users):
    """
    Admin stream GET /v1/admin/soc/stream:
      - Can replay events across different tenants (cross-tenant visibility).
      - Automatically redacts sensitive fields like webhook_secret, api_key, etc.
    """
    admin_u = seeded_users["admin"]
    u1 = seeded_users["u1"]
    u2 = seeded_users["u2"]
    now = datetime.now(timezone.utc)

    async with session_factory() as session:
        # Event from tenant 1 with sensitive secret
        e1 = SOCEventStream(
            cursor_id=101,
            event_id=str(uuid.uuid4()),
            tenant_id=u1.id,
            channel="alerts",
            event_type="alert_created",
            aggregate_id="alt-u1",
            payload_json={
                "id": "alt-u1",
                "severity": "HIGH",
                "rule_name": "Test",
                "webhook_secret": "whsec_supersecret123",
                "api_key": "secret_key_abc",
            },
            created_at=now,
        )
        # Event from tenant 2
        e2 = SOCEventStream(
            cursor_id=102,
            event_id=str(uuid.uuid4()),
            tenant_id=u2.id,
            channel="alerts",
            event_type="alert_created",
            aggregate_id="alt-u2",
            payload_json={"id": "alt-u2", "severity": "CRITICAL"},
            created_at=now,
        )
        session.add_all([e1, e2])
        await session.commit()

    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: admin_u

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"Last-Event-ID": "100", "Authorization": "Bearer admin_token"}
            resp = await client.get("/v1/admin/soc/stream?max_events=2", headers=headers)
            assert resp.status_code == 200

            # Both events (tenant 1 and tenant 2) should be present
            assert "alt-u1" in resp.text
            assert "alt-u2" in resp.text

            # Sensitive fields must be redacted
            assert "whsec_supersecret123" not in resp.text
            assert "secret_key_abc" not in resp.text
            assert "[REDACTED]" in resp.text
    finally:
        app.dependency_overrides.clear()

