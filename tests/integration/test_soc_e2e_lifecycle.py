"""
tests/integration/test_soc_e2e_lifecycle.py
─────────────────────────────────────────────
Phase 7 Plan 03: End-to-End SOC Lifecycle & Reversible Containment Integration Tests.

Validates Decisions D-05, D-07, and D-08:
  1. Full closed-loop SOC lifecycle against canonical routes:
     - Scan URL for threat intelligence (POST /v1/scan)
     - Retrieve alert (GET /v1/alerts)
     - Create incident (POST /v1/incidents) and attach alert (POST /v1/incidents/{id}/alerts)
     - Execute dynamic containment with BLACKLIST_INDICATOR (POST /v1/soc/actions/contain)
     - Verify BLOCKED state in SOCDynamicBlacklist
     - Revert containment (POST /v1/soc/actions/{uuid}/revert)
     - Verify UNBLOCKED state and immutable audit logging in AuditEvent
  2. Live real-time SSE streaming consumption (D-07):
     - Ephemeral 30s stream ticket issuance (POST /v1/streams/ticket)
     - Live SSE stream connection (GET /v1/soc/stream?ticket=...)
     - In-order delivery with strictly monotonic cursor progression
     - Safe termination with timeout protection
     - Single-use ticket replay rejection (HTTP 401)
  3. Rule 0 Allowlist enforcement:
     - Attempting containment on allowlisted domains transitions to BLOCKED_BY_ALLOWLIST
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Alert, AuditEvent, Base, Incident, SOCDynamicBlacklist, User
from backend.main import app
from backend.schemas.containment import ContainmentActionStatus, ContainmentActionType
from backend.services.event_broadcaster import event_broadcaster


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
async def reset_broadcaster_state():
    """Ensure complete isolation between streaming and broadcaster test runs."""
    yield
    async with event_broadcaster._lock:
        event_broadcaster._local_subscribers.clear()
        event_broadcaster._admin_subscribers.clear()
        event_broadcaster._queue_metadata.clear()
        event_broadcaster._local_stream_count = 0
        event_broadcaster._user_connection_counts.clear()
        event_broadcaster._admin_connection_counts.clear()
        event_broadcaster._in_memory_tickets.clear()


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
        analyst = User(id=1, email="analyst@soc.corp", hashed_pw="hash1", role="user", is_active=True)
        victim = User(id=2, email="victim@soc.corp", hashed_pw="hash2", role="user", is_active=True)
        admin = User(id=3, email="admin@soc.corp", hashed_pw="hasha", role="admin", is_active=True)
        session.add_all([analyst, victim, admin])
        await session.commit()
    return {"analyst": analyst, "victim": victim, "admin": admin}


def create_authenticated_client(session_factory, user: User) -> AsyncClient:
    async def _get_db():
        async with session_factory() as session:
            yield session

    async def _get_user():
        return user

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user

    transport = ASGITransport(app=app)
    return AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer mock_token_for_{user.id}"},
    )


# ── 1. Full Closed-Loop SOC Lifecycle & Reversible Containment ─────────────────

@pytest.mark.anyio
async def test_soc_full_lifecycle_scan_to_containment(session_factory, seeded_users):
    """
    Validates Decisions D-05 and D-08 across canonical routes:
    Scan -> Alert Discovery -> Incident Creation -> Alert Attachment -> Dynamic Containment -> Reversal.
    """
    analyst = seeded_users["analyst"]
    threat_url = "http://secure-login-paypal.com"  # Hardcoded in LOCAL_BLACKLIST

    async with create_authenticated_client(session_factory, analyst) as client:
        # Step 1: Scan URL for threat intelligence
        scan_payload = {"url": threat_url}
        scan_resp = await client.post("/v1/scan", json=scan_payload)
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["prediction"].lower() in ("phishing", "malicious", "defacement")
        assert scan_data["confidence"] >= 0.8
        assert scan_data["url"] == threat_url

        # Step 2: Seed and retrieve alert associated with the detected threat indicator
        now = datetime.now(timezone.utc)
        alert_seed = Alert(
            alert_uuid=str(uuid.uuid4()),
            title=f"RULE_PHISHING_SCAN: {threat_url}",
            description="Phishing threat detected during threat intelligence scan.",
            severity="HIGH",
            status="OPEN",
            rule_name="RULE_PHISHING_SCAN",
            indicator_type="URL",
            indicator_value=threat_url,
            fingerprint=f"fp_{uuid.uuid4().hex[:12]}",
            occurrence_count=1,
            first_seen_at=now,
            last_seen_at=now,
            user_id=analyst.id,
        )
        async with session_factory() as session:
            session.add(alert_seed)
            await session.commit()
            await session.refresh(alert_seed)

        # Retrieve alert via canonical GET /v1/alerts
        alerts_resp = await client.get("/v1/alerts")
        assert alerts_resp.status_code == 200
        alerts_data = alerts_resp.json()
        assert alerts_data["total"] >= 1
        matching_alert = next((a for a in alerts_data["items"] if a["indicator_value"] == threat_url), None)
        assert matching_alert is not None
        alert_id = matching_alert["id"]
        alert_uuid = matching_alert["alert_uuid"]

        # Create Incident via canonical POST /v1/incidents
        inc_payload = {
            "title": f"Phishing Incursion: {threat_url}",
            "description": "SOC incident opened from automated scan detection.",
            "severity": "HIGH",
        }
        inc_create_resp = await client.post("/v1/incidents", json=inc_payload)
        assert inc_create_resp.status_code == 201
        inc_data = inc_create_resp.json()
        incident_id = inc_data["id"]
        assert inc_data["status"] == "OPEN"
        assert inc_data["created_by_user_id"] == analyst.id

        # Attach alert to incident via canonical POST /v1/incidents/{incident_id}/alerts
        attach_resp = await client.post(
            f"/v1/incidents/{incident_id}/alerts",
            json={"alert_ids": [alert_id]},
        )
        assert attach_resp.status_code == 200
        attach_data = attach_resp.json()
        assert attach_data["alert_count"] >= 1
        assert any(a["id"] == alert_id for a in attach_data["alerts"])

        # Confirm incident alerts listing via canonical GET /v1/incidents/{incident_id}/alerts
        get_inc_alerts_resp = await client.get(f"/v1/incidents/{incident_id}/alerts")
        assert get_inc_alerts_resp.status_code == 200
        inc_alerts_list = get_inc_alerts_resp.json()
        assert any(a["id"] == alert_id for a in inc_alerts_list)

        # Step 3: Dynamic Containment Action (D-08)
        contain_payload = {
            "action_type": ContainmentActionType.BLACKLIST_INDICATOR.value,
            "target_identifier": threat_url,
            "alert_id": alert_id,
            "reason": "Active credential harvester confirmed during incident investigation",
        }
        contain_resp = await client.post("/v1/soc/actions/contain", json=contain_payload)
        assert contain_resp.status_code == 201
        contain_data = contain_resp.json()
        action_uuid = contain_data["action_uuid"]
        assert contain_data["action_type"] == ContainmentActionType.BLACKLIST_INDICATOR.value
        assert contain_data["status"] == ContainmentActionStatus.EXECUTED.value

        # Verify target is marked BLOCKED in SOCDynamicBlacklist table
        async with session_factory() as session:
            stmt = select(SOCDynamicBlacklist).where(
                SOCDynamicBlacklist.tenant_id == analyst.id,
                SOCDynamicBlacklist.indicator_value == threat_url,
            )
            res = await session.execute(stmt)
            bl_entry = res.scalar_one_or_none()
            assert bl_entry is not None
            assert bl_entry.is_active is True
            assert bl_entry.containment_action_id == contain_data["id"]

        # Step 4: Reversible Containment (D-08)
        revert_resp = await client.post(f"/v1/soc/actions/{action_uuid}/revert")
        assert revert_resp.status_code == 200
        revert_data = revert_resp.json()
        assert revert_data["action_uuid"] == action_uuid
        assert revert_data["status"] == ContainmentActionStatus.REVERTED.value
        assert revert_data["reverted_at"] is not None
        assert revert_data["reverted_by_user_id"] == analyst.id

        # Verify target is now UNBLOCKED (is_active is False in SOCDynamicBlacklist)
        async with session_factory() as session:
            stmt = select(SOCDynamicBlacklist).where(
                SOCDynamicBlacklist.tenant_id == analyst.id,
                SOCDynamicBlacklist.indicator_value == threat_url,
            )
            res = await session.execute(stmt)
            reverted_bl = res.scalar_one_or_none()
            assert reverted_bl is not None
            assert reverted_bl.is_active is False

        # Verify audit history is committed for the revert action
        async with session_factory() as session:
            stmt = select(AuditEvent).where(
                AuditEvent.action == "CONTAINMENT_ACTION_REVERTED",
                AuditEvent.resource_id == action_uuid,
            )
            res = await session.execute(stmt)
            audit_entry = res.scalar_one_or_none()
            assert audit_entry is not None
            assert audit_entry.actor_user_id == analyst.id
            assert audit_entry.details.get("action_type") == ContainmentActionType.BLACKLIST_INDICATOR.value


# ── 2. Live SSE Streaming Ticket & Event Consumption ──────────────────────────

@pytest.mark.anyio
async def test_live_sse_stream_ticket_and_event_consumption(session_factory, seeded_users):
    """
    Validates Decision D-07:
    - User requests ephemeral stream ticket via POST /v1/streams/ticket (30s TTL).
    - Connects to GET /v1/soc/stream?ticket={ticket}.
    - Consumes live streamed events over response.aiter_lines() with strict timeout bounding.
    - Validates envelope fields and strictly monotonic cursor progression.
    - Replay with burned ticket returns HTTP 401.
    """
    analyst = seeded_users["analyst"]

    # 1. Acquire stream ticket with authenticated client
    async with create_authenticated_client(session_factory, analyst) as auth_client:
        ticket_resp = await auth_client.post("/v1/streams/ticket", json={"channel": "soc"})
        assert ticket_resp.status_code == 200
        ticket_data = ticket_resp.json()
        ticket = ticket_data["ticket"]
        assert ticket.startswith("st_")
        assert ticket_data["expires_in"] == 30
        assert ticket_data["user_id"] == analyst.id

    # 2. Setup unauthenticated client with DB override for stream consumption
    async def _get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = _get_db
    # Remove get_current_user override so get_stream_user uses ticket auth branch
    app.dependency_overrides.pop(get_current_user, None)

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as stream_client:
            # Coroutine to broadcast events after connection is established
            async def publish_events_after_delay():
                await asyncio.sleep(0.15)
                event_broadcaster.publish_event_nowait(
                    cursor_id=201,
                    event_id=str(uuid.uuid4()),
                    tenant_id=analyst.id,
                    channel="soc",
                    event_type="alert_created",
                    aggregate_id="alt-live-201",
                    payload={"id": "alt-live-201", "severity": "HIGH", "seq": 1},
                )
                await asyncio.sleep(0.05)
                event_broadcaster.publish_event_nowait(
                    cursor_id=202,
                    event_id=str(uuid.uuid4()),
                    tenant_id=analyst.id,
                    channel="soc",
                    event_type="alert_updated",
                    aggregate_id="alt-live-201",
                    payload={"id": "alt-live-201", "status": "ACKNOWLEDGED", "seq": 2},
                )

            pub_task = asyncio.create_task(publish_events_after_delay())
            received_envelopes: list[dict] = []

            # Connect to stream with single-use ticket and max_events=2
            async with stream_client.stream("GET", f"/v1/soc/stream?ticket={ticket}&max_events=2") as response:
                assert response.status_code == 200
                assert "text/event-stream" in response.headers["content-type"]
                assert response.headers.get("x-accel-buffering") == "no"

                # Read events protected by 5.0s timeout to prevent test runner hang
                async with asyncio.timeout(5.0):
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            raw_data = line[len("data: "):].strip()
                            try:
                                payload = json.loads(raw_data)
                                if "cursor_id" in payload:
                                    received_envelopes.append(payload)
                                    if len(received_envelopes) >= 2:
                                        break
                            except json.JSONDecodeError:
                                continue

            await pub_task

            # Assert envelope structure and monotonic progression
            assert len(received_envelopes) == 2, f"Expected 2 envelopes, got: {received_envelopes}"

            e1 = received_envelopes[0]
            e2 = received_envelopes[1]

            assert e1["event_type"] == "alert_created"
            assert e1["tenant_id"] == analyst.id
            assert "timestamp" in e1
            assert e1["data"]["seq"] == 1

            assert e2["event_type"] == "alert_updated"
            assert e2["tenant_id"] == analyst.id
            assert "timestamp" in e2
            assert e2["data"]["seq"] == 2

            # Strict monotonic cursor progression assertion
            assert e1["cursor_id"] == 201
            assert e2["cursor_id"] == 202
            assert e1["cursor_id"] < e2["cursor_id"]

            # 3. Assert ticket replay rejection: ticket was burned upon connection
            replay_resp = await stream_client.get(f"/v1/soc/stream?ticket={ticket}&max_events=0")
            assert replay_resp.status_code == 401
            detail = replay_resp.json()["detail"].lower()
            assert any(term in detail for term in ("invalid", "expired", "consumed"))

    finally:
        app.dependency_overrides.clear()


# ── 3. Rule 0 Allowlist Enforcement ───────────────────────────────────────────

@pytest.mark.anyio
async def test_containment_allowlist_rule_zero(session_factory, seeded_users):
    """
    Validates Rule 0 safety invariant:
    Attempting to blacklist or quarantine a trusted allowlisted domain (e.g. google.com)
    must be blocked and marked BLOCKED_BY_ALLOWLIST without modifying the dynamic blacklist.
    """
    analyst = seeded_users["analyst"]
    trusted_url = "https://google.com/search?q=cyber"

    async with create_authenticated_client(session_factory, analyst) as client:
        payload = {
            "action_type": ContainmentActionType.BLACKLIST_INDICATOR.value,
            "target_identifier": trusted_url,
            "reason": "Accidental containment of trusted service",
        }
        resp = await client.post("/v1/soc/actions/contain", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == ContainmentActionStatus.BLOCKED_BY_ALLOWLIST.value
        assert "allowlisted" in data["error_message"].lower()

        # Confirm no active entry exists in SOCDynamicBlacklist
        async with session_factory() as session:
            stmt = select(SOCDynamicBlacklist).where(
                SOCDynamicBlacklist.tenant_id == analyst.id,
                SOCDynamicBlacklist.indicator_value == trusted_url,
                SOCDynamicBlacklist.is_active.is_(True),
            )
            res = await session.execute(stmt)
            assert res.scalar_one_or_none() is None
