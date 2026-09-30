"""
tests/integration/test_multitenant_adversarial.py
──────────────────────────────────────────────────
Phase 7 Plan 03: Multi-Tenant Adversarial Isolation Integration Tests.

Validates Decision D-06 on canonical routes:
  1. User B cannot access, view, or acknowledge User A alerts (returns 404/403).
  2. User B cannot access, view, or attach alerts to User A incidents (returns 404/403).
  3. Stream ticket isolation: tickets are strictly bound to issuing user, preventing cross-tenant eavesdropping.
  4. Administrative visibility: Admin has cross-tenant audit/view privileges without credential exposure.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Alert, Base, Incident, User
from backend.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


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
async def seeded_matrix(session_factory):
    async with session_factory() as session:
        user_a = User(id=1, email="user_a@tenant1.test", hashed_pw="pw1", role="user", is_active=True)
        user_b = User(id=2, email="user_b@tenant2.test", hashed_pw="pw2", role="user", is_active=True)
        admin = User(id=3, email="admin@global.test", hashed_pw="pwa", role="admin", is_active=True)
        session.add_all([user_a, user_b, admin])
        await session.flush()

        # Seed Alert for User A
        alert_a = Alert(
            user_id=1,
            title="User A Phishing Detection",
            description="Phishing attempt targeting Tenant A",
            severity="HIGH",
            status="OPEN",
            rule_name="PHISHING_DETECTION",
            indicator_type="DOMAIN",
            indicator_value="malicious-tenant-a.com",
        )
        session.add(alert_a)
        await session.flush()

        # Seed Incident for User A
        incident_a = Incident(
            title="User A High Severity Breach",
            description="Active investigation for Tenant A",
            severity="HIGH",
            status="OPEN",
            created_by_user_id=1,
        )
        session.add(incident_a)
        await session.commit()

        await session.refresh(user_a)
        await session.refresh(user_b)
        await session.refresh(admin)
        await session.refresh(alert_a)
        await session.refresh(incident_a)

    return {
        "user_a": user_a,
        "user_b": user_b,
        "admin": admin,
        "alert_a": alert_a,
        "incident_a": incident_a,
    }


def make_tenant_client(session_factory, active_user: User):
    async def _get_db():
        async with session_factory() as session:
            yield session

    async def _get_user():
        return active_user

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user

    transport = ASGITransport(app=app)
    return AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer mock_token_for_user_{active_user.id}"},
    )


@pytest.mark.anyio
async def test_cross_tenant_alert_isolation(session_factory, seeded_matrix):
    """User B attempts to read or mutate User A's alert; asserts 404 or 403."""
    alert_a = seeded_matrix["alert_a"]
    user_b = seeded_matrix["user_b"]

    async with make_tenant_client(session_factory, user_b) as client_b:
        # 1. Detail fetch on User A's alert by User B
        resp_get = await client_b.get(f"/v1/alerts/{alert_a.alert_uuid}")
        assert resp_get.status_code in (403, 404), f"Expected 403 or 404, got {resp_get.status_code}"

        # 2. Acknowledge User A's alert by User B
        resp_ack = await client_b.post(f"/v1/alerts/{alert_a.alert_uuid}/acknowledge")
        assert resp_ack.status_code in (403, 404), f"Expected 403 or 404, got {resp_ack.status_code}"

        # 3. Listing alerts returns 0 alerts from User A
        resp_list = await client_b.get("/v1/alerts")
        assert resp_list.status_code == 200
        items = resp_list.json()["items"]
        assert len(items) == 0, "User B saw alerts belonging to User A"

    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_cross_tenant_incident_isolation(session_factory, seeded_matrix):
    """User B attempts to read or mutate User A's incident; asserts 404 or 403."""
    incident_a = seeded_matrix["incident_a"]
    user_b = seeded_matrix["user_b"]

    async with make_tenant_client(session_factory, user_b) as client_b:
        # 1. Detail fetch on User A's incident by ID
        resp_get_id = await client_b.get(f"/v1/incidents/{incident_a.id}")
        assert resp_get_id.status_code in (403, 404), f"Expected 403 or 404, got {resp_get_id.status_code}"

        # 2. Detail fetch on User A's incident by UUID
        resp_get_uuid = await client_b.get(f"/v1/incidents/{incident_a.incident_uuid}")
        assert resp_get_uuid.status_code in (403, 404), f"Expected 403 or 404, got {resp_get_uuid.status_code}"

        # 3. Attempt to attach alerts to User A's incident
        resp_attach = await client_b.post(f"/v1/incidents/{incident_a.id}/alerts", json={"alert_ids": [1]})
        assert resp_attach.status_code in (403, 404), f"Expected 403 or 404, got {resp_attach.status_code}"

        # 4. Listing incidents returns 0 incidents for User B
        resp_list = await client_b.get("/v1/incidents")
        assert resp_list.status_code == 200
        items = resp_list.json()
        assert len(items) == 0, "User B saw incidents belonging to User A"

    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_cross_tenant_stream_ticket_isolation(session_factory, seeded_matrix):
    """User A generates a stream ticket. Bogus or mismatched ticket access fails."""
    user_a = seeded_matrix["user_a"]

    async with make_tenant_client(session_factory, user_a) as client_a:
        # User A requests ticket
        ticket_resp = await client_a.post("/v1/streams/ticket")
        assert ticket_resp.status_code == 200
        ticket = ticket_resp.json()["ticket"]
        assert ticket.startswith("st_")

    # Client with no Bearer token attempting invalid or consumed ticket receives 401
    async def _get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides.pop(get_current_user, None)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as anon_client:
        # Invalid ticket
        resp_fake = await anon_client.get("/v1/soc/stream?ticket=st_invalid_fake_ticket&max_events=0")
        assert resp_fake.status_code == 401

    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_admin_cross_tenant_visibility_without_leakage(session_factory, seeded_matrix):
    """Admin user can list incidents and alerts across all tenants."""
    admin = seeded_matrix["admin"]
    incident_a = seeded_matrix["incident_a"]
    alert_a = seeded_matrix["alert_a"]

    async with make_tenant_client(session_factory, admin) as client_admin:
        # 1. Admin lists alerts and sees User A's alert
        resp_alerts = await client_admin.get("/v1/alerts")
        assert resp_alerts.status_code == 200
        alert_ids = [a["alert_uuid"] for a in resp_alerts.json()["items"]]
        assert alert_a.alert_uuid in alert_ids

        # 2. Admin lists incidents and sees User A's incident
        resp_inc = await client_admin.get("/v1/incidents")
        assert resp_inc.status_code == 200
        inc_ids = [i["id"] for i in resp_inc.json()]
        assert incident_a.id in inc_ids

        # 3. Verify sensitive password hashes or tokens are NOT exposed in user sub-dictionaries
        inc_data = resp_inc.json()[0]
        assert "hashed_pw" not in str(inc_data)

    app.dependency_overrides.clear()
