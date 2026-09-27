"""
tests/integration/test_containment_api.py
─────────────────────────────────────────
Sprint 5 Phase 5F: Integration tests for Containment REST API.

Endpoints:
  - POST /v1/soc/actions/contain
  - GET  /v1/soc/actions
  - GET  /v1/soc/actions/{action_uuid}
  - POST /v1/soc/actions/{action_uuid}/revert
  - GET  /v1/soc/playbooks/runs
  - GET  /v1/soc/containment/policy
  - PUT  /v1/soc/containment/policy
"""

from __future__ import annotations

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Base, User
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
async def seeded_session(session_factory):
    async with session_factory() as session:
        u1 = User(id=1, email="tenant1@soc.test", hashed_pw="pw1", role="user", is_active=True)
        u2 = User(id=2, email="tenant2@soc.test", hashed_pw="pw2", role="user", is_active=True)
        admin = User(id=3, email="admin@soc.test", hashed_pw="pwa", role="admin", is_active=True)
        session.add_all([u1, u2, admin])
        await session.commit()
    yield session_factory


@pytest.fixture
def client_factory(seeded_session):
    async def _get_db_override():
        async with seeded_session() as session:
            yield session

    async def _get_user_override(request: Request):
        uid_header = request.headers.get("x-test-user-id")
        uid = int(uid_header) if uid_header else 1
        async with seeded_session() as session:
            res = await session.execute(select(User).where(User.id == uid))
            return res.scalar_one()

    app.dependency_overrides[get_db] = _get_db_override
    app.dependency_overrides[get_current_user] = _get_user_override

    def _create(user_id: int = 1):
        transport = ASGITransport(app=app)
        return AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"x-test-user-id": str(user_id)},
        )

    yield _create
    app.dependency_overrides.clear()


# ── 1. POST /v1/soc/actions/contain Tests ─────────────────────────────────────

@pytest.mark.anyio
async def test_manual_containment_action_api(client_factory):
    """Verify manual containment action creation returns 201 and persists."""
    client = client_factory(user_id=1)
    payload = {
        "action_type": "BLACKLIST_INDICATOR",
        "target_identifier": "https://threat-site.xyz/malware",
        "reason": "Security analyst manual block",
    }
    resp = await client.post("/v1/soc/actions/contain", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["action_type"] == "BLACKLIST_INDICATOR"
    assert data["target_identifier"] == "https://threat-site.xyz/malware"
    assert data["status"] in ("EXECUTED", "BLOCKED_BY_ALLOWLIST")
    assert "action_uuid" in data


# ── 2. GET /v1/soc/actions & Tenant Isolation Tests ───────────────────────────

@pytest.mark.anyio
async def test_list_actions_tenant_isolation(client_factory):
    """Verify list actions returns only the authenticated tenant's actions."""
    client1 = client_factory(user_id=1)
    client2 = client_factory(user_id=2)

    # Tenant 1 creates action
    p1 = {
        "action_type": "BLACKLIST_INDICATOR",
        "target_identifier": "https://tenant1-threat.xyz",
        "reason": "T1 block",
    }
    resp1 = await client1.post("/v1/soc/actions/contain", json=p1)
    assert resp1.status_code == 201
    uuid1 = resp1.json()["action_uuid"]

    # Tenant 2 lists actions -> must be empty
    list_resp2 = await client2.get("/v1/soc/actions")
    assert list_resp2.status_code == 200
    assert list_resp2.json()["total"] == 0

    # Tenant 2 attempts to get Tenant 1's action by UUID -> must return 404 (anti-enumeration)
    detail_resp2 = await client2.get(f"/v1/soc/actions/{uuid1}")
    assert detail_resp2.status_code == 404

    # Tenant 1 gets own action -> 200
    detail_resp1 = await client1.get(f"/v1/soc/actions/{uuid1}")
    assert detail_resp1.status_code == 200
    assert detail_resp1.json()["action_uuid"] == uuid1


# ── 3. POST /v1/soc/actions/{action_uuid}/revert Tests ────────────────────────

@pytest.mark.anyio
async def test_revert_action_api(client_factory):
    """Verify reverting an executed action sets status to REVERTED."""
    client = client_factory(user_id=1)
    payload = {
        "action_type": "BLACKLIST_INDICATOR",
        "target_identifier": "https://phish-to-revert.xyz",
        "reason": "Temp block",
    }
    create_resp = await client.post("/v1/soc/actions/contain", json=payload)
    assert create_resp.status_code == 201
    uuid_val = create_resp.json()["action_uuid"]

    # Revert action
    revert_resp = await client.post(f"/v1/soc/actions/{uuid_val}/revert")
    assert revert_resp.status_code == 200
    assert revert_resp.json()["status"] == "REVERTED"
    assert revert_resp.json()["reverted_at"] is not None


# ── 4. Policy API Tests ───────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_policy_api_lifecycle(client_factory):
    """Verify getting default policy and updating it with optimistic versioning."""
    client = client_factory(user_id=1)

    # 1. Get default policy
    get_resp = await client.get("/v1/soc/containment/policy")
    assert get_resp.status_code == 200
    pdata = get_resp.json()
    assert pdata["auto_containment_enabled"] is False
    assert pdata["policy_version"] == 1

    # 2. Update policy
    up_payload = {
        "auto_containment_enabled": True,
        "auto_blacklist_enabled": True,
        "auto_quarantine_enabled": False,
        "auto_incident_binding_enabled": True,
        "containment_min_severity": "HIGH",
        "blacklist_ttl_seconds": 86400,
        "policy_version": 1,
    }
    put_resp = await client.put("/v1/soc/containment/policy", json=up_payload)
    assert put_resp.status_code == 200
    updated_data = put_resp.json()
    assert updated_data["auto_containment_enabled"] is True
    assert updated_data["policy_version"] == 2

    # 3. Conflicting update (stale version 1)
    conflict_resp = await client.put("/v1/soc/containment/policy", json=up_payload)
    assert conflict_resp.status_code == 409
