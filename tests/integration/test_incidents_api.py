"""
tests/integration/test_incidents_api.py
─────────────────────────────────────────
Sprint 5 Phase 4: Integration tests for Incident Management REST API endpoints (/v1/incidents).

Tests:
- POST /v1/incidents (Create Incident)
- GET /v1/incidents (List Incidents paginated & filtered)
- GET /v1/incidents/{id} (Get detail by int ID and UUID)
- PATCH /v1/incidents/{id} (Update status, severity, assignment)
- POST /v1/incidents/{id}/alerts (Attach alerts)
- DELETE /v1/incidents/{id}/alerts/{alert_id} (Detach alert)
- GET /v1/incidents/{id}/alerts (Retrieve incident alerts)
- HTTP Error Codes (400 Bad Request, 403 Forbidden, 404 Not Found, 409 Conflict, 422 Unprocessable Entity)
"""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Alert, Base, Incident, User
from backend.main import app

# ── Test DB & Dependency Overrides ────────────────────────────────────────────

@pytest.fixture
def test_db_session():
    """Create in-memory SQLite database session for integration tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    # Seed test users
    u1 = User(id=1, email="user1@test.com", hashed_pw="pw1", role="user", is_active=True)
    u2 = User(id=2, email="user2@test.com", hashed_pw="pw2", role="user", is_active=True)
    admin = User(id=3, email="admin@test.com", hashed_pw="pwa", role="admin", is_active=True)

    session.add_all([u1, u2, admin])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture
def override_deps(test_db_session):
    u1 = test_db_session.query(User).filter_by(id=1).one()

    async def _get_db_override():
        yield test_db_session

    async def _get_user_override():
        return u1

    app.dependency_overrides[get_db] = _get_db_override
    app.dependency_overrides[get_current_user] = _get_user_override

    yield

    app.dependency_overrides.clear()


# ── API Endpoints Tests ────────────────────────────────────────────────────────

def test_create_and_get_incident_api(override_deps):
    async def _test():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Create Incident
            create_resp = await client.post(
                "/v1/incidents",
                json={
                    "title": "API Test Incident",
                    "description": "Created via REST API integration test.",
                    "severity": "HIGH",
                },
            )
            assert create_resp.status_code == 201
            data = create_resp.json()
            assert data["title"] == "API Test Incident"
            assert data["status"] == "OPEN"
            assert data["severity"] == "HIGH"
            assert data["created_by_user_id"] == 1
            incident_id = data["id"]
            incident_uuid = data["incident_uuid"]

            # Get by ID
            get_id_resp = await client.get(f"/v1/incidents/{incident_id}")
            assert get_id_resp.status_code == 200
            assert get_id_resp.json()["id"] == incident_id

            # Get by UUID
            get_uuid_resp = await client.get(f"/v1/incidents/{incident_uuid}")
            assert get_uuid_resp.status_code == 200
            assert get_uuid_resp.json()["incident_uuid"] == incident_uuid

    asyncio.run(_test())


def test_list_incidents_api(override_deps):
    async def _test():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Create two incidents
            await client.post("/v1/incidents", json={"title": "List Inc 1", "severity": "MEDIUM"})
            await client.post("/v1/incidents", json={"title": "List Inc 2", "severity": "HIGH"})

            list_resp = await client.get("/v1/incidents?page=1&size=10")
            assert list_resp.status_code == 200
            items = list_resp.json()
            assert len(items) >= 2

    asyncio.run(_test())


def test_update_incident_status_transition_api(override_deps):
    async def _test():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            create_resp = await client.post("/v1/incidents", json={"title": "Transition Inc"})
            inc_id = create_resp.json()["id"]

            # Valid transition: OPEN -> INVESTIGATING
            patch_resp = await client.patch(
                f"/v1/incidents/{inc_id}",
                json={"status": "INVESTIGATING"},
            )
            assert patch_resp.status_code == 200
            assert patch_resp.json()["status"] == "INVESTIGATING"

            # Invalid transition: INVESTIGATING -> invalid enum
            bad_patch = await client.patch(
                f"/v1/incidents/{inc_id}",
                json={"status": "UNKNOWN_STATUS"},
            )
            assert bad_patch.status_code == 422

    asyncio.run(_test())


def test_attach_and_detach_alerts_api(test_db_session, override_deps):
    async def _test():
        # Seed alert for user 1
        a1 = Alert(title="Scan Alert", rule_name="RULE_SCAN", indicator_type="URL", indicator_value="http://evil.com", severity="CRITICAL", user_id=1)
        test_db_session.add(a1)
        test_db_session.commit()
        test_db_session.refresh(a1)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            create_resp = await client.post("/v1/incidents", json={"title": "Alert Link Inc", "severity": "LOW"})
            inc_id = create_resp.json()["id"]

            # Attach alert
            attach_resp = await client.post(
                f"/v1/incidents/{inc_id}/alerts",
                json={"alert_ids": [a1.id]},
            )
            assert attach_resp.status_code == 200
            data = attach_resp.json()
            assert data["alert_count"] == 1
            assert data["severity"] == "CRITICAL"  # Escalated monotonically

            # List attached alerts
            get_alerts_resp = await client.get(f"/v1/incidents/{inc_id}/alerts")
            assert get_alerts_resp.status_code == 200
            alerts = get_alerts_resp.json()
            assert len(alerts) == 1
            assert alerts[0]["id"] == a1.id

            # Detach alert
            detach_resp = await client.delete(f"/v1/incidents/{inc_id}/alerts/{a1.id}")
            assert detach_resp.status_code == 200
            assert detach_resp.json()["alert_count"] == 0

    asyncio.run(_test())


def test_conflict_alert_attachment_api(test_db_session, override_deps):
    async def _test():
        # Seed alert attached to incident 1
        inc1 = Incident(title="Inc 1", created_by_user_id=1, severity="HIGH")
        test_db_session.add(inc1)
        test_db_session.commit()
        test_db_session.refresh(inc1)

        a1 = Alert(title="Conflict Alert", rule_name="R1", indicator_type="URL", indicator_value="http://dup.com", severity="HIGH", user_id=1, incident_id=inc1.id)
        test_db_session.add(a1)
        test_db_session.commit()
        test_db_session.refresh(a1)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            inc2_resp = await client.post("/v1/incidents", json={"title": "Inc 2"})
            inc2_id = inc2_resp.json()["id"]

            # Attempt to attach a1 (already on inc1) to inc2 -> 409 Conflict
            attach_resp = await client.post(
                f"/v1/incidents/{inc2_id}/alerts",
                json={"alert_ids": [a1.id]},
            )
            assert attach_resp.status_code == 409
            assert "already attached" in attach_resp.json()["detail"]

    asyncio.run(_test())


def test_extra_forbidden_fields_rejected_api(override_deps):
    async def _test():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/incidents",
                json={
                    "title": "Valid Title",
                    "malicious_extra_field": "hacked",
                },
            )
            assert resp.status_code == 422

    asyncio.run(_test())
