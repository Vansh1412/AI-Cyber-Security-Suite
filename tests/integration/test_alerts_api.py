"""
tests/integration/test_alerts_api.py
────────────────────────────────────
Sprint 5 Phase 5C: Integration tests for Security Alert Management & Operational Target REST APIs.

Endpoints tested:
  - GET    /v1/alerts (listing, pagination, filtering, multi-tenant scoping)
  - GET    /v1/alerts/stats (telemetry, velocity, dedup savings ratio)
  - GET    /v1/alerts/{uuid} (detail, 404 anti-enumeration)
  - POST   /v1/alerts/{uuid}/acknowledge
  - POST   /v1/alerts/{uuid}/resolve
  - POST   /v1/alerts/{uuid}/dismiss (validation: 422 if dismiss_reason missing/short)
  - POST   /v1/alerts/{uuid}/reopen
  - Forbidden transitions (HTTP 400 Bad Request)
  - POST   /v1/monitor/targets/{uuid}/pause
  - POST   /v1/monitor/targets/{uuid}/resume (409 Conflict on auto-suspended)
  - POST   /v1/monitor/targets/{uuid}/reactivate
  - POST   /v1/monitor/targets/{uuid}/check-now (200 with token, 409 on conflict)
  - GET    /v1/monitor/targets/{uuid}/diagnostics
  - GET    /v1/monitor/stats
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.dependencies import get_current_user, get_db
from backend.database.models import Alert, Base, MonitoringTarget, User
from backend.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_engine():
    """Create in-memory SQLite async engine with StaticPool for integration tests."""
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
        u1 = User(id=1, email="user1@soc.test", hashed_pw="pw1", role="user", is_active=True)
        u2 = User(id=2, email="user2@soc.test", hashed_pw="pw2", role="user", is_active=True)
        admin = User(id=3, email="admin@soc.test", hashed_pw="pwa", role="admin", is_active=True)
        session.add_all([u1, u2, admin])
        await session.commit()
    yield session_factory


@pytest.fixture
def client_factory(seeded_session):
    """Factory to create an AsyncClient authenticated as a specific user."""
    def _create(user_id: int = 1):
        async def _get_db_override():
            async with seeded_session() as session:
                yield session

        async def _get_user_override():
            async with seeded_session() as session:
                res = await session.execute(select(User).where(User.id == user_id))
                return res.scalar_one()

        app.dependency_overrides[get_db] = _get_db_override
        app.dependency_overrides[get_current_user] = _get_user_override

        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    yield _create

    app.dependency_overrides.clear()


async def _seed_alert(
    session_factory,
    user_id: int = 1,
    status: str = "OPEN",
    severity: str = "HIGH",
    rule_name: str = "RULE_PHISHING",
    indicator_type: str = "DOMAIN",
    indicator_value: str = "bad.example.com",
) -> Alert:
    now = datetime.now(timezone.utc)
    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        title=f"Test Alert {rule_name}",
        description="Alert for integration testing",
        severity=severity,
        status=status,
        rule_name=rule_name,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        fingerprint=f"fp_{uuid.uuid4().hex[:12]}",
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
        user_id=user_id,
    )
    async with session_factory() as session:
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
    return alert


async def _seed_target(
    session_factory,
    user_id: int = 1,
    is_active: bool = True,
    consecutive_failures: int = 0,
) -> MonitoringTarget:
    now = datetime.now(timezone.utc)
    target = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url="https://api-target.example.com",
        normalized_domain="api-target.example.com",
        check_interval_minutes=5,
        is_active=is_active,
        next_check_at=now,
        consecutive_failures=consecutive_failures,
        user_id=user_id,
        created_at=now,
    )
    async with session_factory() as session:
        session.add(target)
        await session.commit()
        await session.refresh(target)
    return target


# ── Alert API Integration Tests ───────────────────────────────────────────────

@pytest.mark.anyio
async def test_list_alerts_tenant_isolation_and_filters(seeded_session, client_factory):
    """User 1 only sees user 1's alerts; Admin sees all alerts."""
    await _seed_alert(seeded_session, user_id=1, severity="CRITICAL", rule_name="RULE_A")
    await _seed_alert(seeded_session, user_id=1, severity="LOW", rule_name="RULE_B")
    await _seed_alert(seeded_session, user_id=2, severity="HIGH", rule_name="RULE_C")

    # User 1 client
    async with client_factory(user_id=1) as client_u1:
        resp = await client_u1.get("/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["user_id"] == 1

        # Filtering by severity
        crit_resp = await client_u1.get("/v1/alerts?severity=CRITICAL")
        assert crit_resp.status_code == 200
        crit_data = crit_resp.json()
        assert crit_data["total"] == 1
        assert crit_data["items"][0]["severity"] == "CRITICAL"

    # User 2 client
    async with client_factory(user_id=2) as client_u2:
        resp = await client_u2.get("/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["user_id"] == 2

    # Admin client
    async with client_factory(user_id=3) as client_admin:
        resp = await client_admin.get("/v1/alerts")
        assert resp.status_code == 200
        assert resp.json()["total"] == 3


@pytest.mark.anyio
async def test_get_alert_detail_anti_enumeration(seeded_session, client_factory):
    """Attempting to view another tenant's alert returns 404 Not Found."""
    a1 = await _seed_alert(seeded_session, user_id=1)

    # User 1 accesses own alert -> 200
    async with client_factory(user_id=1) as client_u1:
        resp = await client_u1.get(f"/v1/alerts/{a1.alert_uuid}")
        assert resp.status_code == 200
        assert resp.json()["alert_uuid"] == a1.alert_uuid

    # User 2 accesses User 1's alert -> 404 (anti-enumeration)
    async with client_factory(user_id=2) as client_u2:
        resp = await client_u2.get(f"/v1/alerts/{a1.alert_uuid}")
        assert resp.status_code == 404

    # Non-existent UUID -> 404
    async with client_factory(user_id=1) as client_u1:
        resp = await client_u1.get(f"/v1/alerts/{uuid.uuid4()}")
        assert resp.status_code == 404


@pytest.mark.anyio
async def test_alert_triage_endpoints_lifecycle(seeded_session, client_factory):
    """Full triage lifecycle via HTTP endpoints: ACK -> RESOLVE -> REOPEN -> DISMISS."""
    alert = await _seed_alert(seeded_session, user_id=1, status="OPEN")
    alert_uuid = alert.alert_uuid

    async with client_factory(user_id=1) as client:
        # 1. Acknowledge
        ack_resp = await client.post(
            f"/v1/alerts/{alert_uuid}/acknowledge",
            json={"notes": "Analyst investigating"},
        )
        assert ack_resp.status_code == 200
        assert ack_resp.json()["status"] == "ACKNOWLEDGED"

        # 2. Resolve
        res_resp = await client.post(
            f"/v1/alerts/{alert_uuid}/resolve",
            json={"resolution_notes": "Threat neutralized"},
        )
        assert res_resp.status_code == 200
        assert res_resp.json()["status"] == "RESOLVED"

        # 3. Forbidden terminal flip: RESOLVED -> DISMISSED returns 400
        bad_flip = await client.post(
            f"/v1/alerts/{alert_uuid}/dismiss",
            json={"dismiss_reason": "FALSE_POSITIVE"},
        )
        assert bad_flip.status_code == 400

        # 4. Reopen
        reopen_resp = await client.post(
            f"/v1/alerts/{alert_uuid}/reopen",
            json={"reopen_notes": "New telemetry detected"},
        )
        assert reopen_resp.status_code == 200
        assert reopen_resp.json()["status"] == "OPEN"

        # 5. Dismiss with short reason (< 3 chars) returns 422
        bad_dismiss = await client.post(
            f"/v1/alerts/{alert_uuid}/dismiss",
            json={"dismiss_reason": "no"},
        )
        assert bad_dismiss.status_code == 422

        # 6. Valid dismiss
        dismiss_resp = await client.post(
            f"/v1/alerts/{alert_uuid}/dismiss",
            json={"dismiss_reason": "AUTHORIZED_TEST", "notes": "Approved pentest"},
        )
        assert dismiss_resp.status_code == 200
        assert dismiss_resp.json()["status"] == "DISMISSED"
        assert dismiss_resp.json()["dismiss_reason"] == "AUTHORIZED_TEST"


@pytest.mark.anyio
async def test_alert_stats_endpoint(seeded_session, client_factory):
    """GET /v1/alerts/stats returns aggregated metrics and dedup savings ratio."""
    await _seed_alert(seeded_session, user_id=1, status="OPEN")
    await _seed_alert(seeded_session, user_id=1, status="ACKNOWLEDGED")

    async with client_factory(user_id=1) as client:
        resp = await client.get("/v1/alerts/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_alerts"] == 2
        assert data["open_alerts"] == 1
        assert data["acknowledged_alerts"] == 1
        assert 0.0 <= data["dedup_savings_ratio"] <= 1.0


@pytest.mark.anyio
async def test_forbidden_terminal_flip_dismissed_to_resolved_returns_400(seeded_session, client_factory):
    """
    CONTRACT: DISMISSED -> RESOLVED is a forbidden terminal flip.
    MUST return HTTP 400 Bad Request (not 409 Conflict).
    409 is reserved for resource-level conflicts (e.g., active execution lease, suspended resume).
    """
    alert = await _seed_alert(seeded_session, user_id=1, status="OPEN")
    alert_uuid = alert.alert_uuid

    async with client_factory(user_id=1) as client:
        # Dismiss the alert first
        dismiss_resp = await client.post(
            f"/v1/alerts/{alert_uuid}/dismiss",
            json={"dismiss_reason": "FALSE_POSITIVE", "notes": "Authorized scan"},
        )
        assert dismiss_resp.status_code == 200
        assert dismiss_resp.json()["status"] == "DISMISSED"

        # Attempt forbidden terminal flip: DISMISSED -> RESOLVED
        bad_flip_resp = await client.post(
            f"/v1/alerts/{alert_uuid}/resolve",
            json={"resolution_notes": "Attempting illegal flip"},
        )
        # MUST be 400 Bad Request, not 409
        assert bad_flip_resp.status_code == 400, (
            f"DISMISSED->RESOLVED must return 400, got {bad_flip_resp.status_code}"
        )


# ── Monitoring Operational Endpoints Tests ────────────────────────────────────

@pytest.mark.anyio
async def test_monitor_pause_resume_reactivate_endpoints(seeded_session, client_factory):
    """Operational state transitions via REST API."""
    target = await _seed_target(seeded_session, user_id=1, is_active=True, consecutive_failures=0)
    tuuid = target.target_uuid

    async with client_factory(user_id=1) as client:
        # Pause
        p_resp = await client.post(f"/v1/monitor/targets/{tuuid}/pause")
        assert p_resp.status_code == 200
        assert p_resp.json()["is_active"] is False

        # Verify pause preserved consecutive_failures (was 0, must still be 0)
        assert p_resp.json()["consecutive_failures"] == 0

        # Resume
        r_resp = await client.post(f"/v1/monitor/targets/{tuuid}/resume")
        assert r_resp.status_code == 200
        assert r_resp.json()["is_active"] is True

        # Simulate 5 failures -> auto-suspended
        async with seeded_session() as s:
            t = (await s.execute(select(MonitoringTarget).where(MonitoringTarget.target_uuid == tuuid))).scalar_one()
            t.consecutive_failures = 5
            t.is_active = False
            await s.commit()

        # Resume on auto-suspended target -> 409 Conflict
        susp_resp = await client.post(f"/v1/monitor/targets/{tuuid}/resume")
        assert susp_resp.status_code == 409

        # Pause on auto-suspended target -> 409 Conflict (must NOT silently reinterpret as PAUSED)
        susp_pause_resp = await client.post(f"/v1/monitor/targets/{tuuid}/pause")
        assert susp_pause_resp.status_code == 409, (
            f"Pausing a SUSPENDED target must return 409, got {susp_pause_resp.status_code}"
        )

        # Reactivate recovers target
        react_resp = await client.post(f"/v1/monitor/targets/{tuuid}/reactivate")
        assert react_resp.status_code == 200
        data = react_resp.json()
        assert data["is_active"] is True
        assert data["consecutive_failures"] == 0



@pytest.mark.anyio
async def test_monitor_check_now_api(seeded_session, client_factory):
    """POST /v1/monitor/targets/{uuid}/check-now dispatches target and rejects conflicts."""
    target = await _seed_target(seeded_session, user_id=1, is_active=True)
    tuuid = target.target_uuid

    async with client_factory(user_id=1) as client:
        with patch("backend.services.monitoring_worker.monitoring_worker_pool.submit_target", new_callable=AsyncMock):
            resp = await client.post(f"/v1/monitor/targets/{tuuid}/check-now")
            assert resp.status_code == 200
            data = resp.json()
            assert data["target_uuid"] == tuuid
            assert "execution_token" in data

            # Second call while lease is active returns 409 Conflict
            resp2 = await client.post(f"/v1/monitor/targets/{tuuid}/check-now")
            assert resp2.status_code == 409


@pytest.mark.anyio
async def test_monitor_diagnostics_and_stats_api(seeded_session, client_factory):
    """GET /v1/monitor/targets/{uuid}/diagnostics and GET /v1/monitor/stats."""
    target = await _seed_target(seeded_session, user_id=1, is_active=True)
    tuuid = target.target_uuid

    async with seeded_session() as s:
        t = (await s.execute(select(MonitoringTarget).where(MonitoringTarget.target_uuid == tuuid))).scalar_one()
        t.last_status_code = 200
        t.last_response_time_ms = 94.2
        t.last_prediction = "BENIGN"
        t.last_confidence = 0.99
        await s.commit()

    async with client_factory(user_id=1) as client:
        # Diagnostics
        diag_resp = await client.get(f"/v1/monitor/targets/{tuuid}/diagnostics")
        assert diag_resp.status_code == 200
        diag = diag_resp.json()
        assert diag["target_uuid"] == tuuid
        assert diag["last_status_code"] == 200
        assert diag["last_response_time_ms"] == 94.2

        # Stats
        stats_resp = await client.get("/v1/monitor/stats")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_targets"] >= 1
        assert stats["active_targets"] >= 1
        assert stats["pool_capacity"] == 10
