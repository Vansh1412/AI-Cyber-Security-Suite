"""
tests/integration/test_notifications_api.py
───────────────────────────────────────────
Sprint 5 Phase 5D: Integration tests for Notification & Preference REST APIs.

Endpoints tested:
  - GET    /v1/notifications
  - GET    /v1/notifications/unread-count
  - POST   /v1/notifications/{uuid}/read
  - POST   /v1/notifications/mark-all-read
  - GET    /v1/notifications/preferences
  - PUT    /v1/notifications/preferences
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
from backend.database.models import Base, Notification, User
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


async def _seed_notification(session_factory, user_id: int = 1, severity: str = "HIGH", is_read: bool = False):
    async with session_factory() as session:
        notif = Notification(
            notification_uuid=str(uuid.uuid4()),
            user_id=user_id,
            title=f"Test Notification {severity}",
            message="Test alert description.",
            severity=severity,
            is_read=is_read,
            link_url="/alerts/test",
            created_at=datetime.now(timezone.utc),
        )
        session.add(notif)
        await session.commit()
        await session.refresh(notif)
        return notif


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_list_notifications_pagination_and_scoping(client_factory, seeded_session):
    """Verify notification listing respects pagination and tenant scoping."""
    # Seed 3 notifications for user 1 and 1 notification for user 2
    n1 = await _seed_notification(seeded_session, user_id=1, severity="CRITICAL", is_read=False)
    await _seed_notification(seeded_session, user_id=1, severity="HIGH", is_read=False)
    n3 = await _seed_notification(seeded_session, user_id=1, severity="LOW", is_read=True)
    await _seed_notification(seeded_session, user_id=2, severity="CRITICAL", is_read=False)

    async with client_factory(user_id=1) as client:
        resp = await client.get("/v1/notifications?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()

        assert data["total"] == 3
        assert data["unread_count"] == 2
        assert len(data["items"]) == 2
        assert data["has_next"] is True

        # Test filtering by is_read=true
        resp_read = await client.get("/v1/notifications?is_read=true")
        assert resp_read.status_code == 200
        data_read = resp_read.json()
        assert data_read["total"] == 1
        assert data_read["items"][0]["notification_uuid"] == n3.notification_uuid

        # Test filtering by severity=CRITICAL
        resp_crit = await client.get("/v1/notifications?severity=CRITICAL")
        assert resp_crit.status_code == 200
        data_crit = resp_crit.json()
        assert data_crit["total"] == 1
        assert data_crit["items"][0]["notification_uuid"] == n1.notification_uuid


@pytest.mark.anyio
async def test_get_unread_count(client_factory, seeded_session):
    """Verify unread count accurately reflects user's unread notifications."""
    await _seed_notification(seeded_session, user_id=1, is_read=False)
    await _seed_notification(seeded_session, user_id=1, is_read=False)
    await _seed_notification(seeded_session, user_id=1, is_read=True)

    async with client_factory(user_id=1) as client:
        resp = await client.get("/v1/notifications/unread-count")
        assert resp.status_code == 200
        assert resp.json()["unread_count"] == 2


@pytest.mark.anyio
async def test_mark_notification_read_and_anti_enumeration(client_factory, seeded_session):
    """Verify marking read is idempotent, and foreign tenant lookup returns 404."""
    notif_u1 = await _seed_notification(seeded_session, user_id=1, is_read=False)
    notif_u2 = await _seed_notification(seeded_session, user_id=2, is_read=False)

    async with client_factory(user_id=1) as client:
        # Mark own notification read
        resp = await client.post(f"/v1/notifications/{notif_u1.notification_uuid}/read")
        assert resp.status_code == 200
        assert resp.json()["is_read"] is True

        # Idempotent call
        resp_idem = await client.post(f"/v1/notifications/{notif_u1.notification_uuid}/read")
        assert resp_idem.status_code == 200
        assert resp_idem.json()["is_read"] is True

        # Anti-enumeration: access user 2's notification returns 404
        resp_foreign = await client.post(f"/v1/notifications/{notif_u2.notification_uuid}/read")
        assert resp_foreign.status_code == 404

        # Non-existent UUID returns 404
        resp_none = await client.post(f"/v1/notifications/{uuid.uuid4()}/read")
        assert resp_none.status_code == 404


@pytest.mark.anyio
async def test_mark_all_notifications_read(client_factory, seeded_session):
    """Verify mark-all-read updates all unread notifications for tenant."""
    await _seed_notification(seeded_session, user_id=1, is_read=False)
    await _seed_notification(seeded_session, user_id=1, is_read=False)
    await _seed_notification(seeded_session, user_id=2, is_read=False)

    async with client_factory(user_id=1) as client:
        resp = await client.post("/v1/notifications/mark-all-read")
        assert resp.status_code == 200
        assert resp.json()["updated_count"] == 2

        # Verify unread count is now 0
        resp_count = await client.get("/v1/notifications/unread-count")
        assert resp_count.json()["unread_count"] == 0

    # Verify user 2 was unaffected
    async with client_factory(user_id=2) as client:
        resp_u2 = await client.get("/v1/notifications/unread-count")
        assert resp_u2.json()["unread_count"] == 1


@pytest.mark.anyio
async def test_get_and_update_preferences_lifecycle(client_factory, seeded_session):
    """Verify preferences retrieval, masked preview, and secure update lifecycle."""
    async with client_factory(user_id=1) as client:
        # Initial get
        resp_get = await client.get("/v1/notifications/preferences")
        assert resp_get.status_code == 200
        pref = resp_get.json()
        assert pref["in_app_enabled"] is True
        assert pref["webhook_enabled"] is False
        assert pref["has_webhook_secret"] is False

        # Mock SSRF DNS validation for public partner URL
        with patch("backend.services.notification_service.resolve_and_validate_host", new_callable=AsyncMock) as mock_dns:
            mock_dns.return_value = ["93.184.216.34"]

            # Update webhook URL and user secret
            secret_32chars = "secure_webhook_secret_key_string_32chars"
            resp_update = await client.put(
                "/v1/notifications/preferences",
                json={
                    "webhook_enabled": True,
                    "webhook_url": "https://siem.example.com/webhook",
                    "webhook_secret": secret_32chars,
                    "min_severity": "CRITICAL",
                },
            )
            assert resp_update.status_code == 200
            updated = resp_update.json()
            assert updated["webhook_enabled"] is True
            assert updated["webhook_url"] == "https://siem.example.com/webhook"
            assert updated["has_webhook_secret"] is True
            assert updated["webhook_secret_preview"] == "wh_sec_...hars"
            assert updated["min_severity"] == "CRITICAL"
            # Plaintext secret MUST NOT be in response
            assert secret_32chars not in str(updated)

            # Update omitting secret preserves it
            resp_omit = await client.put(
                "/v1/notifications/preferences",
                json={"min_severity": "HIGH"},
            )
            assert resp_omit.status_code == 200
            assert resp_omit.json()["has_webhook_secret"] is True
            assert resp_omit.json()["min_severity"] == "HIGH"

            # Rotate secret
            resp_rotate = await client.put(
                "/v1/notifications/preferences",
                json={"rotate_secret": True},
            )
            assert resp_rotate.status_code == 200
            assert resp_rotate.json()["has_webhook_secret"] is True

            # Clear secret disables webhook
            resp_clear = await client.put(
                "/v1/notifications/preferences",
                json={"clear_webhook_secret": True},
            )
            assert resp_clear.status_code == 200
            cleared = resp_clear.json()
            assert cleared["webhook_enabled"] is False
            assert cleared["has_webhook_secret"] is False


@pytest.mark.anyio
async def test_update_preferences_ssrf_rejection(client_factory):
    """Verify private and loopback webhook URLs fail validation with 422."""
    async with client_factory(user_id=1) as client:
        # Loopback URL
        resp_loopback = await client.put(
            "/v1/notifications/preferences",
            json={"webhook_url": "http://127.0.0.1:8000/webhook"},
        )
        assert resp_loopback.status_code == 422

        # Metadata URL
        resp_meta = await client.put(
            "/v1/notifications/preferences",
            json={"webhook_url": "http://169.254.169.254/latest/meta-data"},
        )
        assert resp_meta.status_code == 422
