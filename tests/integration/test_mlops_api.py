"""
tests/integration/test_mlops_api.py
───────────────────────────────────
Integration tests for MLOps endpoints, RBAC authorization, and scan history deletion.
Uses FastAPI dependency_overrides for complete database and auth isolation.
Uses asyncio.run() for universal portability across test environments.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from httpx import ASGITransport, AsyncClient

from backend.api.dependencies import (
    get_current_admin,
    get_current_user,
    get_db,
    get_explainer_service,
    get_prediction_service,
)
from backend.core.security import create_access_token
from backend.database.models import ScanResult, User
from backend.main import app


def _tokens_and_users():
    admin = User(id=1, email="admin@cybersec.com", role="admin", is_active=True)
    user = User(id=2, email="user@cybersec.com", role="user", is_active=True)
    admin_token = create_access_token(subject="1")
    user_token = create_access_token(subject="2")
    return admin, user, admin_token, user_token


def _mock_db_session():
    session = AsyncMock()
    res = MagicMock()
    res.scalar.return_value = 0
    res.scalars.return_value.all.return_value = []
    res.scalar_one_or_none.return_value = None
    session.execute.return_value = res
    session.commit = AsyncMock()
    session.delete = AsyncMock()
    return session


def _mock_prediction_service():
    svc = MagicMock()
    svc.wrapper = MagicMock()
    svc.wrapper.name = "XGBoostModel"
    svc.classes = ["legitimate", "phishing"]
    svc.thresholds = {}
    svc.reload_model = MagicMock()
    return svc


def _mock_explainer_service():
    svc = MagicMock()
    svc.reload_model = MagicMock()
    return svc


def _setup_overrides(current_user: User | None = None, current_admin: User | None = None, db_session: Any = None):
    """Register isolated test dependency overrides."""
    if current_user:
        app.dependency_overrides[get_current_user] = lambda: current_user
    if current_admin:
        app.dependency_overrides[get_current_admin] = lambda: current_admin
    app.dependency_overrides[get_db] = lambda: (db_session or _mock_db_session())
    app.dependency_overrides[get_prediction_service] = _mock_prediction_service
    app.dependency_overrides[get_explainer_service] = _mock_explainer_service


def test_mlops_retrain_unauthenticated():
    """Verify anonymous request to /v1/mlops/retrain is rejected with 401."""
    async def _test():
        _setup_overrides()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            try:
                response = await client.post("/v1/mlops/retrain")
                assert response.status_code == 401
            finally:
                app.dependency_overrides.clear()

    asyncio.run(_test())


def test_mlops_retrain_forbidden_for_regular_user():
    """Verify non-admin authenticated request to /v1/mlops/retrain is rejected with 403."""
    async def _test():
        _, mock_user, _, user_token = _tokens_and_users()
        _setup_overrides(current_user=mock_user)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            try:
                response = await client.post(
                    "/v1/mlops/retrain",
                    headers={"Authorization": f"Bearer {user_token}"},
                )
                assert response.status_code == 403
                assert "privileges" in response.json()["detail"].lower()
            finally:
                app.dependency_overrides.clear()

    asyncio.run(_test())


def test_mlops_retrain_admin_success():
    """Verify admin request triggers retraining successfully without force_promotion."""
    async def _test():
        mock_admin, _, admin_token, _ = _tokens_and_users()
        _setup_overrides(current_user=mock_admin, current_admin=mock_admin)

        mock_pipeline_res = {
            "status": "success",
            "promoted": True,
            "model_file": "xgboost_retrained_test.pkl",
            "zero_day_samples_added": 0,
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with (
                patch("backend.api.routers.mlops.learning_service.build_zero_day_dataset", AsyncMock(return_value=(None, None, [], {}))),
                patch("backend.api.routers.mlops.run_retraining_pipeline", return_value=mock_pipeline_res),
                patch("backend.api.routers.mlops.coordinate_model_reload", return_value=None),
            ):
                try:
                    response = await client.post(
                        "/v1/mlops/retrain",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        json={"limit": 500, "tune_hyperparameters": False},
                    )
                    assert response.status_code == 200
                    data = response.json()
                    assert data["status"] == "success"
                    assert data["promoted"] is True
                finally:
                    app.dependency_overrides.clear()

    asyncio.run(_test())


def test_mlops_status_admin_required():
    """Verify standard user is forbidden from viewing internal MLOps telemetry."""
    async def _test():
        _, mock_user, _, user_token = _tokens_and_users()
        _setup_overrides(current_user=mock_user)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            try:
                response = await client.get(
                    "/v1/mlops/status",
                    headers={"Authorization": f"Bearer {user_token}"},
                )
                assert response.status_code == 403
            finally:
                app.dependency_overrides.clear()

    asyncio.run(_test())


def test_mlops_status_admin_success():
    """Verify admin can view MLOps status with sanitized file info."""
    async def _test():
        mock_admin, _, admin_token, _ = _tokens_and_users()
        _setup_overrides(current_user=mock_admin, current_admin=mock_admin)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            try:
                response = await client.get(
                    "/v1/mlops/status",
                    headers={"Authorization": f"Bearer {admin_token}"},
                )
                assert response.status_code == 200
                data = response.json()
                assert "active_model_file" in data
                # Ensure no local filesystem paths are exposed
                assert "/" not in data["active_model_file"]
                assert "\\" not in data["active_model_file"]
                assert "zero_day_verified_eligible" in data
            finally:
                app.dependency_overrides.clear()

    asyncio.run(_test())


def test_mlops_rollback_admin_success():
    """Verify admin can trigger model rollback."""
    async def _test():
        mock_admin, _, admin_token, _ = _tokens_and_users()
        _setup_overrides(current_user=mock_admin, current_admin=mock_admin)

        mock_rollback_res = {
            "status": "rolled_back",
            "current_champion": "xgboost_calibrated.pkl",
            "demoted_model": "xgboost_candidate.pkl",
            "timestamp": "2026-09-10T20:00:00Z",
        }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with (
                patch("backend.api.routers.mlops.rollback_to_previous_champion", return_value=mock_rollback_res),
                patch("backend.api.routers.mlops.coordinate_model_reload", return_value=None),
            ):
                try:
                    response = await client.post(
                        "/v1/mlops/rollback",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert response.status_code == 200
                    assert response.json()["status"] == "rolled_back"
                finally:
                    app.dependency_overrides.clear()

    asyncio.run(_test())


def test_mlops_error_detail_is_sanitized():
    """Verify internal exception tracebacks or file paths are never leaked in error response."""
    async def _test():
        mock_admin, _, admin_token, _ = _tokens_and_users()
        _setup_overrides(current_user=mock_admin, current_admin=mock_admin)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("backend.api.routers.mlops.run_retraining_pipeline", side_effect=RuntimeError("E:\\Secret\\Path\\error.py crashed")):
                try:
                    response = await client.post(
                        "/v1/mlops/retrain",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        json={"limit": 100},
                    )
                    assert response.status_code == 500
                    detail = response.json()["detail"]
                    assert "Secret" not in detail
                    assert "Path" not in detail
                    assert "crashed" not in detail
                    assert "Please check server logs" in detail
                finally:
                    app.dependency_overrides.clear()

    asyncio.run(_test())


def test_delete_history_item():
    """Verify DELETE /v1/history/{scan_id} deletes user scan."""
    async def _test():
        _, mock_user, _, user_token = _tokens_and_users()
        mock_scan = ScanResult(id=42, user_id=mock_user.id, url="http://example.com")
        mock_session = AsyncMock()
        mock_res = MagicMock()
        mock_res.scalar_one_or_none.return_value = mock_scan
        mock_session.execute.return_value = mock_res
        mock_session.delete = AsyncMock()
        mock_session.commit = AsyncMock()

        _setup_overrides(current_user=mock_user, db_session=mock_session)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            try:
                response = await client.delete(
                    "/v1/history/42",
                    headers={"Authorization": f"Bearer {user_token}"},
                )
                assert response.status_code == 204
            finally:
                app.dependency_overrides.clear()

    asyncio.run(_test())


def test_concurrent_retrain_and_rollback_prevented():
    """Stress test 23: Retraining and rollback cannot execute concurrently, returning 409 Conflict."""
    async def _test():
        mock_admin, _, admin_token, _ = _tokens_and_users()
        _setup_overrides(current_user=mock_admin, current_admin=mock_admin)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("backend.api.routers.mlops.model_lifecycle_lock.is_locked", return_value=True):
                try:
                    res_retrain = await client.post(
                        "/v1/mlops/retrain",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        json={"limit": 100},
                    )
                    assert res_retrain.status_code == 409
                    assert "already active" in res_retrain.json()["detail"].lower()

                    res_rollback = await client.post(
                        "/v1/mlops/rollback",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert res_rollback.status_code == 409
                    assert "already active" in res_rollback.json()["detail"].lower()
                finally:
                    app.dependency_overrides.clear()

    asyncio.run(_test())


def test_multiple_rollback_requests_race_prevention():
    """Stress test 24: Multiple concurrent rollback requests are serialized and reject with 409."""
    async def _test():
        mock_admin, _, admin_token, _ = _tokens_and_users()
        _setup_overrides(current_user=mock_admin, current_admin=mock_admin)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("backend.api.routers.mlops.rollback_to_previous_champion", side_effect=RuntimeError("Model lifecycle operation is currently active.")):
                try:
                    response = await client.post(
                        "/v1/mlops/rollback",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert response.status_code == 409
                    assert "already active" in response.json()["detail"].lower()
                finally:
                    app.dependency_overrides.clear()

    asyncio.run(_test())
