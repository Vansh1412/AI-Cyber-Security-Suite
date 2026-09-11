"""
tests/integration/test_analytics_api.py
─────────────────────────────────────────
Sprint 4: Integration tests for analytics, intel enrichment, and investigation endpoints.

Uses FastAPI dependency_overrides for complete isolation.
Deterministic test mocks — zero real database, model, or external network dependencies.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pandas as pd
import pytest
from httpx import ASGITransport, AsyncClient

from backend.api.dependencies import (
    get_current_admin,
    get_current_user,
    get_db,
    get_feature_service,
    get_prediction_service,
)
from backend.database.models import ScanResult, User
from backend.main import app


# ── Test Fixtures & Mock Generators ───────────────────────────────────────────

def _make_admin() -> User:
    return User(id=1, email="admin@test.com", role="admin", is_active=True)


def _make_user(user_id: int = 2) -> User:
    return User(id=user_id, email=f"user{user_id}@test.com", role="user", is_active=True)


def _mock_db_empty() -> AsyncMock:
    session = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalar.return_value = 0
    mock_res.scalars.return_value.all.return_value = []
    mock_res.scalar_one_or_none.return_value = None
    mock_res.all.return_value = []
    session.execute = AsyncMock(return_value=mock_res)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock(return_value=None)
    return session


def _mock_db_with_scan(scan: ScanResult) -> AsyncMock:
    session = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalar.return_value = 1
    mock_res.scalars.return_value.all.return_value = [scan]
    mock_res.scalar_one_or_none.return_value = scan
    mock_res.all.return_value = []
    session.execute = AsyncMock(return_value=mock_res)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock(return_value=scan)
    return session


def _make_scan(user_id: int = 2, has_enrichment: bool = False) -> ScanResult:
    s = ScanResult()
    s.id = 42
    s.url = "https://example.com"
    s.prediction = "legitimate"
    s.confidence = 0.92
    s.latency_ms = 15.0
    s.cache_hit = False
    s.top_reasons = [{"feature": "url_length", "value": 20, "impact": 0.3}]
    s.is_zero_day = False
    s.source_feed = "ml"
    s.feature_vector = {"url_length": 20.0, "num_dots": 1.0}
    s.retrain_status = None
    s.user_id = user_id
    s.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    s.domain_age_days = 365 if has_enrichment else None
    s.tls_valid = True if has_enrichment else None
    s.redirect_count = 0 if has_enrichment else None
    s.final_url = "https://example.com" if has_enrichment else None
    s.threat_intel_enrichment = (
        {
            "domain_age_days": 365,
            "tls_info": {
                "valid": True,
                "issuer": "DigiCert",
                "subject": "example.com",
                "expires_at": "2027-01-01T00:00:00+00:00",
                "days_to_expiry": 365,
            },
            "redirect_count": 0,
            "final_url": "https://example.com",
            "redirect_chain": ["https://example.com"],
            "geolocation": {
                "ip": "93.184.216.34",
                "city": "Los Angeles",
                "region": "CA",
                "country": "US",
                "org": "EdgeCast",
            },
            "enrichment_ms": 120.0,
        }
        if has_enrichment
        else None
    )
    return s


def _mock_feature_service() -> MagicMock:
    svc = MagicMock()
    # Canonical 59 schema features
    schema_59 = [
        "url_length", "domain_length", "path_length", "query_length", "fragment_length",
        "num_dots", "num_hyphens", "num_underscores", "num_digits", "num_slashes",
        "num_at", "num_equals", "num_question", "num_percent", "num_ampersand",
        "num_hash", "num_exclamation", "num_tilde", "num_comma", "num_plus",
        "num_asterisk", "https_flag", "has_ip", "has_port", "url_depth",
        "subdomain_count", "suspicious_tld", "has_fragment", "query_param_count",
        "has_suspicious_ext", "double_slash_redirect", "punycode_domain",
        "domain_has_digits", "has_www", "multi_subdomains", "brand_in_subdomain",
        "url_entropy", "domain_entropy", "digit_ratio", "uppercase_ratio",
        "vowel_ratio", "symbol_ratio", "kw_login", "kw_verify", "kw_secure",
        "kw_update", "kw_bank", "kw_paypal", "kw_account", "kw_signin",
        "kw_invoice", "kw_payment", "kw_confirm", "kw_password", "kw_suspend",
        "kw_validate", "kw_wallet", "keyword_count", "has_brand_name",
    ]
    svc.schema = schema_59
    svc.extract_features.return_value = pd.DataFrame([[0.0] * 59], columns=schema_59)
    return svc


def _mock_prediction_service() -> MagicMock:
    svc = MagicMock()
    svc.predict.return_value = ("legitimate", 0.95)
    return svc


def _setup(
    user: User | None = None,
    admin: User | None = None,
    db: Any = None,
    feat_svc: Any = None,
    pred_svc: Any = None,
):
    app.dependency_overrides.clear()
    if user:
        app.dependency_overrides[get_current_user] = lambda: user
    if admin:
        app.dependency_overrides[get_current_admin] = lambda: admin
    if db:
        app.dependency_overrides[get_db] = lambda: db
    if feat_svc:
        app.dependency_overrides[get_feature_service] = lambda: feat_svc
    if pred_svc:
        app.dependency_overrides[get_prediction_service] = lambda: pred_svc


def _teardown():
    app.dependency_overrides.clear()


# ── 1. Analytics Authorization & Response Tests ───────────────────────────────

def test_global_analytics_admin_only_allows_admin():
    async def _test():
        admin = _make_admin()
        db = _mock_db_empty()
        _setup(admin=admin, db=db, pred_svc=_mock_prediction_service())

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/analytics/global")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert "total_scans" in body
        assert "zero_day_total" in body

    asyncio.run(_test())


def test_global_analytics_forbidden_for_standard_user():
    async def _test():
        user = _make_user()
        _setup(user=user, db=_mock_db_empty())

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/analytics/global")
        _teardown()

        # Should be forbidden or unauthorized (standard user lacks admin privilege)
        assert resp.status_code in (401, 403)

    asyncio.run(_test())


def test_public_analytics_allows_authenticated_user():
    async def _test():
        user = _make_user()
        db = _mock_db_empty()
        _setup(user=user, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/analytics/public")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert "total_scans_platform" in body
        assert "threat_ratio" in body

    asyncio.run(_test())


def test_trends_endpoint_allows_authenticated_user():
    async def _test():
        user = _make_user()
        db = _mock_db_empty()
        _setup(user=user, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/analytics/trends?window_days=14")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["window_days"] == 14
        assert "data" in body

    asyncio.run(_test())


def test_feature_importance_admin_only():
    async def _test():
        admin = _make_admin()
        db = _mock_db_empty()
        _setup(admin=admin, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/analytics/feature-importance?limit=10")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert "features" in body

    asyncio.run(_test())


# ── 2. Threat Intel Enrichment Endpoints Tests ────────────────────────────────

def test_intel_enrichment_not_found():
    async def _test():
        user = _make_user()
        db = _mock_db_empty()
        _setup(user=user, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/intel/999")
        _teardown()

        assert resp.status_code == 404

    asyncio.run(_test())


def test_intel_enrichment_returns_pending_when_not_computed():
    async def _test():
        user = _make_user()
        scan = _make_scan(user_id=user.id, has_enrichment=False)
        db = _mock_db_with_scan(scan)
        _setup(user=user, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/v1/intel/{scan.id}")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == scan.id
        assert body["status"] == "pending"

    asyncio.run(_test())


def test_intel_enrichment_returns_full_when_computed():
    async def _test():
        user = _make_user()
        scan = _make_scan(user_id=user.id, has_enrichment=True)
        db = _mock_db_with_scan(scan)
        _setup(user=user, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/v1/intel/{scan.id}")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["domain_age_days"] == 365
        assert body["tls_info"]["valid"] is True
        assert body["redirect_count"] == 0
        assert body["status"] == "completed"

    asyncio.run(_test())


def test_trigger_intel_enrichment_post_persists_data():
    async def _test():
        user = _make_user()
        scan = _make_scan(user_id=user.id, has_enrichment=False)
        db = _mock_db_with_scan(scan)
        _setup(user=user, db=db)

        fake_enrich_result = {
            "domain_age_days": 180,
            "tls_info": {"valid": True},
            "redirect_count": 1,
            "final_url": "https://example.com/dest",
            "redirect_chain": ["https://example.com", "https://example.com/dest"],
            "geolocation": {"country": "US"},
            "enrichment_ms": 110.0,
        }

        with patch("backend.api.routers.intel.enrich_scan", AsyncMock(return_value=fake_enrich_result)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.post(f"/v1/intel/{scan.id}/enrich")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["domain_age_days"] == 180
        assert body["redirect_count"] == 1
        assert body["status"] == "completed"
        # Confirm db.commit was called to persist
        assert db.commit.called

    asyncio.run(_test())


# ── 3. Deep Scan Report Contract Tests (Strict 59 Features) ───────────────────

def test_deep_report_returns_exactly_59_canonical_features():
    async def _test():
        user = _make_user()
        scan = _make_scan(user_id=user.id, has_enrichment=True)
        db = _mock_db_with_scan(scan)
        feat_svc = _mock_feature_service()
        _setup(user=user, db=db, feat_svc=feat_svc)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/v1/scan/{scan.id}/deep-report")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == scan.id
        # Strict contract: canonical_features.count MUST be 59
        assert "canonical_features" in body
        assert body["canonical_features"]["count"] == 59
        assert len(body["canonical_features"]["features"]) == 59
        assert len(body["feature_vector"]) == 59

    asyncio.run(_test())


# ── 4. Bulk Investigation Bounded Execution Tests ─────────────────────────────

def test_bulk_scan_rejects_more_than_20_urls():
    async def _test():
        user = _make_user()
        _setup(user=user)

        urls = [f"https://test{i}.com" for i in range(21)]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/v1/investigate/bulk", json={"urls": urls})
        _teardown()

        assert resp.status_code == 422

    asyncio.run(_test())


def test_bulk_scan_processes_valid_batch_and_deduplicates():
    async def _test():
        user = _make_user()
        feat_svc = _mock_feature_service()
        pred_svc = _mock_prediction_service()
        _setup(user=user, feat_svc=feat_svc, pred_svc=pred_svc)

        with patch("backend.services.cache.cache_service.get", AsyncMock(return_value=None)):
            with patch("backend.services.cache.cache_service.set", AsyncMock()):
                with patch("backend.services.threat_intel.threat_intel_service.check_url", AsyncMock(return_value=None)):
                    # Provide duplicates: 3 urls total, but only 2 unique
                    urls = ["https://site-a.com", "https://site-b.com", "https://site-a.com"]
                    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                        resp = await c.post("/v1/investigate/bulk", json={"urls": urls})
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2  # Deduplicated from 3 to 2
        assert body["results"][0]["url"] == "https://site-a.com"
        assert body["results"][1]["url"] == "https://site-b.com"

    asyncio.run(_test())


def test_bulk_scan_normalizes_whitespace_before_deduplication():
    async def _test():
        user = _make_user()
        feat_svc = _mock_feature_service()
        pred_svc = _mock_prediction_service()
        _setup(user=user, feat_svc=feat_svc, pred_svc=pred_svc)

        with patch("backend.services.cache.cache_service.get", AsyncMock(return_value=None)):
            with patch("backend.services.cache.cache_service.set", AsyncMock()):
                with patch("backend.services.threat_intel.threat_intel_service.check_url", AsyncMock(return_value=None)):
                    # URLs with trailing/leading whitespace should be normalized and deduplicated
                    urls = ["https://site-a.com", "https://site-a.com ", " https://site-b.com"]
                    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                        resp = await c.post("/v1/investigate/bulk", json={"urls": urls})
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2  # Deduplicated from 3 to 2
        assert body["results"][0]["url"] == "https://site-a.com"
        assert body["results"][1]["url"] == "https://site-b.com"

    asyncio.run(_test())


def test_bulk_scan_uses_cache_and_waterfall():
    async def _test():
        user = _make_user()
        feat_svc = _mock_feature_service()
        pred_svc = _mock_prediction_service()
        _setup(user=user, feat_svc=feat_svc, pred_svc=pred_svc)

        async def fake_cache_get(url: str):
            if "cached" in url:
                return {"prediction": "phishing", "confidence": 0.99}
            return None

        async def fake_intel_check(url: str):
            if "waterfall" in url:
                return {"prediction": "malware", "confidence": 0.95, "source": "phishtank"}
            return None

        with patch("backend.services.cache.cache_service.get", side_effect=fake_cache_get):
            with patch("backend.services.cache.cache_service.set", AsyncMock()):
                with patch("backend.services.threat_intel.threat_intel_service.check_url", side_effect=fake_intel_check):
                    urls = ["https://cached.com", "https://waterfall.com", "https://zeroday.com"]
                    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                        resp = await c.post("/v1/investigate/bulk", json={"urls": urls})
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 3
        # URL 1: Cache hit
        assert body["results"][0]["cache_hit"] is True
        assert body["results"][0]["prediction"] == "phishing"
        # URL 2: Waterfall hit
        assert body["results"][1]["cache_hit"] is False
        assert body["results"][1]["source"] == "phishtank"
        assert body["results"][1]["prediction"] == "malware"
        # URL 3: ML hit
        assert body["results"][2]["cache_hit"] is False
        assert body["results"][2]["source"] == "ml"
        assert body["results"][2]["prediction"] == "legitimate"

    asyncio.run(_test())


# ── 5. Domain History Endpoint Tests ──────────────────────────────────────────

def test_domain_history_rejects_invalid_domain():
    async def _test():
        user = _make_user()
        _setup(user=user)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/investigate/domain/bad%20domain%20with%20spaces")
        _teardown()

        assert resp.status_code == 422

    asyncio.run(_test())


def test_domain_history_returns_matching_scans():
    async def _test():
        user = _make_user()
        scan = _make_scan(user_id=user.id)
        scan.url = "https://sub.example.com/page"
        db = _mock_db_with_scan(scan)
        _setup(user=user, db=db)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/investigate/domain/example.com")
        _teardown()

        assert resp.status_code == 200
        body = resp.json()
        assert body["domain"] == "example.com"
        assert body["total_scans"] == 1
        assert len(body["scans"]) == 1

    asyncio.run(_test())
