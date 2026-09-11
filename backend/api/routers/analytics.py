"""
backend/api/routers/analytics.py
──────────────────────────────────
Sprint 4: Analytics Endpoints.

Endpoints:
  GET /v1/analytics/global            — Admin-only: platform-wide aggregate stats
  GET /v1/analytics/public            — Authenticated: limited aggregate counts
  GET /v1/analytics/trends            — Authenticated: threat trend time series (sliding window)
  GET /v1/analytics/feature-importance — Admin-only: aggregated SHAP feature importance
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import (
    get_current_admin,
    get_current_user,
    get_db,
    get_prediction_service,
)
from backend.core.config import settings
from backend.core.rate_limit import limiter
from backend.database.models import ScanResult, User
from backend.schemas.intel import (
    FeatureImportanceItem,
    FeatureImportanceResponse,
    GlobalAnalyticsResponse,
    PublicAnalyticsResponse,
    TrendPoint,
    TrendsResponse,
)
from backend.services.prediction import PredictionService

router = APIRouter(prefix="/analytics", tags=["Analytics"])


# ── GET /v1/analytics/global ──────────────────────────────────────────────────

@router.get("/global", response_model=GlobalAnalyticsResponse)
@limiter.limit("30/minute")
async def get_global_analytics(
    request: Request,
    db: AsyncSession = Depends(get_db),
    pred_svc: PredictionService = Depends(get_prediction_service),
    current_admin: User = Depends(get_current_admin),
) -> GlobalAnalyticsResponse:
    """
    Admin-only: Platform-wide aggregated scan analytics.
    Returns total counts, threat distribution, top threat domains,
    zero-day metrics, and active model information.
    """
    # Total scans (platform-wide)
    total_result = await db.execute(select(func.count(ScanResult.id)))
    total_scans = total_result.scalar() or 0

    # Total registered users
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users = total_users_result.scalar() or 0

    # Scans by class
    by_class_result = await db.execute(
        select(ScanResult.prediction, func.count(ScanResult.id)).group_by(ScanResult.prediction)
    )
    by_class: dict[str, int] = {row[0]: row[1] for row in by_class_result.all()}

    # Daily volume (last 30 days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    date_expr = cast(ScanResult.created_at, Date)
    daily_result = await db.execute(
        select(date_expr.label("date"), func.count(ScanResult.id))
        .where(ScanResult.created_at >= cutoff)
        .group_by(date_expr)
        .order_by(date_expr)
    )
    daily_volume = [{"date": row.date.isoformat(), "count": row[1]} for row in daily_result.all()]

    # Zero-day counts
    zd_total_result = await db.execute(
        select(func.count(ScanResult.id)).where(ScanResult.is_zero_day.is_(True))
    )
    zero_day_total = zd_total_result.scalar() or 0

    zd_verified_result = await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.is_zero_day.is_(True),
            ScanResult.retrain_status == "VERIFIED",
        )
    )
    zero_day_verified = zd_verified_result.scalar() or 0

    zd_promoted_result = await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.is_zero_day.is_(True),
            ScanResult.retrain_status == "PROMOTED",
        )
    )
    zero_day_promoted = zd_promoted_result.scalar() or 0

    # Top threat domains (from non-legitimate scans) — limit to top 10
    threat_domain_result = await db.execute(
        select(ScanResult.url, ScanResult.prediction, func.count(ScanResult.id).label("cnt"))
        .where(ScanResult.prediction != "legitimate", ScanResult.created_at >= cutoff)
        .group_by(ScanResult.url, ScanResult.prediction)
        .order_by(func.count(ScanResult.id).desc())
        .limit(100)
    )
    domain_counter: Counter = Counter()
    domain_pred: dict[str, str] = {}
    for url, pred, cnt in threat_domain_result.all():
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname or url
            domain_counter[domain] += cnt
            domain_pred[domain] = pred
        except Exception:
            pass
    top_threat_domains = [
        {"domain": d, "count": c, "prediction": domain_pred.get(d, "unknown")}
        for d, c in domain_counter.most_common(10)
    ]

    return GlobalAnalyticsResponse(
        total_scans=total_scans,
        total_users=total_users,
        by_class=by_class,
        daily_volume=daily_volume,
        zero_day_total=zero_day_total,
        zero_day_verified=zero_day_verified,
        zero_day_promoted=zero_day_promoted,
        top_threat_domains=top_threat_domains,
        model_env=settings.MODEL_ENV,
        active_model=settings.MODEL_PATH.name,
    )


# ── GET /v1/analytics/public ──────────────────────────────────────────────────

@router.get("/public", response_model=PublicAnalyticsResponse)
@limiter.limit("60/minute")
async def get_public_analytics(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PublicAnalyticsResponse:
    """
    Authenticated (non-admin): Limited platform aggregate counts.
    No individual URL data exposed.
    """
    total_result = await db.execute(select(func.count(ScanResult.id)))
    total_scans = total_result.scalar() or 0

    by_class_result = await db.execute(
        select(ScanResult.prediction, func.count(ScanResult.id)).group_by(ScanResult.prediction)
    )
    by_class: dict[str, int] = {row[0]: row[1] for row in by_class_result.all()}

    threat_count = sum(v for k, v in by_class.items() if k != "legitimate")
    threat_ratio = round(threat_count / total_scans, 4) if total_scans else 0.0

    return PublicAnalyticsResponse(
        total_scans_platform=total_scans,
        threat_ratio=threat_ratio,
        by_class=by_class,
    )


# ── GET /v1/analytics/trends ──────────────────────────────────────────────────

@router.get("/trends", response_model=TrendsResponse)
@limiter.limit("30/minute")
async def get_threat_trends(
    request: Request,
    window_days: int = Query(default=30, ge=7, le=90, description="Sliding window in days"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TrendsResponse:
    """
    Authenticated: Threat trend time series for a sliding window.
    Returns daily counts per threat class for the past N days.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    date_expr = cast(ScanResult.created_at, Date)

    result = await db.execute(
        select(
            date_expr.label("date"),
            ScanResult.prediction,
            func.count(ScanResult.id).label("cnt"),
        )
        .where(ScanResult.created_at >= cutoff)
        .group_by(date_expr, ScanResult.prediction)
        .order_by(date_expr)
    )

    # Build a day-keyed accumulator
    day_map: dict[str, dict[str, int]] = defaultdict(
        lambda: {"phishing": 0, "malware": 0, "defacement": 0, "legitimate": 0, "total": 0}
    )

    for row in result.all():
        d = row.date.isoformat() if hasattr(row.date, "isoformat") else str(row.date)
        cls = row.prediction if row.prediction in {"phishing", "malware", "defacement", "legitimate"} else "legitimate"
        day_map[d][cls] += row.cnt
        day_map[d]["total"] += row.cnt

    # Fill missing days with zeros
    all_days = sorted(day_map.keys())
    if all_days:
        start_date = date.fromisoformat(all_days[0])
        end_date = date.today()
        current = start_date
        while current <= end_date:
            ds = current.isoformat()
            if ds not in day_map:
                day_map[ds] = {"phishing": 0, "malware": 0, "defacement": 0, "legitimate": 0, "total": 0}
            current += timedelta(days=1)

    data = [
        TrendPoint(date=d, **day_map[d])
        for d in sorted(day_map.keys())
    ]

    return TrendsResponse(window_days=window_days, data=data)


# ── GET /v1/analytics/feature-importance ──────────────────────────────────────

@router.get("/feature-importance", response_model=FeatureImportanceResponse)
@limiter.limit("10/minute")
async def get_feature_importance(
    request: Request,
    limit: int = Query(default=20, ge=5, le=50),
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
) -> FeatureImportanceResponse:
    """
    Admin-only: Aggregated SHAP feature importance across all scans.
    Computes average impact and appearance count from stored top_reasons.
    """
    # Analyze up to the latest 1,000 scans with SHAP attributions for performance and scalability
    MAX_ANALYSIS_SCANS = 1000
    result = await db.execute(
        select(ScanResult.top_reasons)
        .where(ScanResult.top_reasons.isnot(None))
        .order_by(ScanResult.created_at.desc())
        .limit(MAX_ANALYSIS_SCANS)
    )
    rows = result.scalars().all()

    feature_impacts: dict[str, list[float]] = defaultdict(list)
    total_analyzed = 0

    for reasons in rows:
        if not isinstance(reasons, list):
            continue
        total_analyzed += 1
        for reason in reasons:
            if isinstance(reason, dict) and "feature" in reason and "impact" in reason:
                feature_impacts[reason["feature"]].append(float(reason["impact"]))

    from backend.api.routers.intel import categorize_feature

    items = sorted(
        [
            FeatureImportanceItem(
                feature=feat,
                avg_impact=round(sum(vals) / len(vals), 6),
                appearance_count=len(vals),
                category=categorize_feature(feat),
            )
            for feat, vals in feature_impacts.items()
        ],
        key=lambda x: x.avg_impact,
        reverse=True,
    )[:limit]

    return FeatureImportanceResponse(
        total_scans_analyzed=total_analyzed,
        features=items,
    )
