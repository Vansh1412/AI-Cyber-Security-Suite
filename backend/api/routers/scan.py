"""
backend/api/routers/scan.py
────────────────────────────
POST /v1/scan

- Rate Limiting (SlowAPI)
- Redis Caching
- Threat Intelligence Waterfall (Local → PhishTank → VirusTotal)
- ML Model Inference
- Background SHAP tracking
- Zero-Day URL logging (Sprint 2)
"""

from __future__ import annotations

import time

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import (
    get_db,
    get_explainer_service,
    get_feature_service,
    get_optional_user,
    get_prediction_service,
)
from backend.database.models import ScanResult, User
from backend.schemas.payload import ScanRequest, ScanResponse
from backend.services.cache import cache_service
from backend.services.explainer import ExplainerService
from backend.services.feature_eng import FeatureService
from backend.services.prediction import PredictionService
from backend.services.threat_intel import threat_intel_service

router = APIRouter()


def limit_by_role(request: Request) -> str:
    """Dynamically applies rate limits. Admins bypass the limit entirely."""
    user: User | None = getattr(request.state, "user", None)
    if user and user.role == "admin":
        return "1000000/minute"  # Effectively unlimited
    if user:
        return "100/minute"      # Authenticated standard users
    return "20/minute"           # Anonymous


async def _compute_shap_and_store(
    scan_id: int,
    url: str,
    prediction: str,
    feat_svc: FeatureService,
    expl_svc: ExplainerService,
) -> None:
    """Background task: run SHAP and write top_reasons into DB."""
    from backend.database.session import AsyncSessionLocal
    from src.utils.logger import logger
    try:
        df = feat_svc.extract_features(url)
        raw = expl_svc.explain(df, prediction)
        top_reasons = [
            {"feature": r["feature"], "value": round(r["value"], 4), "impact": round(r["impact"], 4)}
            for r in raw
        ]
        async with AsyncSessionLocal() as db:
            result = await db.get(ScanResult, scan_id)
            if result:
                result.top_reasons = top_reasons
                await db.commit()
    except (ValueError, RuntimeError, AttributeError) as e:
        logger.error("SHAP background task failed (model/data error): %s", e)
    except Exception as e:  # noqa: BLE001
        # Broad catch intentional — background task must never crash the server
        logger.error("SHAP background task failed (unexpected): %s", e)


@router.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def scan_url(
    request: Request,  # Required by SlowAPI
    background_tasks: BackgroundTasks,
    payload: ScanRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    feat_svc: FeatureService = Depends(get_feature_service),
    pred_svc: PredictionService = Depends(get_prediction_service),
    expl_svc: ExplainerService = Depends(get_explainer_service),
    current_user: User | None = Depends(get_optional_user),
):
    """
    Scan a URL for phishing, malware, or defacement.
    Passes URLs through a Threat Intelligence waterfall before invoking ML.
    Newly seen URLs are flagged as zero-day and persisted for active learning.
    """
    # 0. Set state for dynamic rate limiting
    request.state.user = current_user

    # We invoke the limiter manually here inside the route, since we need dynamic limits
    limiter = request.app.state.limiter
    limiter._check_request_limit(request, endpoint_name="scan_url", limit_value=limit_by_role(request))

    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=422, detail="URL cannot be empty.")

    t0 = time.perf_counter()

    # 1. Cache check — cache hits are NOT logged as zero-day (already known)
    cached = await cache_service.get(payload.url)
    if cached:
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return ScanResponse(
            url=payload.url,
            prediction=cached["prediction"],
            confidence=cached["confidence"],
            latency_ms=latency_ms,
            cache_hit=True,
        )

    # 2. Threat Intelligence Waterfall (Heuristics → PhishTank → VirusTotal)
    intel_hit = await threat_intel_service.check_url(payload.url)

    # ── Sprint 2: Track which layer caught this and whether it's a zero-day ──
    # A URL is "zero-day" when it passes ALL static intel layers and falls
    # through to the ML model. The ML result then becomes our prediction.
    is_zero_day: bool = intel_hit is None
    source_feed: str | None = intel_hit["source"] if intel_hit else "ml"
    feature_vector: dict | None = None

    if intel_hit:
        prediction = intel_hit["prediction"]
        confidence = intel_hit["confidence"]
        # No SHAP or feature extraction required for threat intel hits
    else:
        # 3. Feature extraction + ML prediction
        df = feat_svc.extract_features(payload.url)
        prediction, confidence = pred_svc.predict(df)
        # Capture the raw feature dict for active learning / retraining
        feature_vector = df.iloc[0].to_dict()

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    # 4. Cache the result
    await cache_service.set(payload.url, {"prediction": prediction, "confidence": confidence})

    # 5. Persist to DB — including zero-day signal and feature vector
    scan = ScanResult(
        url=payload.url,
        prediction=prediction,
        confidence=round(confidence, 4),
        latency_ms=latency_ms,
        cache_hit=False,
        is_zero_day=is_zero_day,
        feature_vector=feature_vector,
        source_feed=source_feed,
        user_id=current_user.id if current_user else None,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # 6. Background SHAP computation (Only if ML was used — i.e., zero-day)
    if is_zero_day:
        background_tasks.add_task(
            _compute_shap_and_store,
            scan.id,
            payload.url,
            prediction,
            feat_svc,
            expl_svc,
        )

    return ScanResponse(
        url=payload.url,
        prediction=prediction,
        confidence=round(confidence, 4),
        latency_ms=latency_ms,
        cache_hit=False,
    )
