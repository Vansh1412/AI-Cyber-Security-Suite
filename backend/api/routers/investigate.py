"""
backend/api/routers/investigate.py
────────────────────────────────────
Sprint 4: Threat Investigation Endpoints (Hardened).

Endpoints:
  POST /v1/investigate/bulk             — Batch scan up to 20 URLs (bounded concurrency, cached)
  GET  /v1/investigate/domain/{domain}  — Domain cross-scan history lookup
"""

import asyncio
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import (
    get_current_user,
    get_db,
    get_feature_service,
    get_prediction_service,
)
from backend.core.rate_limit import limiter
from backend.core.security_network import sanitize_domain_for_whois
from backend.database.models import ScanResult, User
from backend.schemas.intel import (
    BulkScanItem,
    BulkScanRequest,
    BulkScanResponse,
    DomainScanHistory,
)
from backend.services.cache import cache_service
from backend.services.feature_eng import FeatureService
from backend.services.prediction import PredictionService
from backend.services.threat_intel import threat_intel_service
from src.utils.logger import logger

router = APIRouter(prefix="/investigate", tags=["Investigation"])

BULK_SCAN_MAX: int = 20
MAX_URL_LENGTH: int = 2048
CONCURRENCY_LIMIT: int = 5


async def _scan_single_url_safe(
    url: str,
    feat_svc: FeatureService,
    pred_svc: PredictionService,
    semaphore: asyncio.Semaphore,
) -> BulkScanItem:
    """Process a single URL in the bulk scan pipeline with bounded concurrency."""
    async with semaphore:
        t0 = time.perf_counter()
        try:
            # 1. Check Redis cache
            cached = await cache_service.get(url)
            if cached:
                latency = round((time.perf_counter() - t0) * 1000, 2)
                return BulkScanItem(
                    url=url,
                    prediction=cached.get("prediction"),
                    confidence=round(float(cached.get("confidence", 1.0)), 4),
                    latency_ms=latency,
                    cache_hit=True,
                    source="cache",
                )

            # 2. Threat intelligence waterfall (Blacklist -> Allowlist -> Heuristics -> Feeds)
            intel_hit = await threat_intel_service.check_url(url)
            if intel_hit:
                latency = round((time.perf_counter() - t0) * 1000, 2)
                await cache_service.set(url, intel_hit)
                return BulkScanItem(
                    url=url,
                    prediction=intel_hit.get("prediction"),
                    confidence=round(float(intel_hit.get("confidence", 1.0)), 4),
                    latency_ms=latency,
                    cache_hit=False,
                    source=intel_hit.get("source", "threat_intel"),
                )

            # 3. Canonical 59-feature extraction + XGBoost Cascade Inference
            df = await asyncio.to_thread(feat_svc.extract_features, url)
            prediction, confidence = await asyncio.to_thread(pred_svc.predict, df)

            latency = round((time.perf_counter() - t0) * 1000, 2)
            await cache_service.set(url, {"prediction": prediction, "confidence": confidence})

            return BulkScanItem(
                url=url,
                prediction=prediction,
                confidence=round(float(confidence), 4),
                latency_ms=latency,
                cache_hit=False,
                source="ml",
            )

        except Exception as exc:
            logger.warning("Bulk scan item failure for %s: %s", url, exc)
            latency = round((time.perf_counter() - t0) * 1000, 2)
            return BulkScanItem(
                url=url,
                latency_ms=latency,
                error="Scan failed or target malformed",
            )


# ── POST /v1/investigate/bulk ─────────────────────────────────────────────────

@router.post("/bulk", response_model=BulkScanResponse)
@limiter.limit("5/minute")
async def bulk_scan(
    request: Request,
    payload: BulkScanRequest = Body(...),
    feat_svc: FeatureService = Depends(get_feature_service),
    pred_svc: PredictionService = Depends(get_prediction_service),
    current_user: User = Depends(get_current_user),
) -> BulkScanResponse:
    """
    Batch scan up to 20 URLs with bounded concurrency (5 concurrent workers),
    cache lookups, threat waterfall integration, and deduplication.
    """
    t0 = time.perf_counter()

    # Deduplicate URLs while preserving order, normalizing whitespace
    deduped_urls: list[str] = []
    seen: set[str] = set()
    for raw_u in payload.urls:
        u = raw_u.strip()
        if u and u not in seen:
            seen.add(u)
            deduped_urls.append(u)

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    # Process concurrently with bounded concurrency
    tasks = [
        _scan_single_url_safe(url, feat_svc, pred_svc, semaphore)
        for url in deduped_urls
    ]
    results = await asyncio.gather(*tasks)

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return BulkScanResponse(total=len(results), results=list(results), elapsed_ms=elapsed_ms)


# ── GET /v1/investigate/domain/{domain} ───────────────────────────────────────

@router.get("/domain/{domain:path}", response_model=DomainScanHistory)
@limiter.limit("20/minute")
async def get_domain_history(
    request: Request,
    domain: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DomainScanHistory:
    """
    Retrieve all scan records associated with a domain for the current user.
    Matches URLs where the hostname equals or is a subdomain of the target.
    """
    clean_domain = domain.lower().strip().lstrip("/").strip()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    # Validate domain name formatting
    sanitized = sanitize_domain_for_whois(clean_domain)
    if not sanitized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid domain format.",
        )

    # Query scans belonging to user where URL contains domain
    result = await db.execute(
        select(ScanResult)
        .where(
            ScanResult.user_id == current_user.id,
            ScanResult.url.contains(sanitized),
        )
        .order_by(ScanResult.created_at.desc())
        .limit(100)
    )
    scans = result.scalars().all()

    matching = []
    for s in scans:
        try:
            parsed = urlparse(s.url if "://" in s.url else "http://" + s.url)
            host = (parsed.hostname or "").lower()
            if host == sanitized or host.endswith("." + sanitized):
                matching.append(s)
        except Exception:
            pass

    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan history found for domain: {sanitized}",
        )

    threat_count = sum(1 for s in matching if s.prediction != "legitimate")
    latest = matching[0]

    scans_list = [
        {
            "id": s.id,
            "url": s.url,
            "prediction": s.prediction,
            "confidence": s.confidence,
            "created_at": s.created_at.isoformat(),
            "source_feed": s.source_feed,
        }
        for s in matching
    ]

    return DomainScanHistory(
        domain=sanitized,
        total_scans=len(matching),
        threat_count=threat_count,
        latest_prediction=latest.prediction,
        latest_confidence=latest.confidence,
        scans=scans_list,
    )
