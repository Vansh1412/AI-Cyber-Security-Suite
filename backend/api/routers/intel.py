"""
backend/api/routers/intel.py
─────────────────────────────
Sprint 4: Threat Intelligence Enrichment & Deep Report Endpoints (Hardened).

Endpoints:
  POST /v1/intel/{scan_id}/enrich        — Explicit, user-initiated enrichment
  GET  /v1/intel/{scan_id}               — Retrieve enrichment status/results
  GET  /v1/scan/{scan_id}/deep-report    — 59 canonical model features + enrichment
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db, get_feature_service
from backend.core.rate_limit import limiter
from backend.database.models import ScanResult, User
from backend.schemas.intel import (
    CanonicalFeatures,
    DeepScanFeature,
    DeepScanReportResponse,
    GeoLocation,
    IntelEnrichmentResponse,
    TLSInfo,
)
from backend.services.feature_eng import FeatureService
from backend.services.intel_enrichment import enrich_scan
from src.utils.logger import logger

router = APIRouter(tags=["Threat Intelligence"])

# ── Feature category mapping ──────────────────────────────────────────────────
_LEXICAL_PREFIXES = (
    "url_length", "domain_length", "path_length", "query_length", "fragment_length",
    "num_dots", "num_hyphens", "num_underscores", "num_digits", "num_slashes",
    "num_at", "num_equals", "num_question", "num_percent", "num_ampersand",
    "num_hash", "num_exclamation", "num_tilde", "num_comma", "num_plus",
    "num_asterisk", "https_flag", "has_ip", "has_port", "url_depth",
)
_STRUCTURAL_PREFIXES = (
    "subdomain_count", "suspicious_tld", "has_fragment", "query_param_count",
    "has_suspicious_ext", "double_slash_redirect", "punycode_domain",
    "domain_has_digits", "has_www", "multi_subdomains", "brand_in_subdomain",
)
_STATISTICAL_PREFIXES = (
    "url_entropy", "domain_entropy", "digit_ratio", "uppercase_ratio",
    "vowel_ratio", "symbol_ratio",
)


def categorize_feature(name: str) -> str:
    """Categorize a canonical feature into its functional engineering group."""
    if name.startswith("kw_") or name in ("keyword_count", "has_brand_name"):
        return "keyword"
    if name in _LEXICAL_PREFIXES:
        return "lexical"
    if name in _STRUCTURAL_PREFIXES:
        return "structural"
    if name in _STATISTICAL_PREFIXES:
        return "statistical"
    return "other"


def _build_enrichment_response(scan: ScanResult) -> IntelEnrichmentResponse:
    """Convert ScanResult ORM enrichment fields to IntelEnrichmentResponse."""
    enrichment = scan.threat_intel_enrichment or {}
    tls_raw = enrichment.get("tls_info")
    geo_raw = enrichment.get("geolocation")

    status_str = "blocked" if enrichment.get("blocked") else "completed"

    return IntelEnrichmentResponse(
        scan_id=scan.id,
        url=scan.url,
        status=status_str,
        domain_age_days=scan.domain_age_days,
        tls_info=TLSInfo(**tls_raw) if isinstance(tls_raw, dict) else None,
        redirect_count=scan.redirect_count or 0,
        final_url=scan.final_url or scan.url,
        redirect_chain=enrichment.get("redirect_chain", [scan.url]),
        geolocation=GeoLocation(**geo_raw) if isinstance(geo_raw, dict) else None,
        enrichment_ms=enrichment.get("enrichment_ms"),
    )


# ── POST /v1/intel/{scan_id}/enrich ───────────────────────────────────────────

@router.post("/intel/{scan_id}/enrich", response_model=IntelEnrichmentResponse)
@limiter.limit("20/minute")
async def trigger_intel_enrichment(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntelEnrichmentResponse:
    """
    Explicitly trigger threat intelligence enrichment for an existing scan record.
    Requires authentication and ownership of the scan.
    """
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    # If already enriched, return cached enrichment
    if scan.threat_intel_enrichment is not None:
        return _build_enrichment_response(scan)

    # Perform enrichment
    enrich_result = await enrich_scan(scan.url)

    # Persist enrichment to database
    scan.domain_age_days = enrich_result.get("domain_age_days")
    tls = enrich_result.get("tls_info")
    scan.tls_valid = tls.get("valid") if isinstance(tls, dict) else None
    scan.redirect_count = enrich_result.get("redirect_count", 0)
    scan.final_url = enrich_result.get("final_url", scan.url)
    scan.threat_intel_enrichment = enrich_result

    await db.commit()
    await db.refresh(scan)
    logger.info("Enrichment successfully persisted for scan %d (User %d)", scan.id, current_user.id)

    return _build_enrichment_response(scan)


# ── GET /v1/intel/{scan_id} ───────────────────────────────────────────────────

@router.get("/intel/{scan_id}", response_model=IntelEnrichmentResponse)
@limiter.limit("30/minute")
async def get_intel_enrichment(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntelEnrichmentResponse:
    """
    Retrieve threat intelligence enrichment for an existing scan.
    Does NOT automatically perform external lookups if not already enriched.
    """
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.threat_intel_enrichment is None:
        return IntelEnrichmentResponse(
            scan_id=scan.id,
            url=scan.url,
            status="pending",
            redirect_count=0,
            redirect_chain=[scan.url],
        )

    return _build_enrichment_response(scan)


# ── GET /v1/scan/{scan_id}/deep-report ────────────────────────────────────────

@router.get("/scan/{scan_id}/deep-report", response_model=DeepScanReportResponse)
@limiter.limit("20/minute")
async def get_deep_scan_report(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    feat_svc: FeatureService = Depends(get_feature_service),
    current_user: User = Depends(get_current_user),
) -> DeepScanReportResponse:
    """
    Retrieve the deep scan report: exactly 59 canonical model features,
    SHAP top attributions, and threat intelligence enrichment if available.
    """
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    # Obtain canonical 59-feature vector
    fv_dict: dict[str, Any] = scan.feature_vector or {}
    if not fv_dict:
        # Re-extract canonical features if not previously stored
        df = feat_svc.extract_features(scan.url)
        fv_dict = df.iloc[0].to_dict()

    feature_items = [
        DeepScanFeature(
            name=name,
            value=fv_dict.get(name, 0.0),
            category=categorize_feature(name),
        )
        for name in feat_svc.schema
    ]

    canonical = CanonicalFeatures(count=len(feature_items), features=feature_items)

    enrichment_resp: IntelEnrichmentResponse | None = None
    if scan.threat_intel_enrichment is not None:
        enrichment_resp = _build_enrichment_response(scan)

    return DeepScanReportResponse(
        scan_id=scan.id,
        url=scan.url,
        prediction=scan.prediction,
        confidence=scan.confidence,
        canonical_features=canonical,
        feature_vector=feature_items,
        intel_enrichment=enrichment_resp,
        top_reasons=scan.top_reasons,
        created_at=scan.created_at.isoformat(),
    )
