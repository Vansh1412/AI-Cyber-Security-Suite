"""
backend/schemas/intel.py
─────────────────────────
Sprint 4: Pydantic schemas for Threat Intelligence Enrichment & Deep Analysis.

Contracts:
  - Canonical ML Feature Count is strictly 59.
  - Threat enrichment is explicitly typed and separated from model features.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator


class TLSInfo(BaseModel):
    valid: bool
    issuer: str | None = None
    subject: str | None = None
    expires_at: str | None = None
    days_to_expiry: int | None = None
    reason: str | None = None


class GeoLocation(BaseModel):
    ip: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    org: str | None = None
    private: bool = False


class IntelEnrichmentResponse(BaseModel):
    """Full threat intelligence enrichment for a scan result."""
    scan_id: int
    url: str
    status: str = "completed"  # pending | completed | failed | blocked
    domain_age_days: int | None = None
    tls_info: TLSInfo | None = None
    redirect_count: int = 0
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    geolocation: GeoLocation | None = None
    enrichment_ms: float | None = None

    model_config = {"from_attributes": True}


class DeepScanFeature(BaseModel):
    """A single canonical model feature with its value and category."""
    name: str
    value: float | int
    category: str  # lexical | structural | statistical | keyword | other


class CanonicalFeatures(BaseModel):
    """Strictly 59 canonical features evaluated by the production ML model."""
    count: int = 59
    features: list[DeepScanFeature] = Field(default_factory=list)


class DeepScanReportResponse(BaseModel):
    """
    Deep scan report: 59 canonical model features, SHAP top reasons,
    and optional user-initiated threat intelligence enrichment.
    """
    scan_id: int
    url: str
    prediction: str
    confidence: float
    canonical_features: CanonicalFeatures
    feature_vector: list[DeepScanFeature] = Field(
        default_factory=list,
        description="Alias for canonical_features.features for client backwards-compatibility",
    )
    intel_enrichment: IntelEnrichmentResponse | None = None
    top_reasons: list[dict[str, Any]] | None = None
    created_at: str

    model_config = {"from_attributes": True}


# ── Analytics & Investigation Schemas ─────────────────────────────────────────

class GlobalAnalyticsResponse(BaseModel):
    """Admin-only global platform analytics."""
    total_scans: int
    total_users: int
    by_class: dict[str, int]
    daily_volume: list[dict[str, Any]]
    zero_day_total: int
    zero_day_verified: int
    zero_day_promoted: int
    top_threat_domains: list[dict[str, Any]]
    model_env: str
    active_model: str


class TrendPoint(BaseModel):
    date: str
    phishing: int = 0
    malware: int = 0
    defacement: int = 0
    legitimate: int = 0
    total: int = 0


class TrendsResponse(BaseModel):
    """Sliding-window threat trend time series."""
    window_days: int
    data: list[TrendPoint]


class FeatureImportanceItem(BaseModel):
    feature: str
    avg_impact: float
    appearance_count: int
    category: str


class FeatureImportanceResponse(BaseModel):
    """Aggregated SHAP feature importance across analyzed scans."""
    total_scans_analyzed: int
    features: list[FeatureImportanceItem]


class BulkScanRequest(BaseModel):
    urls: list[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of URLs to scan (max 20, max 2048 chars each).",
    )

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, urls: list[str]) -> list[str]:
        if not urls:
            raise ValueError("Request must contain at least one URL.")
        cleaned = []
        for u in urls:
            if not isinstance(u, str) or not u.strip():
                raise ValueError("URLs in batch cannot be empty or whitespace.")
            u_clean = u.strip()
            if len(u_clean) > 2048:
                raise ValueError("URL exceeds maximum length of 2048 characters.")
            cleaned.append(u_clean)
        return cleaned


class BulkScanItem(BaseModel):
    """Result of scanning one URL in a bulk request."""
    url: str
    prediction: str | None = None
    confidence: float | None = None
    latency_ms: float | None = None
    cache_hit: bool = False
    source: str | None = None
    error: str | None = None


class BulkScanResponse(BaseModel):
    """Response for bulk URL scan."""
    total: int
    results: list[BulkScanItem]
    elapsed_ms: float


class DomainScanHistory(BaseModel):
    """Cross-scan history for a domain."""
    domain: str
    total_scans: int
    threat_count: int
    latest_prediction: str | None = None
    latest_confidence: float | None = None
    scans: list[dict[str, Any]]


class PublicAnalyticsResponse(BaseModel):
    """Limited public analytics — aggregate counts only."""
    total_scans_platform: int
    threat_ratio: float
    by_class: dict[str, int]
