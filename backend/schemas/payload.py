"""
backend/schemas/payload.py
───────────────────────────
Pydantic models for API Requests and Responses.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., description="The URL to be scanned.")


class ScanResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    latency_ms: float
    cache_hit: bool = False


class ExplanationFeature(BaseModel):
    feature: str
    value: float
    impact: float
    description: str = ""


class ExplainResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    top_reasons: list[ExplanationFeature]
    latency_ms: float


class HistoryItem(BaseModel):
    id: int
    url: str
    prediction: str
    confidence: float
    latency_ms: float | None
    cache_hit: bool
    top_reasons: list | None
    is_zero_day: bool = False
    source_feed: str | None = None
    # Sprint 4 enrichment summary
    domain_age_days: int | None = None
    tls_valid: bool | None = None
    redirect_count: int | None = None
    final_url: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


def _compute_threat_score(prediction: str, confidence: float) -> float:
    """Weighted threat score: 0.0 (safe) to 1.0 (maximum threat)."""
    weights: dict[str, float] = {
        "phishing": 1.0,
        "malware": 0.95,
        "defacement": 0.70,
        "legitimate": 0.0,
    }
    return round(weights.get(prediction, 0.0) * confidence, 4)


class FullReport(HistoryItem):
    """Extended scan detail with threat score and model environment."""
    threat_score: float = 0.0
    model_env: str = "production"


class StatsResponse(BaseModel):
    total_scans: int
    by_class: dict
    daily_volume: list   # list of {"date": "2024-01-01", "count": 42}
