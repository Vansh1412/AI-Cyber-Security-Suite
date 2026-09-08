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
    created_at: datetime

    model_config = {"from_attributes": True}


class StatsResponse(BaseModel):
    total_scans: int
    by_class: dict
    daily_volume: list   # list of {"date": "2024-01-01", "count": 42}
