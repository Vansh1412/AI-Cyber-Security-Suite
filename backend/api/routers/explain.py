"""
backend/api/routers/explain.py
────────────────────────────────
POST /v1/explain — Explanation endpoint leveraging SHAP.

Returns the same prediction as /scan plus the top reasons
(feature attributions) that drove the classification.
"""

import time
from fastapi import APIRouter, Depends, HTTPException, Request

from backend.schemas.payload import ScanRequest, ExplainResponse, ExplanationFeature
from backend.api.dependencies import get_feature_service, get_prediction_service, get_explainer_service
from backend.services.feature_eng import FeatureService
from backend.services.prediction import PredictionService
from backend.services.explainer import ExplainerService
from backend.core.rate_limit import limiter

router = APIRouter()

# Human-readable descriptions for top features
FEATURE_DESCRIPTIONS = {
    "brand_in_subdomain": "A known brand name appears in the subdomain — a classic phishing technique.",
    "url_length":         "The URL is unusually long, which is common in obfuscated phishing links.",
    "url_entropy":        "The URL has high character randomness, indicating possible obfuscation.",
    "https_flag":         "The URL does not use HTTPS, meaning the connection is unencrypted.",
    "num_dots":           "The URL has an unusual number of dots, often used to mimic legitimate domains.",
    "has_ip":             "The URL uses a raw IP address instead of a domain name — a red flag.",
    "kw_login":           "The URL contains the word 'login', commonly abused in credential phishing.",
    "kw_secure":          "The URL contains the word 'secure', a social engineering tactic.",
    "kw_verify":          "The URL contains the word 'verify', commonly used to request user credentials.",
    "kw_paypal":          "The URL contains 'paypal' in a suspicious context.",
    "num_subdomains":     "The URL has many subdomains, used to obscure the real domain.",
    "suspicious_tld":     "The top-level domain (e.g. .xyz, .tk) is commonly associated with abuse.",
    "path_length":        "The URL path is unusually long.",
    "digit_ratio":        "The URL contains an unusual proportion of digits.",
    "subdomain_count":    "The URL has multiple subdomains stacked, a common cloaking technique.",
}


@router.post("/explain", response_model=ExplainResponse, tags=["Explainability"])
@limiter.limit("20/minute")
def explain_url(
    req: Request,
    request: ScanRequest,
    feat_svc: FeatureService = Depends(get_feature_service),
    pred_svc: PredictionService = Depends(get_prediction_service),
    expl_svc: ExplainerService = Depends(get_explainer_service),
):
    """
    Scans a URL and explains why it was classified as threatening.

    Returns the prediction, confidence, and top feature attributions (via SHAP).
    """
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=422, detail="URL cannot be empty.")

    t0 = time.perf_counter()

    df = feat_svc.extract_features(request.url)
    prediction, confidence = pred_svc.predict(df)

    try:
        raw_impacts = expl_svc.explain(df, prediction)
    except Exception as e:
        raw_impacts = []

    top_reasons = [
        ExplanationFeature(
            feature=imp["feature"],
            value=round(imp["value"], 4),
            impact=round(imp["impact"], 4),
            description=FEATURE_DESCRIPTIONS.get(imp["feature"], ""),
        )
        for imp in raw_impacts
    ]

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return ExplainResponse(
        url=request.url,
        prediction=prediction,
        confidence=round(confidence, 4),
        top_reasons=top_reasons,
        latency_ms=latency_ms,
    )
