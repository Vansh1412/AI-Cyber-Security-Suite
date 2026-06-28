"""
ml/evaluation/adversarial.py
─────────────────────────────
Generates adversarial/mutated URLs to test model robustness.
"""

from __future__ import annotations

import sys
import pickle
import time
from pathlib import Path

import pandas as pd

from ml.features.extractor import FeatureExtractor
from src.config import MODEL_DIR, REPORT_DIR
from src.utils.logger import logger


def generate_adversarial_cases() -> list[dict]:
    return [
        {"url": "paypal.com", "true_class": "legitimate", "type": "baseline"},
        {"url": "paypal-login.com", "true_class": "phishing", "type": "hyphenation"},
        {"url": "paypa1.com", "true_class": "phishing", "type": "typosquat"},
        {"url": "secure-paypal-update.xyz", "true_class": "phishing", "type": "keywords"},
        {"url": "paypal.com.secure-update.xyz", "true_class": "phishing", "type": "brand_in_subdomain"},
        
        {"url": "google.com", "true_class": "legitimate", "type": "baseline"},
        {"url": "g00gle.com", "true_class": "phishing", "type": "typosquat"},
        
        {"url": "bankofamerica.com", "true_class": "legitimate", "type": "baseline"},
        {"url": "bankofamerica-secure-login.net", "true_class": "phishing", "type": "keywords"},
    ]


def main():
    logger.info("=" * 55)
    logger.info("Adversarial Robustness Evaluation")
    logger.info("=" * 55)

    model_path = MODEL_DIR / "xgboost_calibrated.pkl"
    if not model_path.exists():
        model_path = MODEL_DIR / "xgboost_optuna_best.pkl"
        
    with open(model_path, "rb") as f:
        wrapper = pickle.load(f)

    extractor = FeatureExtractor()
    cases = generate_adversarial_cases()
    
    results = []
    
    # Load feature list schema to ensure ordering
    from src.config import SELECTED_FEATURES
    import json
    if SELECTED_FEATURES.exists():
        schema = json.loads(SELECTED_FEATURES.read_text())["features"]
    else:
        logger.error("No selected_features.json found.")
        return

    logger.info("Evaluating %d adversarial cases...", len(cases))
    
    for case in cases:
        url = case["url"]
        features_dict = extractor.extract(url)
        
        # Build strict feature vector
        vector = {k: features_dict.get(k, 0) for k in schema}
        df = pd.DataFrame([vector])
        
        t0 = time.perf_counter()
        pred_label = wrapper.predict(df)[0]
        if hasattr(wrapper.model, "predict_proba"):
            probs = wrapper.model.predict_proba(df)[0]
            pred_idx = wrapper._label_encoder.transform([pred_label])[0]
            conf = probs[pred_idx]
        else:
            conf = 1.0
            
        latency_ms = (time.perf_counter() - t0) * 1000
        
        results.append({
            "url": url,
            "type": case["type"],
            "true_class": case["true_class"],
            "pred_class": pred_label,
            "confidence": round(conf, 3),
            "latency_ms": round(latency_ms, 2)
        })

    results_df = pd.DataFrame(results)
    print("\nAdversarial Results:")
    print(results_df.to_string(index=False))
    
    # Generate simple HTML
    html_path = REPORT_DIR / "adversarial_report.html"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    html_path.write_text(f"""
    <html>
    <head><style>body{{font-family:sans-serif;}} table{{border-collapse:collapse;width:100%;}} th,td{{border:1px solid #ddd;padding:8px;}} tr:nth-child(even){{background-color:#f2f2f2;}} th{{padding-top:12px;padding-bottom:12px;text-align:left;background-color:#04AA6D;color:white;}}</style></head>
    <body><h2>Adversarial Robustness Report</h2>
    {results_df.to_html(index=False, classes='table')}
    </body></html>
    """, encoding="utf-8")
    
    logger.info("Saved adversarial report -> %s", html_path.name)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
