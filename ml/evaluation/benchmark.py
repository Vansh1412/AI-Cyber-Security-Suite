"""
ml/evaluation/benchmark.py
───────────────────────────
Inference Speed Benchmarking.

Evaluates batch size processing times for the API.
"""

from __future__ import annotations

import sys
import pickle
import time
import numpy as np
import pandas as pd
from pathlib import Path

from ml.features.extractor import FeatureExtractor
from src.config import MODEL_DIR
from src.utils.logger import logger


def main():
    logger.info("=" * 55)
    logger.info("Inference Speed Benchmarking")
    logger.info("=" * 55)

    model_path = MODEL_DIR / "xgboost_calibrated.pkl"
    if not model_path.exists():
        model_path = MODEL_DIR / "xgboost_optuna_best.pkl"
        
    with open(model_path, "rb") as f:
        wrapper = pickle.load(f)

    from src.config import SELECTED_FEATURES
    import json
    schema = json.loads(SELECTED_FEATURES.read_text())["features"]
    
    extractor = FeatureExtractor()
    
    batch_sizes = [1, 10, 100, 1000]
    results = []
    
    base_url = "http://example.com/test/url"
    
    for b in batch_sizes:
        # Pre-extract features for benchmarking just the model vs end-to-end
        # Here we benchmark end-to-end (extraction + prediction)
        
        t0 = time.perf_counter()
        
        # 1. Extraction
        vectors = []
        for _ in range(b):
            f_dict = extractor.extract(base_url)
            vectors.append({k: f_dict.get(k, 0) for k in schema})
            
        df = pd.DataFrame(vectors)
        
        # 2. Prediction
        _ = wrapper.predict(df)
        
        t1 = time.perf_counter()
        
        total_time_ms = (t1 - t0) * 1000
        avg_time_ms = total_time_ms / b
        
        results.append({
            "Batch Size": b,
            "Total Time (ms)": round(total_time_ms, 2),
            "Avg Time per URL (ms)": round(avg_time_ms, 2)
        })
        
    print("\nBenchmark Results (End-to-End: Extraction + Prediction):")
    results_df = pd.DataFrame(results)
    print(results_df.to_string(index=False))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
