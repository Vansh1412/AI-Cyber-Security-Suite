"""
backend/services/feature_eng.py
───────────────────────────────
Service for extracting and validating features.
"""

import json
import pandas as pd
from typing import Dict, List

from backend.core.config import settings
from ml.features.extractor import FeatureExtractor
from src.utils.logger import logger


class FeatureService:
    def __init__(self):
        self.extractor = FeatureExtractor()
        
        with open(settings.SCHEMA_PATH, "r") as f:
            self.schema: List[str] = json.load(f)["features"]
            
        logger.info(f"FeatureService initialized with schema of {len(self.schema)} features.")

    def extract_features(self, url: str) -> pd.DataFrame:
        """
        Extracts features for a single URL and returns a 1-row DataFrame 
        strictly aligned to the schema.
        """
        raw_features = self.extractor.extract(url)
        
        # Build strict feature vector
        vector = {feat: raw_features.get(feat, 0.0) for feat in self.schema}
        
        return pd.DataFrame([vector])
