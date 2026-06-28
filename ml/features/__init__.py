# ml/features/__init__.py
"""
Feature engineering package for AI Cyber Security Suite.

Public interface — import from here:

    from ml.features import FeatureExtractor

    extractor = FeatureExtractor()
    features  = extractor.extract("https://paypal-login.evil.com/verify")
"""

from ml.features.extractor import FeatureExtractor

__all__ = ["FeatureExtractor"]
