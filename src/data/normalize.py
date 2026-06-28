"""
src/data/normalize.py
──────────────────────
DataNormalizer — placeholder for Phase 2 feature-level normalization.

This module will be expanded in Phase 2 (Feature Engineering) to handle:
  • Numerical feature scaling (MinMaxScaler / StandardScaler)
  • Categorical encoding
  • Feature selection / dimensionality reduction

At this stage it serves as a documented stub so the import chain is complete
and the module can be imported without errors.

Usage (Phase 2+):
    from src.data.normalize import DataNormalizer

    normalizer = DataNormalizer()
    normalizer.fit(train_features)
    X_scaled = normalizer.transform(features)
"""

from src.utils.logger import logger


class DataNormalizer:
    """
    Placeholder for Phase 2 feature normalization.

    Will wrap sklearn transformers to provide a consistent fit/transform API
    once feature extraction (ml/features/extractor.py) is implemented.
    """

    def __init__(self) -> None:
        logger.debug("DataNormalizer initialised (stub — Phase 2).")

    def fit(self, features) -> "DataNormalizer":  # noqa: ANN001
        """Fit scaler to training features. (Not yet implemented.)"""
        logger.warning("DataNormalizer.fit() is not yet implemented (Phase 2).")
        return self

    def transform(self, features):  # noqa: ANN001
        """Transform features using the fitted scaler. (Not yet implemented.)"""
        logger.warning("DataNormalizer.transform() is not yet implemented (Phase 2).")
        return features
