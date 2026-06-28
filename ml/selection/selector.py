"""
ml/selection/selector.py
─────────────────────────
FeatureSelector — pre-training feature selection pipeline.

Pipeline stages
---------------
1. Drop explicitly configured features (from training.yaml: drop_features)
2. Drop string/object columns (tld, file_extension — not numeric)
3. Variance Threshold — remove zero-variance (constant) features
4. Correlation Filter — remove one feature from each pair with corr > threshold

Output
------
  ml/feature_store/selected_features.json  — list of retained features + drop reasons

Later (post-training):
  SHAP importance + permutation importance are used to further refine.

Usage
-----
    python -m ml.selection.selector
"""

from __future__ import annotations

import json
import sys
import time

import numpy as np
import pandas as pd
import yaml

from src.config import FEATURES_100K, SELECTED_FEATURES, TRAINING_CONFIG
from src.utils.logger import logger

# Meta-columns that are never features
META_COLS = {"url", "label", "source"}


def _load_config() -> dict:
    with open(TRAINING_CONFIG, "r") as f:
        return yaml.safe_load(f)


class FeatureSelector:
    """
    Runs the pre-training feature selection pipeline.

    Parameters
    ----------
    source_path : Path | None
        Parquet file to analyse (default: features_train_100k.parquet).
    variance_threshold : float
        Minimum variance to retain a feature (default: 0.0 — drop constants only).
    correlation_threshold : float
        Maximum allowed Pearson correlation between two features (default: 0.98).
    """

    def __init__(
        self,
        source_path=None,
        variance_threshold: float | None = None,
        correlation_threshold: float | None = None,
    ) -> None:
        cfg             = _load_config()
        fs_cfg          = cfg.get("feature_selection", {})
        train_cfg       = cfg.get("training", {})

        self.source_path          = source_path or FEATURES_100K
        self.variance_threshold   = variance_threshold   or fs_cfg.get("variance_threshold",   0.0)
        self.correlation_threshold = correlation_threshold or fs_cfg.get("correlation_threshold", 0.98)
        self.explicit_drops: list[str] = train_cfg.get("drop_features", [])

        self.dropped:  dict[str, str] = {}   # feature → reason
        self.retained: list[str]      = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def fit(self, df: pd.DataFrame | None = None) -> "FeatureSelector":
        """
        Fit the selector on a DataFrame (or load from source_path).

        Parameters
        ----------
        df : optional DataFrame — if None, loads from self.source_path.

        Returns
        -------
        self (for chaining)
        """
        if df is None:
            logger.info("Loading: %s", self.source_path)
            df = pd.read_parquet(self.source_path)

        t0 = time.perf_counter()
        logger.info("=" * 55)
        logger.info("FeatureSelector — fitting on %s rows × %s cols",
                    f"{len(df):,}", len(df.columns))
        logger.info("=" * 55)

        # Start with all non-meta columns
        candidates = [c for c in df.columns if c not in META_COLS]
        logger.info("Starting features: %d", len(candidates))

        # ── Stage 1: Explicit drops (from training.yaml) ───────────────────────
        for feat in self.explicit_drops:
            if feat in candidates:
                self.dropped[feat] = "explicit_drop (training.yaml)"
                candidates.remove(feat)
                logger.info("  DROP (explicit): %s", feat)

        # ── Stage 2: Object/string columns ────────────────────────────────────
        numeric_df = df[candidates].select_dtypes(include=[np.number])
        for feat in list(candidates):
            if feat not in numeric_df.columns:
                self.dropped[feat] = "non_numeric (object dtype)"
                candidates.remove(feat)
                logger.info("  DROP (non-numeric): %s", feat)

        # ── Stage 3: Variance threshold ────────────────────────────────────────
        variances = numeric_df[candidates].var()
        low_var = variances[variances <= self.variance_threshold].index.tolist()
        for feat in low_var:
            self.dropped[feat] = f"low_variance (var={variances[feat]:.6f})"
            candidates.remove(feat)
            logger.info("  DROP (low variance): %s  var=%.6f", feat, variances[feat])

        if not low_var:
            logger.info("  Variance check: all features pass")

        # ── Stage 4: Correlation filter ────────────────────────────────────────
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            corr_matrix = numeric_df[candidates].corr().abs()

        to_drop_corr: set[str] = set()
        cols = candidates.copy()
        for i, c1 in enumerate(cols):
            if c1 in to_drop_corr:
                continue
            for c2 in cols[i + 1:]:
                if c2 in to_drop_corr:
                    continue
                val = corr_matrix.loc[c1, c2]
                if val >= self.correlation_threshold:
                    # Drop c2 (keep c1 — it appeared first / has lower index)
                    to_drop_corr.add(c2)
                    self.dropped[c2] = f"high_correlation (corr={val:.4f} with {c1})"
                    logger.info("  DROP (corr %.4f): %s  ↔  %s", val, c2, c1)

        candidates = [c for c in candidates if c not in to_drop_corr]

        if not to_drop_corr:
            logger.info("  Correlation check: no pairs above threshold %.2f", self.correlation_threshold)

        # ── Result ─────────────────────────────────────────────────────────────
        self.retained = candidates
        elapsed = time.perf_counter() - t0

        logger.info("-" * 55)
        logger.info(
            "Selection complete in %.2fs: %d retained, %d dropped",
            elapsed, len(self.retained), len(self.dropped),
        )

        return self

    def save(self) -> None:
        """Save selected_features.json to the feature store."""
        result = {
            "version":       1,
            "n_features":    len(self.retained),
            "n_dropped":     len(self.dropped),
            "features":      self.retained,
            "dropped":       self.dropped,
        }
        SELECTED_FEATURES.write_text(json.dumps(result, indent=2))
        logger.info("Feature selection schema saved → %s", SELECTED_FEATURES)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply feature selection to a DataFrame.

        Parameters
        ----------
        df : Feature DataFrame (must contain all retained feature columns).

        Returns
        -------
        pd.DataFrame  with only retained feature columns (+ meta cols if present).
        """
        if not self.retained:
            raise RuntimeError("Call fit() before transform().")
        keep = [c for c in self.retained if c in df.columns]
        meta = [c for c in META_COLS if c in df.columns]
        return df[keep + meta]

    def fit_transform(self, df: pd.DataFrame | None = None) -> pd.DataFrame:
        """Fit and transform in one call."""
        self.fit(df)
        self.save()
        if df is None:
            df = pd.read_parquet(self.source_path)
        return self.transform(df)

    def print_report(self) -> None:
        """Print selection summary to stdout."""
        from tabulate import tabulate
        print()
        print(f"── Feature Selection: {len(self.retained)} retained, {len(self.dropped)} dropped ─────")
        if self.dropped:
            rows = [{"feature": k, "reason": v} for k, v in self.dropped.items()]
            print(tabulate(rows, headers="keys", tablefmt="github", showindex=False))
        print()
        print("Retained features:")
        for i, f in enumerate(self.retained, 1):
            print(f"  {i:2d}. {f}")
        print()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    selector = FeatureSelector()
    selector.fit()
    selector.save()
    selector.print_report()


if __name__ == "__main__":
    main()
