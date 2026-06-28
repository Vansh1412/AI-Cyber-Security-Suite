"""
ml/datasets/sampler.py
───────────────────────
DatasetSampler — creates stratified multi-scale training subsets
from features_v1.parquet for fast development iteration.

Output files
------------
  ml/feature_store/features_train_100k.parquet  — 100,000 rows
  ml/feature_store/features_train_500k.parquet  — 500,000 rows

Both preserve the original class distribution (stratified sampling).

Usage
-----
    python -m ml.datasets.sampler
    python -m ml.datasets.sampler --sizes 50000 200000
"""

from __future__ import annotations

import sys
import time

import pandas as pd

from src.config import (
    FEATURE_STORE_DIR,
    FEATURES_100K,
    FEATURES_500K,
    FEATURES_V1,
)
from src.utils.logger import logger


class DatasetSampler:
    """
    Creates stratified subsets of features_v1.parquet.

    Parameters
    ----------
    source : str | Path
        Source parquet file (default: features_v1.parquet).
    seed : int
        Random seed for reproducibility (default: 42).
    """

    def __init__(self, source=None, seed: int = 42) -> None:
        self.source = source or FEATURES_V1
        self.seed   = seed

    def sample(self, n: int, output_path=None) -> pd.DataFrame:
        """
        Create a stratified sample of n rows.

        Parameters
        ----------
        n           : Target row count.
        output_path : Where to save the parquet. If None, returns df only.

        Returns
        -------
        pd.DataFrame  The sampled subset.
        """
        logger.info("Loading source: %s", self.source)
        t0  = time.perf_counter()
        df  = pd.read_parquet(self.source)
        total = len(df)

        if n >= total:
            logger.warning("Requested %d rows but source only has %d — returning full dataset.", n, total)
            sampled = df
        else:
            # Stratified sample preserving label distribution
            sampled = (
                df.groupby("label", group_keys=False)
                .sample(frac=n / total, random_state=self.seed)
                .reset_index(drop=True)
            )
            # May be slightly off due to rounding — trim to exactly n rows
            if len(sampled) > n:
                sampled = sampled.sample(n=n, random_state=self.seed).reset_index(drop=True)

        logger.info(
            "Sampled %s rows from %s in %.1fs",
            f"{len(sampled):,}", f"{total:,}", time.perf_counter() - t0,
        )

        # Class distribution sanity check
        dist = sampled["label"].value_counts(normalize=True).round(4)
        logger.info("Class distribution: %s", dist.to_dict())

        if output_path:
            sampled.to_parquet(output_path, index=False, compression="snappy")
            size_mb = output_path.stat().st_size / 1_048_576
            logger.info("Saved → %s (%.1f MB)", output_path, size_mb)

        return sampled

    def run_all(self) -> None:
        """Create the 100k and 500k subsets."""
        logger.info("=" * 55)
        logger.info("DatasetSampler — creating multi-scale subsets")
        logger.info("=" * 55)

        sizes = [
            (100_000,  FEATURES_100K,  "100k"),
            (500_000,  FEATURES_500K,  "500k"),
        ]

        for n, path, label in sizes:
            if path.exists():
                logger.info("SKIP — %s already exists: %s", label, path.name)
                continue
            logger.info("Creating %s subset → %s", label, path.name)
            self.sample(n, output_path=path)

        logger.info("DatasetSampler — complete")
        self._print_summary()

    def _print_summary(self) -> None:
        print()
        print("── Dataset Subsets ───────────────────────────────────────────")
        for path in [FEATURES_100K, FEATURES_500K, FEATURES_V1]:
            if path.exists():
                mb = path.stat().st_size / 1_048_576
                df = pd.read_parquet(path, columns=["label"])
                print(f"   {path.name:<40} {len(df):>10,} rows   {mb:>6.1f} MB")
        print()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sampler = DatasetSampler()
    sampler.run_all()


if __name__ == "__main__":
    main()
