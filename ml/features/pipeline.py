"""
ml/features/pipeline.py
────────────────────────
FeaturePipeline — batch feature extraction engine.

Reads merged_dataset.csv, extracts 63 features per URL in batches,
validates the result, and saves to ml/feature_store/features_v1.parquet.

Design
------
• Batch processing (configurable chunk size) keeps memory bounded
  even for 2.77M rows.
• Uses DataFrame.apply() which is ~10x faster than iterrows() at scale.
• Per-row error isolation: one bad URL never crashes the batch.
• tqdm progress bar for live feedback.
• Execution stats logged at completion.

Usage
-----
    # Full pipeline (2.77M rows)
    python -m ml.features.pipeline

    # Quick test on 100k rows
    from ml.features.pipeline import FeaturePipeline
    pipeline = FeaturePipeline(sample=100_000)
    pipeline.run()
"""

import time
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from ml.features.extractor import FeatureExtractor
from ml.features.validator import FeatureValidator
from src.config import FEATURES_V1, MERGED_DATASET, REPORT_DIR
from src.utils.logger import logger

# ── Default configuration ──────────────────────────────────────────────────────
DEFAULT_CHUNK_SIZE = 10_000   # rows processed per batch
SAMPLE_SIZE: int | None = None  # Set to e.g. 100_000 for quick testing


class FeaturePipeline:
    """
    Batch feature extraction pipeline.

    Parameters
    ----------
    chunk_size : int
        Number of rows to process per batch (default 10,000).
    sample : int | None
        If set, only process the first N rows (useful for rapid testing).
    output_path : Path | None
        Override the default parquet output path.
    """

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        sample: int | None = SAMPLE_SIZE,
        output_path: Path | None = None,
    ) -> None:
        self.chunk_size  = chunk_size
        self.sample      = sample
        self.output_path = output_path or FEATURES_V1
        self._extractor  = FeatureExtractor()
        self._zero       = self._extractor._zero_vector()  # cached once

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> Path:
        """
        Execute the full pipeline:
          1. Load merged_dataset.csv
          2. Extract features in batches using apply()
          3. Validate the feature matrix
          4. Save to features_v1.parquet

        Returns
        -------
        Path
            Path to the saved parquet file.
        """
        logger.info("=" * 60)
        logger.info("Feature Pipeline — Start")
        logger.info("=" * 60)

        # ── 1. Load source data ────────────────────────────────────────────────
        logger.info("Loading: %s", MERGED_DATASET)
        df_raw = pd.read_csv(MERGED_DATASET, low_memory=False)

        if self.sample:
            df_raw = df_raw.head(self.sample)
            logger.info("SAMPLE MODE: using first %s rows", f"{self.sample:,}")

        total_rows = len(df_raw)
        logger.info("Total rows to process: %s", f"{total_rows:,}")

        # ── 2. Extract features in batches ─────────────────────────────────────
        all_frames: list[pd.DataFrame] = []
        self._errors = 0
        t_start = time.perf_counter()

        chunks = range(0, total_rows, self.chunk_size)
        for start in tqdm(chunks, desc="Extracting features", unit="batch"):
            chunk = df_raw.iloc[start : start + self.chunk_size]
            chunk_feats = chunk.apply(self._extract_row, axis=1)
            all_frames.append(chunk_feats)

        elapsed = time.perf_counter() - t_start
        logger.info("Extraction complete: %s rows in %.1fs (%.0f rows/s)",
                    f"{total_rows:,}", elapsed, total_rows / elapsed)
        if self._errors:
            logger.warning("Rows with extraction errors: %d", self._errors)

        # ── 3. Build DataFrame ─────────────────────────────────────────────────
        logger.info("Building feature DataFrame…")
        feature_df = pd.concat(all_frames, ignore_index=True)

        # Ensure metadata columns come last for readability
        meta_cols    = ["url", "label", "source"]
        feature_cols = [c for c in feature_df.columns if c not in meta_cols]
        feature_df   = feature_df[feature_cols + meta_cols]

        logger.info(
            "Feature matrix shape: %d rows × %d columns (%d features + 3 meta)",
            len(feature_df), len(feature_df.columns), len(feature_cols),
        )

        # ── 4. Type optimisation (int64→int32, float64→float32) ───────────────
        for col in feature_df.select_dtypes(include=["int64"]).columns:
            feature_df[col] = feature_df[col].astype("int32")
        for col in feature_df.select_dtypes(include=["float64"]).columns:
            feature_df[col] = feature_df[col].astype("float32")

        # ── 5. Validate ────────────────────────────────────────────────────────
        logger.info("Running feature validation…")
        validator = FeatureValidator()
        validator.validate(feature_df[feature_cols])   # validate features only

        # ── 6. Save parquet ────────────────────────────────────────────────────
        logger.info("Saving → %s", self.output_path)
        feature_df.to_parquet(self.output_path, index=False, compression="snappy")

        size_mb = self.output_path.stat().st_size / 1_048_576
        logger.info(
            "Saved: %s (%.1f MB, %d rows, %d columns)",
            self.output_path.name, size_mb, len(feature_df), len(feature_df.columns),
        )

        # ── 7. Quick sanity print ──────────────────────────────────────────────
        self._print_summary(feature_df, feature_cols, size_mb)
        logger.info("Feature Pipeline — Complete (%.1fs total)", time.perf_counter() - t_start)
        return self.output_path

    # ── Internal ───────────────────────────────────────────────────────────────

    def _extract_row(self, row: pd.Series) -> pd.Series:
        """Extract features for a single DataFrame row. Never raises."""
        url = str(row.get("url", ""))
        try:
            feats = self._extractor.extract(url)
        except Exception:  # noqa: BLE001
            self._errors += 1
            feats = dict(self._zero)   # copy to avoid mutation

        feats["url"]    = url
        feats["label"]  = str(row.get("label",  ""))
        feats["source"] = str(row.get("source", ""))
        return pd.Series(feats)

    def _print_summary(
        self, df: pd.DataFrame, feature_cols: list[str], size_mb: float
    ) -> None:
        from tabulate import tabulate

        print()
        print("── Feature Pipeline Summary ─────────────────────────────────────")
        print(f"   Rows:        {len(df):>12,}")
        print(f"   Features:    {len(feature_cols):>12,}")
        print(f"   File size:   {size_mb:>11.1f} MB")
        print(f"   Output:      {self.output_path}")
        print()

        # Class distribution
        dist = df["label"].value_counts().reset_index()
        dist.columns = ["label", "count"]
        dist["pct"] = (dist["count"] / len(df) * 100).round(2)
        print(tabulate(dist, headers="keys", tablefmt="github", showindex=False))
        print()


# ── CLI entry point ────────────────────────────────────────────────────────────

def main() -> None:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    pipeline = FeaturePipeline()
    pipeline.run()


if __name__ == "__main__":
    main()
