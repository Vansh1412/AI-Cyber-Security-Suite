"""
src/data/merge.py
──────────────────
DataMerger — combines all cleaned datasets into a single master CSV.

Responsibilities:
  • Read all cleaned_*.csv files from datasets/processed/
  • Concatenate into one DataFrame
  • Shuffle rows (reproducible, seed=42)
  • Log class distribution (phishing vs legitimate)
  • Save to datasets/processed/merged_dataset.csv

Usage:
    from src.data.merge import DataMerger

    merger = DataMerger()
    merger.merge()
"""

import pandas as pd
from tabulate import tabulate

from src.config import PROCESSED_DIR, MERGED_DATASET, SCHEMA_COLUMNS
from src.utils.logger import logger


class DataMerger:
    """Merges all cleaned CSVs into a single shuffled master dataset."""

    def merge(self) -> pd.DataFrame:
        """
        Load, concatenate, shuffle, and save all cleaned datasets.

        Returns
        -------
        pd.DataFrame
            The merged dataset (also saved to disk).
        """
        files = sorted(PROCESSED_DIR.glob("cleaned_*.csv"))

        if not files:
            logger.warning(
                "No cleaned CSV files found in '%s'. "
                "Run DataCleaner first.",
                PROCESSED_DIR,
            )
            return pd.DataFrame()

        logger.info("Merging %d cleaned file(s)…", len(files))

        frames: list[pd.DataFrame] = []
        for path in files:
            try:
                df = pd.read_csv(path, low_memory=False)
                # Ensure all required columns are present
                missing = [c for c in SCHEMA_COLUMNS if c not in df.columns]
                if missing:
                    logger.error(
                        "Skipping '%s' — missing columns: %s", path.name, missing
                    )
                    continue
                frames.append(df[SCHEMA_COLUMNS])
                logger.info("  ✓ %s — %d rows", path.name, len(df))
            except Exception as exc:  # noqa: BLE001
                logger.error("Could not read '%s': %s", path.name, exc)

        if not frames:
            logger.error("No valid frames to merge.")
            return pd.DataFrame()

        merged = pd.concat(frames, ignore_index=True)

        # ── Shuffle ────────────────────────────────────────────────────────────
        merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

        # ── Class distribution report ──────────────────────────────────────────
        dist = merged["label"].value_counts().reset_index()
        dist.columns = ["label", "count"]
        dist["percentage"] = (dist["count"] / len(merged) * 100).round(2)

        print()
        print("── Class Distribution ───────────────────────────────")
        print(tabulate(dist, headers="keys", tablefmt="github", showindex=False))
        print(f"   Total rows: {len(merged):,}")
        print()

        for _, row in dist.iterrows():
            logger.info(
                "  Label '%s': %s rows (%.1f%%)",
                row["label"], f"{row['count']:,}", row["percentage"],
            )

        # ── Save ───────────────────────────────────────────────────────────────
        merged.to_csv(MERGED_DATASET, index=False)
        logger.info("Merged dataset saved → %s (%d rows)", MERGED_DATASET, len(merged))

        return merged
