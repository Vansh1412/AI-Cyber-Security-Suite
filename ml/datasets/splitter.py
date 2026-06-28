"""
ml/datasets/splitter.py
────────────────────────
DatasetSplitter — reproducible train/val/test splits with SHA-256
verification to guarantee splits are never accidentally regenerated.

Split ratios
------------
  train : 70%   (for model training and cross-validation)
  val   : 15%   (for hyperparameter tuning feedback)
  test  : 15%   (LOCKED — evaluated only once, never during development)

Design rules
------------
  1. Seed is always read from configs/training.yaml (default: 42)
  2. Splits are stratified on the label column
  3. Once test.parquet exists and manifest.json matches,
     the splitter will NOT regenerate — it will refuse.
  4. A SHA-256 checksum is stored in manifest.json after first run
  5. Source dataset is read from configs/training.yaml (dataset scale)

Usage
-----
    python -m ml.datasets.splitter                   # creates splits
    python -m ml.datasets.splitter --verify          # verify checksums
    python -m ml.datasets.splitter --force           # regenerate (rare)
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pandas as pd
import yaml
from sklearn.model_selection import train_test_split

from src.config import (
    FEATURES_100K,
    FEATURES_500K,
    FEATURES_V1,
    MANIFEST,
    TEST_PATH,
    TRAIN_PATH,
    TRAINING_CONFIG,
    VAL_PATH,
)
from src.utils.logger import logger

_DATASET_MAP = {
    "100k": FEATURES_100K,
    "500k": FEATURES_500K,
    "full": FEATURES_V1,
}


def _load_config() -> dict:
    with open(TRAINING_CONFIG, "r") as f:
        return yaml.safe_load(f)


def _sha256(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class DatasetSplitter:
    """
    Reproducible train/val/test splitter.

    Parameters
    ----------
    force : bool
        If True, regenerate splits even if they already exist.
    """

    def __init__(self, force: bool = False) -> None:
        cfg         = _load_config()["training"]
        self.seed   = cfg.get("random_seed", 42)
        self.scale  = cfg.get("dataset", "100k")
        self.target = cfg.get("target_column", "label")
        self.test_size = cfg.get("test_size",  0.15)
        self.val_size  = cfg.get("val_size",   0.15)
        self.force     = force
        self.source    = _DATASET_MAP.get(self.scale, FEATURES_100K)

    # ── Public API ─────────────────────────────────────────────────────────────

    def split(self) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Create stratified train/val/test splits.

        Returns (train_df, val_df, test_df).
        Saves parquet files and manifest.json.
        Refuses to overwrite existing verified splits (unless force=True).
        """
        logger.info("=" * 55)
        logger.info("DatasetSplitter — Seed=%d  Scale=%s", self.seed, self.scale)
        logger.info("=" * 55)

        # ── Guard: refuse to overwrite verified splits ─────────────────────────
        if not self.force and self._splits_verified():
            logger.info("Splits already exist and checksums match — skipping.")
            logger.info("Use --force to regenerate.")
            return self._load_existing()

        # ── Load source ────────────────────────────────────────────────────────
        logger.info("Loading: %s", self.source)
        t0 = time.perf_counter()
        df = pd.read_parquet(self.source)
        logger.info("Loaded %s rows in %.1fs", f"{len(df):,}", time.perf_counter() - t0)

        # ── Split ──────────────────────────────────────────────────────────────
        # Step 1: carve out test set
        train_val, test = train_test_split(
            df,
            test_size=self.test_size,
            stratify=df[self.target],
            random_state=self.seed,
        )

        # Step 2: carve out val from remaining
        relative_val = self.val_size / (1.0 - self.test_size)
        train, val = train_test_split(
            train_val,
            test_size=relative_val,
            stratify=train_val[self.target],
            random_state=self.seed,
        )

        logger.info(
            "Split sizes — train: %s | val: %s | test: %s",
            f"{len(train):,}", f"{len(val):,}", f"{len(test):,}",
        )

        # ── Save ───────────────────────────────────────────────────────────────
        for df_part, path, name in [
            (train, TRAIN_PATH, "train"),
            (val,   VAL_PATH,   "val"),
            (test,  TEST_PATH,  "test"),
        ]:
            df_part.to_parquet(path, index=False, compression="snappy")
            logger.info("Saved %s → %s (%.1f MB)", name, path.name,
                        path.stat().st_size / 1_048_576)

        # ── Write manifest ─────────────────────────────────────────────────────
        self._write_manifest(train, val, test)
        self._print_summary(train, val, test)

        return train, val, test

    def verify(self) -> bool:
        """Verify existing split checksums against manifest."""
        if self._splits_verified():
            logger.info("Verification PASSED — all checksums match.")
            return True
        else:
            logger.error("Verification FAILED — splits may have been corrupted.")
            return False

    # ── Internal ───────────────────────────────────────────────────────────────

    def _splits_verified(self) -> bool:
        """Return True if all splits exist and checksums match manifest."""
        if not MANIFEST.exists():
            return False
        for p in (TRAIN_PATH, VAL_PATH, TEST_PATH):
            if not p.exists():
                return False
        try:
            manifest = json.loads(MANIFEST.read_text())
            for p in (TRAIN_PATH, VAL_PATH, TEST_PATH):
                recorded = manifest.get("checksums", {}).get(p.name)
                if recorded and _sha256(p) != recorded:
                    return False
        except Exception:
            return False
        return True

    def _write_manifest(self, train, val, test) -> None:
        manifest = {
            "seed":   self.seed,
            "scale":  self.scale,
            "rows":   {"train": len(train), "val": len(val), "test": len(test)},
            "checksums": {
                TRAIN_PATH.name: _sha256(TRAIN_PATH),
                VAL_PATH.name:   _sha256(VAL_PATH),
                TEST_PATH.name:  _sha256(TEST_PATH),
            },
        }
        MANIFEST.write_text(json.dumps(manifest, indent=2))
        logger.info("Manifest saved → %s", MANIFEST)

    def _load_existing(self) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        return (
            pd.read_parquet(TRAIN_PATH),
            pd.read_parquet(VAL_PATH),
            pd.read_parquet(TEST_PATH),
        )

    def _print_summary(self, train, val, test) -> None:
        from tabulate import tabulate
        print()
        print("── Dataset Splits ─────────────────────────────────────────────")
        for name, df in [("train", train), ("val", val), ("test", test)]:
            dist = df[self.target].value_counts().to_dict()
            print(f"   {name:5s}  {len(df):>8,} rows   {dist}")
        print()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    force  = "--force"  in sys.argv
    verify = "--verify" in sys.argv

    splitter = DatasetSplitter(force=force)
    if verify:
        splitter.verify()
    else:
        splitter.split()


if __name__ == "__main__":
    main()
