"""
src/data/validate.py
─────────────────────
DataValidator — validates cleaned datasets before they enter the ML pipeline.

Checks performed:
  1. Schema validation   — required columns present (url, label, source)
  2. URL format check    — uses the `validators` library
  3. Label integrity     — only "phishing" / "legitimate" values allowed
  4. Null check          — no nulls in any required column
  5. Duplicate check     — no duplicate urls

Outputs:
  • Console summary table
  • reports/validation_report.csv

Usage:
    from src.data.validate import DataValidator

    validator = DataValidator()
    validator.validate_all()
"""

from pathlib import Path

import pandas as pd
import validators
from tabulate import tabulate

from src.config import PROCESSED_DIR, REPORT_DIR, SCHEMA_COLUMNS
from src.utils.logger import logger

VALID_LABELS = {"phishing", "legitimate", "defacement", "malware"}


class DataValidator:
    """Validates all cleaned CSV files in datasets/processed/."""

    def __init__(self) -> None:
        self.results: list[dict] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def validate_all(self) -> pd.DataFrame:
        """
        Validate every cleaned CSV in PROCESSED_DIR.

        Returns
        -------
        pd.DataFrame
            Validation results table (also saved to reports/).
        """
        files = [
            f for f in PROCESSED_DIR.glob("*.csv")
            if f.name != "merged_dataset.csv"
        ]

        if not files:
            logger.warning(
                "No cleaned CSV files found in '%s'. Run DataCleaner first.",
                PROCESSED_DIR,
            )
            return pd.DataFrame()

        logger.info("Starting validation on %d file(s)…", len(files))

        for csv_path in files:
            self._validate_single(csv_path)

        results_df = pd.DataFrame(self.results)

        # ── Console output ─────────────────────────────────────────────────────
        print()
        print(tabulate(results_df, headers="keys", tablefmt="github", showindex=False))
        print()

        # ── Save report ────────────────────────────────────────────────────────
        report_path = REPORT_DIR / "validation_report.csv"
        results_df.to_csv(report_path, index=False)
        logger.info("Validation report saved → %s", report_path)

        passed = results_df[results_df["status"] == "PASS"]
        failed = results_df[results_df["status"] == "FAIL"]
        logger.info("Validation complete: %d PASS, %d FAIL", len(passed), len(failed))

        return results_df

    # ── Internal ───────────────────────────────────────────────────────────────

    def _validate_single(self, csv_path: Path) -> None:
        logger.info("Validating: %s", csv_path.name)
        issues: list[str] = []

        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as exc:  # noqa: BLE001
            logger.error("Cannot read '%s': %s", csv_path.name, exc)
            self.results.append(
                {"file": csv_path.name, "rows": 0,
                 "status": "FAIL", "issues": str(exc)}
            )
            return

        # ── 1. Schema check ────────────────────────────────────────────────────
        missing_cols = [c for c in SCHEMA_COLUMNS if c not in df.columns]
        if missing_cols:
            issues.append(f"Missing columns: {missing_cols}")

        if missing_cols:
            # Cannot proceed without required columns
            self.results.append(
                {"file": csv_path.name, "rows": len(df),
                 "status": "FAIL", "issues": "; ".join(issues)}
            )
            return

        # ── 2. Null check ──────────────────────────────────────────────────────
        null_counts = df[SCHEMA_COLUMNS].isnull().sum()
        if null_counts.any():
            for col, cnt in null_counts.items():
                if cnt > 0:
                    issues.append(f"{cnt} nulls in '{col}'")

        # ── 3. Label integrity ─────────────────────────────────────────────────
        bad_labels = df[~df["label"].isin(VALID_LABELS)]["label"].unique()
        if len(bad_labels) > 0:
            issues.append(f"Unknown labels: {list(bad_labels[:5])}")

        # ── 4. URL format check (sample up to 2 000 rows for speed) ───────────
        sample = df["url"].dropna().astype(str)
        if len(sample) > 2000:
            sample = sample.sample(2000, random_state=42)

        invalid_urls = sample[
            sample.apply(
                lambda u: not (
                    validators.url(u)
                    or validators.domain(u.lstrip("www.").split("/")[0])
                )
            )
        ]
        if len(invalid_urls) > 0:
            pct = len(invalid_urls) / len(sample) * 100
            issues.append(
                f"{len(invalid_urls)} invalid URLs in sample ({pct:.1f}%)"
            )

        # ── 5. Duplicate check ─────────────────────────────────────────────────
        dup_count = df.duplicated(subset=["url"]).sum()
        if dup_count > 0:
            issues.append(f"{dup_count} duplicate URLs")

        status = "PASS" if not issues else "FAIL"
        self.results.append(
            {
                "file": csv_path.name,
                "rows": f"{len(df):,}",
                "status": status,
                "issues": "; ".join(issues) if issues else "—",
            }
        )

        if status == "PASS":
            logger.info("  ✓ %s — PASS", csv_path.name)
        else:
            logger.warning("  ✗ %s — FAIL: %s", csv_path.name, "; ".join(issues))
