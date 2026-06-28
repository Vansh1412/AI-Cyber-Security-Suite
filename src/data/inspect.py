"""
src/data/inspect.py
────────────────────
DatasetInspector — discovers and summarises all raw CSV datasets.

Responsibilities:
  • Glob PHISHING_DIR and LEGITIMATE_DIR for *.csv files
  • For each file, compute: rows, columns, missing values, duplicate rows
  • Print a GitHub-flavoured markdown table to stdout
  • Save a machine-readable summary to reports/dataset_summary.csv
  • Log every action via the centralised logger

Usage:
    from src.data.inspect import DatasetInspector

    inspector = DatasetInspector()
    inspector.discover()
    inspector.inspect()
"""

from pathlib import Path

import pandas as pd
from tabulate import tabulate

from src.config import PHISHING_DIR, LEGITIMATE_DIR, REPORT_DIR
from src.utils.logger import logger


class DatasetInspector:
    """Discovers and produces a structural summary of all raw CSV datasets."""

    def __init__(self) -> None:
        self.datasets: list[Path] = []

    # ── Discovery ──────────────────────────────────────────────────────────────

    def discover(self) -> None:
        """Glob both raw directories and collect all CSV paths."""
        phishing_files = list(PHISHING_DIR.glob("*.csv"))
        legitimate_files = list(LEGITIMATE_DIR.glob("*.csv"))

        self.datasets = phishing_files + legitimate_files

        logger.info(
            "Discovered %d dataset(s) — %d phishing, %d legitimate",
            len(self.datasets),
            len(phishing_files),
            len(legitimate_files),
        )

        if not self.datasets:
            logger.warning(
                "No CSV files found in '%s' or '%s'. "
                "Place your datasets there and re-run.",
                PHISHING_DIR,
                LEGITIMATE_DIR,
            )

    # ── Inspection ─────────────────────────────────────────────────────────────

    def inspect(self) -> pd.DataFrame:
        """
        Load every discovered CSV, compute quality metrics, print a summary
        table, and save reports/dataset_summary.csv.

        Returns
        -------
        pd.DataFrame
            The summary table (also saved to disk).
        """
        if not self.datasets:
            logger.warning("No datasets to inspect. Run discover() first.")
            return pd.DataFrame()

        summary: list[dict] = []

        for file in self.datasets:
            logger.info("Inspecting: %s", file.name)
            try:
                df = pd.read_csv(file, low_memory=False)

                rows = len(df)
                cols = len(df.columns)
                missing = int(df.isnull().sum().sum())
                duplicates = int(df.duplicated().sum())
                columns_preview = ", ".join(df.columns[:5].tolist())
                if len(df.columns) > 5:
                    columns_preview += f" … (+{len(df.columns) - 5} more)"

                source_tag = (
                    "phishing" if file.parent == PHISHING_DIR else "legitimate"
                )

                summary.append(
                    {
                        "Dataset": file.name,
                        "Source": source_tag,
                        "Rows": f"{rows:,}",
                        "Columns": cols,
                        "Missing": missing,
                        "Duplicates": duplicates,
                        "Column Preview": columns_preview,
                    }
                )

                logger.info(
                    "  ✓ %s | rows=%s cols=%d missing=%d dups=%d",
                    file.name, f"{rows:,}", cols, missing, duplicates,
                )

            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to read '%s': %s", file.name, exc)
                summary.append(
                    {
                        "Dataset": file.name,
                        "Source": "unknown",
                        "Rows": "ERROR",
                        "Columns": "ERROR",
                        "Missing": "ERROR",
                        "Duplicates": "ERROR",
                        "Column Preview": str(exc),
                    }
                )

        summary_df = pd.DataFrame(summary)

        # ── Console output ─────────────────────────────────────────────────────
        print()
        print(tabulate(summary_df, headers="keys", tablefmt="github", showindex=False))
        print()

        # ── Persist report ─────────────────────────────────────────────────────
        report_path = REPORT_DIR / "dataset_summary.csv"
        summary_df.to_csv(report_path, index=False)
        logger.info("Summary saved → %s", report_path)

        return summary_df
