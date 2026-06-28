"""
src/data/clean.py
──────────────────
DataCleaner — normalises every raw CSV into a canonical three-column schema.

Canonical schema:
    url     (str)   — the URL or domain string
    label   (str)   — "phishing" | "legitimate"
    source  (str)   — original filename (for provenance tracing)

Responsibilities:
  • Auto-detect the URL column regardless of its original name
  • Auto-detect or infer the label column
  • Drop rows with null/empty URLs
  • Strip whitespace and lower-case URLs
  • Remove duplicate rows (by url)
  • Save cleaned files to datasets/processed/

Usage:
    from src.data.clean import DataCleaner

    cleaner = DataCleaner()
    cleaner.clean_all()
"""

import re
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from src.config import (
    PHISHING_DIR,
    LEGITIMATE_DIR,
    PROCESSED_DIR,
    URL_COLUMN_ALIASES,
    LABEL_COLUMN_ALIASES,
    SCHEMA_COLUMNS,
)
from src.utils.logger import logger


# ── Helpers ────────────────────────────────────────────────────────────────────

def _find_column(df: pd.DataFrame, aliases: list[str]) -> str | None:
    """Return the first column name in *df* that matches any alias (case-aware)."""
    for alias in aliases:
        if alias in df.columns:
            return alias
    # Fallback: case-insensitive substring match
    lower_cols = {c.lower(): c for c in df.columns}
    for alias in aliases:
        if alias.lower() in lower_cols:
            return lower_cols[alias.lower()]
    return None


def _infer_label(source_dir: Path, row_count: int) -> pd.Series:
    """
    If no label column exists, infer label from the parent directory name.
    phishing/ → "phishing",  legitimate/ → "legitimate".
    """
    tag = "phishing" if source_dir.name == "phishing" else "legitimate"
    return pd.Series([tag] * row_count)


def _is_valid_url(url: str) -> bool:
    """Lightweight URL validity check — no network requests."""
    if not isinstance(url, str) or not url.strip():
        return False
    # Must start with http/https OR look like a domain
    pattern = re.compile(
        r"^(https?://)"          # has scheme
        r"|"
        r"^[a-zA-Z0-9]"         # or starts with alphanumeric (bare domain)
        r"[a-zA-Z0-9\-\.]{1,}"  # followed by valid domain chars
        r"\.[a-zA-Z]{2,}",      # has a TLD
        re.IGNORECASE,
    )
    return bool(pattern.match(url.strip()))


# ── Main class ─────────────────────────────────────────────────────────────────

class DataCleaner:
    """
    Cleans and normalises all raw CSV datasets into a common schema,
    saving the results to datasets/processed/.
    """

    def __init__(self) -> None:
        self._raw_dirs: list[tuple[Path, str]] = [
            (PHISHING_DIR, "phishing"),
            (LEGITIMATE_DIR, "legitimate"),
        ]
        self.stats: list[dict] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def clean_all(self) -> list[Path]:
        """
        Clean every CSV in the raw directories and write to processed/.

        Returns
        -------
        list[Path]
            Paths of all cleaned output files.
        """
        output_paths: list[Path] = []

        all_files: list[tuple[Path, str]] = []
        for raw_dir, label_hint in self._raw_dirs:
            for csv_path in raw_dir.glob("*.csv"):
                all_files.append((csv_path, label_hint))

        if not all_files:
            logger.warning("No CSV files found in raw directories. Nothing to clean.")
            return []

        logger.info("Starting clean pass on %d file(s)…", len(all_files))

        for csv_path, label_hint in tqdm(all_files, desc="Cleaning", unit="file"):
            out = self._clean_single(csv_path, label_hint)
            if out is not None:
                output_paths.append(out)

        logger.info("Clean pass complete. %d file(s) written to '%s'.",
                    len(output_paths), PROCESSED_DIR)
        return output_paths

    # ── Internal ───────────────────────────────────────────────────────────────

    def _clean_single(self, csv_path: Path, label_hint: str) -> Path | None:
        """
        Clean one CSV file and write the result.

        Parameters
        ----------
        csv_path    : Path to the raw CSV.
        label_hint  : "phishing" | "legitimate" (used if no label column found).

        Returns
        -------
        Path | None
            Output path on success, None on failure.
        """
        logger.info("Cleaning: %s", csv_path.name)

        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not read '%s': %s", csv_path.name, exc)
            return None

        original_rows = len(df)

        # ── 0. Handle headerless rank+domain files (Tranco / Alexa / top-1m) ──
        # These have no header row; pandas reads rank as col[0], domain as col[1].
        # Heuristic: if the first column is entirely numeric, assume this format.
        if len(df.columns) >= 2 and pd.to_numeric(df[df.columns[0]], errors="coerce").notna().mean() > 0.95:
            logger.info(
                "'%s': Detected headerless rank+domain format — treating column '%s' as URL.",
                csv_path.name, df.columns[1],
            )
            df = df.rename(columns={df.columns[1]: "url", df.columns[0]: "rank"})
            # Inject a label column (legitimate — these are top-ranked domains)
            if "label" not in df.columns:
                df["label"] = "legitimate"

        # ── 1. Detect URL column ───────────────────────────────────────────────
        url_col = _find_column(df, URL_COLUMN_ALIASES)
        if url_col is None:
            logger.error(
                "'%s': No recognisable URL column found. "
                "Columns present: %s",
                csv_path.name, list(df.columns),
            )
            return None

        # ── 2. Detect or infer label column ───────────────────────────────────
        label_col = _find_column(df, LABEL_COLUMN_ALIASES)

        # ── 3. Build working frame ─────────────────────────────────────────────
        working = pd.DataFrame()
        working["url"] = df[url_col].astype(str).str.strip()

        if label_col:
            working["label"] = df[label_col].astype(str).str.strip().str.lower()
        else:
            logger.warning(
                "'%s': No label column found. Inferring label as '%s' "
                "based on source directory.",
                csv_path.name, label_hint,
            )
            working["label"] = label_hint

        working["source"] = csv_path.name

        # ── 4. Drop null / empty URLs ──────────────────────────────────────────
        before_null = len(working)
        working = working[working["url"].notna() & (working["url"] != "") & (working["url"] != "nan")]
        null_dropped = before_null - len(working)

        # ── 5. Remove duplicates (by url) ─────────────────────────────────────
        before_dup = len(working)
        working = working.drop_duplicates(subset=["url"])
        dup_dropped = before_dup - len(working)

        # ── 6. Normalise label values ─────────────────────────────────────────
        # Map common variants → canonical labels
        label_map = {
            # Phishing
            "phishing": "phishing", "bad": "phishing", "malicious": "phishing",
            "1": "phishing", "spam": "phishing",
            # Legitimate
            "legitimate": "legitimate", "good": "legitimate", "benign": "legitimate",
            "0": "legitimate", "clean": "legitimate",
            # Extended threat types (pass through as-is for multi-class support)
            "defacement": "defacement",
            "malware": "malware",
        }
        working["label"] = working["label"].map(label_map).fillna(working["label"])

        # ── 7. Ensure column order matches schema ──────────────────────────────
        working = working[SCHEMA_COLUMNS]

        # ── 8. Write output ────────────────────────────────────────────────────
        out_path = PROCESSED_DIR / f"cleaned_{csv_path.name}"
        working.to_csv(out_path, index=False)

        self.stats.append(
            {
                "file": csv_path.name,
                "original_rows": original_rows,
                "null_dropped": null_dropped,
                "dup_dropped": dup_dropped,
                "final_rows": len(working),
                "output": out_path.name,
            }
        )

        logger.info(
            "  ✓ %s | original=%d → final=%d (nulls=%d dups=%d)",
            csv_path.name, original_rows, len(working), null_dropped, dup_dropped,
        )

        return out_path
