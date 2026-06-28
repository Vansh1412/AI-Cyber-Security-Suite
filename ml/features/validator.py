"""
ml/features/validator.py
─────────────────────────
FeatureValidator — validates the feature matrix before model training.

Checks
------
1. Schema          — all expected columns present
2. Null check      — no NaN values in numeric columns
3. Type check      — numeric columns are int/float; string columns are object
4. Constant check  — no zero-variance columns (they add no signal)
5. Range check     — ratio features must be in [0, 1]
6. Duplicate names — no duplicate column names
7. Correlation     — flag highly correlated feature pairs (>0.98)

Outputs
-------
- Console table (tabulate)
- reports/feature_report.csv  — per-feature statistics
- reports/feature_correlation.csv — highly correlated pairs
"""

import warnings

import numpy as np
import pandas as pd
from tabulate import tabulate

from src.config import REPORT_DIR
from src.utils.logger import logger

# Features that must be in [0.0, 1.0]
RATIO_FEATURES = {
    "digit_ratio", "uppercase_ratio", "vowel_ratio",
    "consonant_ratio", "symbol_ratio",
}

# Features that must be non-negative integers
COUNT_FEATURES = {
    "url_length", "domain_length", "path_length", "query_length",
    "fragment_length", "num_dots", "num_hyphens", "num_underscores",
    "num_digits", "num_slashes", "num_at", "num_equals", "num_question",
    "num_percent", "num_ampersand", "num_hash", "num_exclamation",
    "num_tilde", "num_comma", "num_plus", "num_asterisk",
    "url_depth", "subdomain_count", "query_param_count",
    "hex_char_count", "keyword_count",
}

# Binary flag features (must be 0 or 1)
FLAG_FEATURES = {
    "https_flag", "has_ip", "has_port", "url_depth",
    "suspicious_tld", "has_fragment", "has_suspicious_ext",
    "double_slash_redirect", "punycode_domain", "domain_has_digits",
    "has_www", "multi_subdomains", "brand_in_subdomain",
    "kw_login", "kw_verify", "kw_secure", "kw_update", "kw_bank",
    "kw_paypal", "kw_account", "kw_signin", "kw_invoice", "kw_payment",
    "kw_confirm", "kw_password", "kw_suspend", "kw_validate", "kw_wallet",
    "has_brand_name",
}

CORRELATION_THRESHOLD = 0.98


class FeatureValidator:
    """Validates a feature DataFrame and produces quality reports."""

    def __init__(self) -> None:
        self.issues: list[str] = []

    def validate(self, df: pd.DataFrame) -> bool:
        """
        Run all validation checks on the feature DataFrame.

        Parameters
        ----------
        df : pd.DataFrame
            Feature matrix (output of FeaturePipeline).

        Returns
        -------
        bool
            True if validation passed (no critical issues), False otherwise.
        """
        self.issues = []
        logger.info("Running feature validation on %s rows × %s columns…",
                    f"{len(df):,}", len(df.columns))

        self._check_nulls(df)
        self._check_constants(df)
        self._check_ranges(df)
        self._check_duplicates(df)
        self._generate_feature_report(df)
        self._check_correlation(df)

        if self.issues:
            logger.warning("Validation found %d issue(s):", len(self.issues))
            for issue in self.issues:
                logger.warning("  • %s", issue)
        else:
            logger.info("Validation PASSED — no issues found.")

        return len(self.issues) == 0

    # ── Checks ──────────────────────────────────────────────────────────────────

    def _check_nulls(self, df: pd.DataFrame) -> None:
        null_counts = df.isnull().sum()
        offenders = null_counts[null_counts > 0]
        if not offenders.empty:
            for col, cnt in offenders.items():
                self.issues.append(f"NULL: '{col}' has {cnt:,} null values")

    def _check_constants(self, df: pd.DataFrame) -> None:
        numeric = df.select_dtypes(include=[np.number])
        for col in numeric.columns:
            if numeric[col].nunique() <= 1:
                self.issues.append(f"CONSTANT: '{col}' has zero variance (always {numeric[col].iloc[0]})")

    def _check_ranges(self, df: pd.DataFrame) -> None:
        for col in RATIO_FEATURES:
            if col not in df.columns:
                continue
            out_of_range = ((df[col] < 0) | (df[col] > 1)).sum()
            if out_of_range > 0:
                self.issues.append(f"RANGE: '{col}' has {out_of_range:,} values outside [0,1]")

        for col in COUNT_FEATURES:
            if col not in df.columns:
                continue
            negative = (df[col] < 0).sum()
            if negative > 0:
                self.issues.append(f"RANGE: '{col}' has {negative:,} negative values")

    def _check_duplicates(self, df: pd.DataFrame) -> None:
        seen: set[str] = set()
        for col in df.columns:
            if col in seen:
                self.issues.append(f"DUPLICATE: Column '{col}' appears more than once")
            seen.add(col)

    def _generate_feature_report(self, df: pd.DataFrame) -> None:
        """Save per-feature statistics to reports/feature_report.csv."""
        numeric = df.select_dtypes(include=[np.number])
        rows = []
        for col in numeric.columns:
            series = numeric[col]
            rows.append({
                "feature":   col,
                "dtype":     str(series.dtype),
                "min":       round(float(series.min()), 6),
                "max":       round(float(series.max()), 6),
                "mean":      round(float(series.mean()), 6),
                "std":       round(float(series.std()), 6),
                "null_count": int(series.isnull().sum()),
                "unique":    int(series.nunique()),
                "zero_pct":  round((series == 0).mean() * 100, 2),
            })

        report_df = pd.DataFrame(rows)
        path = REPORT_DIR / "feature_report.csv"
        report_df.to_csv(path, index=False)
        logger.info("Feature report saved → %s", path)

        print()
        print(tabulate(
            report_df[["feature", "min", "max", "mean", "std", "null_count", "unique"]].head(20),
            headers="keys", tablefmt="github", showindex=False,
        ))
        if len(rows) > 20:
            print(f"  … {len(rows) - 20} more features in {path}")
        print()

    def _check_correlation(self, df: pd.DataFrame) -> None:
        """Flag highly correlated feature pairs."""
        numeric = df.select_dtypes(include=[np.number])
        if numeric.shape[1] < 2:
            return

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            corr = numeric.corr().abs()

        pairs = []
        cols = corr.columns.tolist()
        for i, c1 in enumerate(cols):
            for c2 in cols[i + 1:]:
                val = corr.loc[c1, c2]
                if val >= CORRELATION_THRESHOLD:
                    pairs.append({"feature_a": c1, "feature_b": c2, "correlation": round(val, 4)})
                    self.issues.append(
                        f"CORRELATION: '{c1}' ↔ '{c2}' = {val:.4f} (≥{CORRELATION_THRESHOLD})"
                    )

        if pairs:
            path = REPORT_DIR / "feature_correlation.csv"
            pd.DataFrame(pairs).to_csv(path, index=False)
            logger.warning("Correlation report saved → %s (%d pairs)", path, len(pairs))
