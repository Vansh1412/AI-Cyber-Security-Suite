"""
ml/features/catalog.py
───────────────────────
Generates reports/feature_catalog.csv — a human-readable registry
of all 63 features with their module, dtype, description, and SHAP
compatibility flag.

This catalog makes SHAP explanations far easier to interpret during
presentations and is required by the training report generator.

Usage
-----
    python -m ml.features.catalog
"""

from __future__ import annotations

import pandas as pd

from src.config import REPORT_DIR
from src.utils.logger import logger

# ── Feature registry ───────────────────────────────────────────────────────────
# Format: (feature_name, module, dtype, description, shap_ready)
FEATURE_REGISTRY: list[tuple[str, str, str, str, bool]] = [
    # ── Lexical (25) ──────────────────────────────────────────────────────────
    ("url_length",       "lexical", "int32",   "Total character count of the full URL", True),
    ("domain_length",    "lexical", "int32",   "Character count of the hostname", True),
    ("path_length",      "lexical", "int32",   "Character count of the URL path", True),
    ("query_length",     "lexical", "int32",   "Character count of the query string", True),
    ("fragment_length",  "lexical", "int32",   "Character count of the fragment (#anchor)", True),
    ("num_dots",         "lexical", "int32",   "Number of '.' characters in the URL", True),
    ("num_hyphens",      "lexical", "int32",   "Number of '-' characters in the URL", True),
    ("num_underscores",  "lexical", "int32",   "Number of '_' characters in the URL", True),
    ("num_digits",       "lexical", "int32",   "Number of digit characters (0–9) in the URL", True),
    ("num_slashes",      "lexical", "int32",   "Number of '/' characters in the URL", True),
    ("num_at",           "lexical", "int32",   "Number of '@' characters (credential injection signal)", True),
    ("num_equals",       "lexical", "int32",   "Number of '=' characters in the URL", True),
    ("num_question",     "lexical", "int32",   "Number of '?' characters in the URL", True),
    ("num_percent",      "lexical", "int32",   "Number of '%' characters (percent-encoding)", True),
    ("num_ampersand",    "lexical", "int32",   "Number of '&' characters in the URL", True),
    ("num_hash",         "lexical", "int32",   "Number of '#' characters in the URL", True),
    ("num_exclamation",  "lexical", "int32",   "Number of '!' characters in the URL", True),
    ("num_tilde",        "lexical", "int32",   "Number of '~' characters in the URL", True),
    ("num_comma",        "lexical", "int32",   "Number of ',' characters in the URL", True),
    ("num_plus",         "lexical", "int32",   "Number of '+' characters in the URL", True),
    ("num_asterisk",     "lexical", "int32",   "Number of '*' characters in the URL", True),
    ("https_flag",       "lexical", "int32",   "1 if scheme is HTTPS, 0 otherwise", True),
    ("has_ip",           "lexical", "int32",   "1 if hostname is an IPv4 or IPv6 address", True),
    ("has_port",         "lexical", "int32",   "1 if an explicit port number is present in the URL", True),
    ("url_depth",        "lexical", "int32",   "Number of path segments (depth of directory tree)", True),

    # ── Structural (14) ───────────────────────────────────────────────────────
    ("subdomain_count",       "structural", "int32",  "Number of subdomain labels before registered domain", True),
    ("tld",                   "structural", "object", "Top-level domain (e.g. com, ru, xyz) — string, encode before training", False),
    ("suspicious_tld",        "structural", "int32",  "1 if TLD is in known-suspicious list (xyz, tk, ru, etc.)", True),
    ("has_fragment",          "structural", "int32",  "1 if URL contains a #fragment", True),
    ("query_param_count",     "structural", "int32",  "Number of key=value query parameters", True),
    ("file_extension",        "structural", "object", "File extension from path (e.g. .php, .exe) — string, encode before training", False),
    ("has_suspicious_ext",    "structural", "int32",  "1 if extension is .exe, .zip, .php, .js, etc.", True),
    ("double_slash_redirect", "structural", "int32",  "1 if '//' appears in path (redirect obfuscation)", True),
    ("hex_char_count",        "structural", "int32",  "Count of %XX hex-encoded characters — CORRELATED with num_percent (drop before training)", False),
    ("punycode_domain",       "structural", "int32",  "1 if domain uses xn-- encoding (homograph attack indicator)", True),
    ("domain_has_digits",     "structural", "int32",  "1 if hostname contains digit characters", True),
    ("has_www",               "structural", "int32",  "1 if hostname begins with 'www.'", True),
    ("multi_subdomains",      "structural", "int32",  "1 if 3 or more subdomains are present", True),
    ("brand_in_subdomain",    "structural", "int32",  "1 if a brand name appears in subdomain (not registered domain)", True),

    # ── Statistical (7) ───────────────────────────────────────────────────────
    ("url_entropy",      "statistical", "float32", "Shannon entropy of the full URL string", True),
    ("domain_entropy",   "statistical", "float32", "Shannon entropy of the hostname only", True),
    ("digit_ratio",      "statistical", "float32", "Fraction of URL characters that are digits", True),
    ("uppercase_ratio",  "statistical", "float32", "Fraction of URL characters that are uppercase", True),
    ("vowel_ratio",      "statistical", "float32", "Fraction of alphabetic chars that are vowels", True),
    ("consonant_ratio",  "statistical", "float32", "Fraction of alphabetic chars that are consonants — CORRELATED with vowel_ratio (drop before training)", False),
    ("symbol_ratio",     "statistical", "float32", "Fraction of URL characters that are punctuation/symbols", True),

    # ── Keywords (17) ─────────────────────────────────────────────────────────
    ("kw_login",    "keywords", "int32", "1 if 'login' appears anywhere in the URL",    True),
    ("kw_verify",   "keywords", "int32", "1 if 'verify' appears anywhere in the URL",   True),
    ("kw_secure",   "keywords", "int32", "1 if 'secure' appears anywhere in the URL",   True),
    ("kw_update",   "keywords", "int32", "1 if 'update' appears anywhere in the URL",   True),
    ("kw_bank",     "keywords", "int32", "1 if 'bank' appears anywhere in the URL",     True),
    ("kw_paypal",   "keywords", "int32", "1 if 'paypal' appears anywhere in the URL",   True),
    ("kw_account",  "keywords", "int32", "1 if 'account' appears anywhere in the URL",  True),
    ("kw_signin",   "keywords", "int32", "1 if 'signin' appears anywhere in the URL",   True),
    ("kw_invoice",  "keywords", "int32", "1 if 'invoice' appears anywhere in the URL",  True),
    ("kw_payment",  "keywords", "int32", "1 if 'payment' appears anywhere in the URL",  True),
    ("kw_confirm",  "keywords", "int32", "1 if 'confirm' appears anywhere in the URL",  True),
    ("kw_password", "keywords", "int32", "1 if 'password' appears anywhere in the URL", True),
    ("kw_suspend",  "keywords", "int32", "1 if 'suspend' appears anywhere in the URL",  True),
    ("kw_validate", "keywords", "int32", "1 if 'validate' appears anywhere in the URL", True),
    ("kw_wallet",   "keywords", "int32", "1 if 'wallet' appears anywhere in the URL",   True),
    ("keyword_count",  "keywords", "int32", "Total number of phishing keywords found in URL", True),
    ("has_brand_name", "keywords", "int32", "1 if any major brand name appears in URL", True),
]


def build_catalog() -> pd.DataFrame:
    """Build the feature catalog DataFrame."""
    rows = []
    for name, module, dtype, description, shap_ready in FEATURE_REGISTRY:
        rows.append({
            "feature":     name,
            "module":      module,
            "dtype":       dtype,
            "shap_ready":  "yes" if shap_ready else "no",
            "description": description,
        })
    return pd.DataFrame(rows)


def save_catalog() -> None:
    """Generate and save reports/feature_catalog.csv."""
    df = build_catalog()
    path = REPORT_DIR / "feature_catalog.csv"
    df.to_csv(path, index=False)

    shap_count = (df["shap_ready"] == "yes").sum()
    logger.info("Feature catalog saved → %s (%d features, %d SHAP-ready)",
                path, len(df), shap_count)

    from tabulate import tabulate
    print()
    print(tabulate(df.head(10), headers="keys", tablefmt="github", showindex=False))
    if len(df) > 10:
        print(f"  … {len(df) - 10} more features in {path}")
    print()


if __name__ == "__main__":
    save_catalog()
