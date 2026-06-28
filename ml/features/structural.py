"""
ml/features/structural.py
──────────────────────────
StructuralFeatures — 15 features derived from URL component structure.

These capture the architecture of the URL rather than raw character
counts: subdomain depth, TLD risk, file extensions, redirect patterns,
and homograph/punycode attacks.
"""

import re
from pathlib import PurePosixPath
from urllib.parse import ParseResult

# ── Suspicious TLD list ────────────────────────────────────────────────────────
# Sources: URIBL, Spamhaus, OpenPhish threat intelligence lists
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "club", "online", "site", "info", "biz", "tk",
    "ga", "cf", "ml", "gq", "pw", "cc", "su", "ru", "cn", "ws",
    "click", "link", "win", "download", "loan", "work", "trade",
    "review", "stream", "gdn", "date", "faith", "science",
})

# ── Suspicious file extensions ─────────────────────────────────────────────────
SUSPICIOUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".zip", ".rar", ".tar", ".gz", ".7z",
    ".js",  ".vbs", ".bat", ".cmd", ".sh",
    ".php", ".asp", ".aspx", ".jsp",
    ".scr", ".pif", ".com", ".jar",
})

# ── Common brand names that appear in phishing subdomains ─────────────────────
BRAND_NAMES: frozenset[str] = frozenset({
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "bank", "secure", "signin", "login",
    "verify", "account", "support", "update", "service",
    "ebay", "wellsfargo", "chase", "citibank", "hsbc",
})

# ── Regex helpers ──────────────────────────────────────────────────────────────
_DOUBLE_SLASH_RE  = re.compile(r"(?<!:)//")
_HEX_ENCODE_RE    = re.compile(r"%[0-9A-Fa-f]{2}")
_PUNYCODE_RE      = re.compile(r"xn--", re.IGNORECASE)
_DOMAIN_DIGIT_RE  = re.compile(r"\d")


def _extract_tld(hostname: str) -> str:
    """Return the TLD (last dot-separated segment) from a hostname."""
    if not hostname:
        return ""
    parts = hostname.rstrip(".").split(".")
    return parts[-1].lower() if parts else ""


def _extract_registered_domain_parts(hostname: str) -> tuple[str, list[str]]:
    """
    Naively split hostname into (registered_domain, subdomains).

    For 'login.evil.paypal.com' → registered='paypal.com', subs=['login','evil']
    This is a heuristic (no PSL lookup) sufficient for feature engineering.
    """
    if not hostname:
        return "", []
    parts = hostname.rstrip(".").split(".")
    if len(parts) <= 2:
        return hostname, []
    # Treat last two parts as registered domain
    registered = ".".join(parts[-2:])
    subdomains  = parts[:-2]
    return registered, subdomains


class StructuralFeatures:
    """
    Extracts 15 structural features from a parsed URL.

    Usage
    -----
    parsed = urllib.parse.urlparse(url)
    features = StructuralFeatures.extract(url, parsed)
    """

    @staticmethod
    def extract(url: str, parsed: ParseResult) -> dict:
        """
        Parameters
        ----------
        url    : Raw URL string.
        parsed : urllib.parse.urlparse(url) result.

        Returns
        -------
        dict[str, int | str]
            15 structural feature key-value pairs.
        """
        hostname = parsed.hostname or ""
        path     = parsed.path     or ""
        query    = parsed.query    or ""

        registered_domain, subdomains = _extract_registered_domain_parts(hostname)
        tld = _extract_tld(hostname)

        # ── TLD features ───────────────────────────────────────────────────────
        suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

        # ── Subdomain features ─────────────────────────────────────────────────
        subdomain_count  = len(subdomains)
        multi_subdomains = 1 if subdomain_count >= 3 else 0

        # Brand name in subdomain (not in registered domain → impersonation)
        subdomain_str = ".".join(subdomains).lower()
        brand_in_subdomain = 1 if any(b in subdomain_str for b in BRAND_NAMES) else 0

        # ── Port / fragment ────────────────────────────────────────────────────
        has_fragment = 1 if parsed.fragment else 0

        # ── Query parameters ───────────────────────────────────────────────────
        query_param_count = len(query.split("&")) if query else 0

        # ── File extension ─────────────────────────────────────────────────────
        try:
            suffix = PurePosixPath(path).suffix.lower()
        except Exception:
            suffix = ""
        file_extension    = suffix if suffix else "none"
        has_suspicious_ext = 1 if suffix in SUSPICIOUS_EXTENSIONS else 0

        # ── Path redirect / encoding ───────────────────────────────────────────
        double_slash_redirect = 1 if _DOUBLE_SLASH_RE.search(path) else 0
        hex_char_count        = len(_HEX_ENCODE_RE.findall(url))

        # ── Domain characteristics ─────────────────────────────────────────────
        punycode_domain   = 1 if _PUNYCODE_RE.search(hostname) else 0
        domain_has_digits = 1 if _DOMAIN_DIGIT_RE.search(hostname) else 0
        has_www           = 1 if hostname.startswith("www.") else 0

        return {
            "subdomain_count":       subdomain_count,
            "tld":                   tld,
            "suspicious_tld":        suspicious_tld,
            "has_fragment":          has_fragment,
            "query_param_count":     query_param_count,
            "file_extension":        file_extension,
            "has_suspicious_ext":    has_suspicious_ext,
            "double_slash_redirect": double_slash_redirect,
            "hex_char_count":        hex_char_count,
            "punycode_domain":        punycode_domain,
            "domain_has_digits":     domain_has_digits,
            "has_www":               has_www,
            "multi_subdomains":      multi_subdomains,
            "brand_in_subdomain":    brand_in_subdomain,
        }
