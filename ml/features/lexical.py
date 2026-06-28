"""
ml/features/lexical.py
───────────────────────
LexicalFeatures — 25 features extracted purely from URL characters.

No network calls. No external dependencies beyond the standard library.
All features operate on the raw URL string and the pre-parsed
urllib.parse.ParseResult object.

Feature naming follows SHAP-friendly conventions:
    num_*   → character counts
    *_flag  → binary 0/1
    *_length → character lengths
"""

import re
import socket
from urllib.parse import ParseResult

# ── IPv4 / IPv6 detection ──────────────────────────────────────────────────────
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
_IPV4_WITH_PORT_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
)


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(":")[0] if ":" in hostname and not hostname.startswith("[") else hostname
    host = host.strip("[]")  # IPv6 bracket notation
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (socket.error, OSError):
            pass
    return False


class LexicalFeatures:
    """
    Extracts 25 lexical features from a URL string.

    Usage
    -----
    parsed = urllib.parse.urlparse(url)
    features = LexicalFeatures.extract(url, parsed)
    """

    @staticmethod
    def extract(url: str, parsed: ParseResult) -> dict:
        """
        Parameters
        ----------
        url    : Raw URL string (may be bare domain without scheme).
        parsed : urllib.parse.urlparse(url) result.

        Returns
        -------
        dict[str, int | float]
            25 lexical feature key-value pairs.
        """
        hostname = parsed.hostname or ""
        path     = parsed.path     or ""
        query    = parsed.query    or ""
        fragment = parsed.fragment or ""
        scheme   = parsed.scheme   or ""

        # ── Lengths ────────────────────────────────────────────────────────────
        url_length      = len(url)
        domain_length   = len(hostname)
        path_length     = len(path)
        query_length    = len(query)
        fragment_length = len(fragment)

        # ── Character counts (full URL) ────────────────────────────────────────
        num_dots        = url.count(".")
        num_hyphens     = url.count("-")
        num_underscores = url.count("_")
        num_digits      = sum(c.isdigit() for c in url)
        num_slashes     = url.count("/")
        num_at          = url.count("@")
        num_equals      = url.count("=")
        num_question    = url.count("?")
        num_percent     = url.count("%")
        num_ampersand   = url.count("&")
        num_hash        = url.count("#")
        num_exclamation = url.count("!")
        num_tilde       = url.count("~")
        num_comma       = url.count(",")
        num_plus        = url.count("+")
        num_asterisk    = url.count("*")

        # ── Binary flags ───────────────────────────────────────────────────────
        https_flag = 1 if scheme.lower() == "https" else 0
        has_ip     = 1 if _is_ip_address(hostname) else 0
        has_port   = 1 if parsed.port is not None else 0

        # ── URL depth (number of path segments) ───────────────────────────────
        url_depth = len([s for s in path.split("/") if s]) if path else 0

        return {
            "url_length":       url_length,
            "domain_length":    domain_length,
            "path_length":      path_length,
            "query_length":     query_length,
            "fragment_length":  fragment_length,
            "num_dots":         num_dots,
            "num_hyphens":      num_hyphens,
            "num_underscores":  num_underscores,
            "num_digits":       num_digits,
            "num_slashes":      num_slashes,
            "num_at":           num_at,
            "num_equals":       num_equals,
            "num_question":     num_question,
            "num_percent":      num_percent,
            "num_ampersand":    num_ampersand,
            "num_hash":         num_hash,
            "num_exclamation":  num_exclamation,
            "num_tilde":        num_tilde,
            "num_comma":        num_comma,
            "num_plus":         num_plus,
            "num_asterisk":     num_asterisk,
            "https_flag":       https_flag,
            "has_ip":           has_ip,
            "has_port":         has_port,
            "url_depth":        url_depth,
        }
