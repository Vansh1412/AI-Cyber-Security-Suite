"""
ml/features/extractor.py
─────────────────────────
FeatureExtractor — the single public interface for URL feature extraction.

Design
------
All consumers (batch pipeline, FastAPI endpoint, notebook EDA, unit tests)
use exactly one interface:

    extractor = FeatureExtractor()
    features  = extractor.extract(url)   # → dict[str, int | float | str]

Internally delegates to the four focused sub-modules:
    LexicalFeatures    → 25 features
    StructuralFeatures → 15 features
    StatisticalFeatures →  7 features
    KeywordFeatures    → 17 features
                         ──────────
    Total              → 64 features

URL Normalisation
-----------------
Many URLs in phishing datasets are bare domains or missing a scheme.
The extractor pre-processes the URL before parsing so that all
feature modules receive a consistent ParseResult:

    "paypal-login.evil.com"    → "http://paypal-login.evil.com"
    "http://evil.com/path"     → unchanged
    "//evil.com/path"          → "http://evil.com/path"

Error Handling
--------------
If extraction fails for any URL, a zero-vector of the correct shape
is returned (never raises). This keeps the batch pipeline from
crashing on malformed rows.
"""

from __future__ import annotations

import urllib.parse
from functools import lru_cache
from urllib.parse import ParseResult, urlparse

from ml.features.entropy    import shannon_entropy   # noqa: F401 (re-export convenience)
from ml.features.keywords   import KeywordFeatures
from ml.features.lexical    import LexicalFeatures
from ml.features.statistical import StatisticalFeatures
from ml.features.structural import StructuralFeatures

# ── Feature name registry (used by pipeline for column ordering) ───────────────
FEATURE_NAMES: list[str] = (
    list(LexicalFeatures.extract.__doc__ and [] or [])  # populated below
)


def _normalise_url(url: str) -> str:
    """
    Ensure the URL has a scheme so urlparse produces sensible components.

    Handles:
      - Bare domains:   'evil.com'          → 'http://evil.com'
      - Protocol-rel:   '//evil.com/path'   → 'http://evil.com/path'
      - Already valid:  'https://...'       → unchanged
    """
    url = url.strip()
    if not url:
        return "http://invalid"
    if url.startswith("//"):
        return "http:" + url
    if "://" not in url:
        return "http://" + url
    return url


def _zero_features() -> dict:
    """Return a zero-vector dict with all 64 feature names."""
    extractor = FeatureExtractor.__new__(FeatureExtractor)
    try:
        return extractor.extract("http://example.com")
    except Exception:
        return {}


class FeatureExtractor:
    """
    Unified feature extraction interface.

    All sub-module instances are created once and reused across calls
    (stateless modules, so this is safe and avoids repeated object
    construction in batch loops).
    """

    def __init__(self) -> None:
        # Sub-modules are stateless; kept as references for clarity
        self._lexical    = LexicalFeatures
        self._structural = StructuralFeatures
        self._statistical = StatisticalFeatures
        self._keywords   = KeywordFeatures

    # ── Public API ─────────────────────────────────────────────────────────────

    @lru_cache(maxsize=10_000)
    def extract(self, url: str) -> dict:
        """
        Extract all 64 features from a single URL string.

        Parameters
        ----------
        url : str
            Raw URL (with or without scheme; bare domains accepted).

        Returns
        -------
        dict[str, int | float | str]
            64 feature key-value pairs. Never raises — returns a zero-vector
            on any parsing or extraction failure.
        """
        try:
            normalised = _normalise_url(url)
            parsed: ParseResult = urlparse(normalised)

            features: dict = {}
            features.update(self._lexical.extract(normalised, parsed))
            features.update(self._structural.extract(normalised, parsed))
            features.update(self._statistical.extract(normalised, parsed))
            features.update(self._keywords.extract(normalised, parsed))

            return features

        except Exception:  # noqa: BLE001
            # Return zero-vector so batch processing never crashes
            return self._zero_vector()

    def feature_names(self) -> list[str]:
        """Return the ordered list of all feature names."""
        return list(self.extract("http://example.com").keys())

    # ── Internal ───────────────────────────────────────────────────────────────

    def _zero_vector(self) -> dict:
        """Return a zero/empty value for every feature."""
        sample = {}
        try:
            p = urlparse("http://example.com")
            sample.update(self._lexical.extract("http://example.com", p))
            sample.update(self._structural.extract("http://example.com", p))
            sample.update(self._statistical.extract("http://example.com", p))
            sample.update(self._keywords.extract("http://example.com", p))
        except Exception:  # noqa: BLE001
            pass
        # Zero-out all numeric values; keep string defaults
        return {
            k: (0 if isinstance(v, (int, float)) else ("none" if isinstance(v, str) else v))
            for k, v in sample.items()
        }
