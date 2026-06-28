"""
ml/features/statistical.py
───────────────────────────
StatisticalFeatures — 7 ratio and entropy features.

These capture the "randomness" and character-class composition of a URL,
which strongly distinguishes DGA-generated phishing domains from legitimate ones.

Key insight: phishing URLs tend to have high entropy (random-looking) and
unusual character distributions (many digits, low vowels).
"""

import string
from urllib.parse import ParseResult

from ml.features.entropy import shannon_entropy

_VOWELS     = set("aeiouAEIOU")
_CONSONANTS = set(string.ascii_letters) - _VOWELS
_SYMBOLS    = set(string.punctuation)


class StatisticalFeatures:
    """
    Extracts 7 statistical features from a URL string.

    Usage
    -----
    parsed = urllib.parse.urlparse(url)
    features = StatisticalFeatures.extract(url, parsed)
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
        dict[str, float]
            7 statistical feature key-value pairs.
        """
        hostname = parsed.hostname or ""
        total    = len(url) if url else 1          # avoid /0
        alpha    = sum(c.isalpha() for c in url)
        alpha    = alpha if alpha > 0 else 1       # avoid /0

        # ── Entropy ────────────────────────────────────────────────────────────
        url_entropy    = round(shannon_entropy(url),      6)
        domain_entropy = round(shannon_entropy(hostname), 6)

        # ── Character-class ratios (relative to total URL length) ──────────────
        digit_ratio  = round(sum(c.isdigit() for c in url) / total, 6)
        symbol_ratio = round(sum(c in _SYMBOLS for c in url) / total, 6)

        # Uppercase includes scheme/TLD but still a useful signal
        uppercase_ratio = round(sum(c.isupper() for c in url) / total, 6)

        # ── Vowel / consonant ratios (relative to alpha chars) ─────────────────
        vowel_ratio     = round(sum(c in _VOWELS     for c in url) / alpha, 6)
        consonant_ratio = round(sum(c in _CONSONANTS for c in url) / alpha, 6)

        return {
            "url_entropy":      url_entropy,
            "domain_entropy":   domain_entropy,
            "digit_ratio":      digit_ratio,
            "uppercase_ratio":  uppercase_ratio,
            "vowel_ratio":      vowel_ratio,
            "consonant_ratio":  consonant_ratio,
            "symbol_ratio":     symbol_ratio,
        }
