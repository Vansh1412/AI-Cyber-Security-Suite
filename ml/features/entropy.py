"""
ml/features/entropy.py
───────────────────────
Shared entropy utilities used by statistical.py and other modules.

Kept as a separate module so the calculation is defined exactly once
and never drifts between sub-modules.
"""

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    H = -Σ p(c) * log2(p(c))

    A high-entropy string (e.g. 'x7fQ2kPm9') is characteristic of
    randomly generated phishing subdomains or obfuscated paths.

    Parameters
    ----------
    text : str
        Input string (URL, domain, path, etc.)

    Returns
    -------
    float
        Entropy in bits. Returns 0.0 for empty or single-character strings.
    """
    if not text or len(text) < 2:
        return 0.0

    freq = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def char_class_entropy(text: str, charset: str) -> float:
    """
    Calculate entropy restricted to characters within a given charset.

    Useful for computing entropy of only the alphabetic characters,
    or only the digits, in a URL.

    Parameters
    ----------
    text    : Input string.
    charset : String of characters to include in the calculation.

    Returns
    -------
    float
        Entropy of the filtered character subsequence.
    """
    filtered = "".join(c for c in text if c in charset)
    return shannon_entropy(filtered)
