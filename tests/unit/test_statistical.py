"""
tests/unit/test_statistical.py
────────────────────────────────
Unit tests for ml/features/statistical.py — StatisticalFeatures,
and ml/features/entropy.py — entropy utilities.
"""

import math
import urllib.parse

import pytest

from ml.features.entropy import shannon_entropy, char_class_entropy
from ml.features.statistical import StatisticalFeatures


def _extract(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    return StatisticalFeatures.extract(url, parsed)


# ── Entropy utility ────────────────────────────────────────────────────────────

def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_entropy_single_char():
    assert shannon_entropy("a") == 0.0


def test_entropy_uniform():
    # "ab" — two equally likely chars → entropy = 1 bit
    assert abs(shannon_entropy("ab") - 1.0) < 1e-9


def test_entropy_high_for_random():
    # A random-looking string has higher entropy than a word
    random_str = "x7fQ2kPm9nRzWaYb"
    word = "loginloginlogin"
    assert shannon_entropy(random_str) > shannon_entropy(word)


def test_entropy_non_negative():
    for s in ["http://example.com", "aaaaaa", "abc123!@#"]:
        assert shannon_entropy(s) >= 0.0


# ── StatisticalFeatures ────────────────────────────────────────────────────────

def test_feature_count():
    feats = _extract("https://www.example.com")
    assert len(feats) == 7


def test_all_features_are_float():
    feats = _extract("https://www.example.com/path?q=1")
    for k, v in feats.items():
        assert isinstance(v, float), f"'{k}' should be float, got {type(v)}"


def test_url_entropy_positive():
    feats = _extract("https://www.google.com")
    assert feats["url_entropy"] > 0.0


def test_domain_entropy_positive():
    feats = _extract("https://www.google.com")
    assert feats["domain_entropy"] > 0.0


def test_digit_ratio_all_digits():
    # URL with many digits → high digit ratio
    feats = _extract("http://123456789.com")
    assert feats["digit_ratio"] > 0.0


def test_digit_ratio_no_digits():
    feats = _extract("http://abc.def")
    # scheme has no digits, neither does domain
    assert feats["digit_ratio"] == pytest.approx(0.0, abs=0.05)


def test_all_ratios_in_range():
    """All ratio features must be in [0, 1]."""
    for url in [
        "https://www.google.com",
        "http://x7fq2kpm9.evil.xyz/login?id=1",
        "http://192.168.1.1/%20path",
        "http://xn--pypal-4ve.com/verify",
    ]:
        feats = _extract(url)
        for key in ("digit_ratio", "uppercase_ratio", "vowel_ratio",
                    "consonant_ratio", "symbol_ratio"):
            val = feats[key]
            assert 0.0 <= val <= 1.0, f"'{key}' = {val} out of [0,1] for URL: {url}"


def test_phishing_url_higher_entropy():
    """Random-looking phishing domain has higher entropy than legitimate."""
    phishing = _extract("http://x7fq2kPm9nRzWaYb.evil.xyz")
    legit    = _extract("https://www.google.com")
    assert phishing["url_entropy"] > legit["url_entropy"]


def test_symbol_ratio_url_with_many_symbols():
    feats = _extract("http://evil.com/%20%3F%41&a=1&b=2#hash!")
    assert feats["symbol_ratio"] > 0.0
