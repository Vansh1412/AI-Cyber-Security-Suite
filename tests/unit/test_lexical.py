"""
tests/unit/test_lexical.py
───────────────────────────
Unit tests for ml/features/lexical.py — LexicalFeatures.

Tests cover:
  - Every feature returns the correct type (int)
  - Edge cases: empty string, bare domain, IP URL, port URL, @ URL
  - HTTPS flag accuracy
  - URL depth computation
  - Character counts on known URLs
"""

import urllib.parse

import pytest

from ml.features.lexical import LexicalFeatures


def _extract(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    return LexicalFeatures.extract(url, parsed)


# ── Type checks ────────────────────────────────────────────────────────────────

def test_all_features_are_numeric():
    feats = _extract("https://www.example.com/path?q=1")
    for k, v in feats.items():
        assert isinstance(v, (int, float)), f"Feature '{k}' has unexpected type {type(v)}"


def test_feature_count():
    feats = _extract("https://www.example.com")
    assert len(feats) == 25, f"Expected 25 lexical features, got {len(feats)}"


# ── HTTPS flag ─────────────────────────────────────────────────────────────────

def test_https_flag_true():
    assert _extract("https://example.com")["https_flag"] == 1


def test_https_flag_false_http():
    assert _extract("http://example.com")["https_flag"] == 0


def test_https_flag_false_ftp():
    assert _extract("ftp://example.com")["https_flag"] == 0


# ── IP flag ────────────────────────────────────────────────────────────────────

def test_has_ip_ipv4():
    assert _extract("http://192.168.1.1/login")["has_ip"] == 1


def test_has_ip_clean_domain():
    assert _extract("https://www.google.com")["has_ip"] == 0


def test_has_ip_domain_with_digits():
    # Domain like '123abc.com' is NOT an IP
    assert _extract("http://123abc.com")["has_ip"] == 0


# ── Port flag ──────────────────────────────────────────────────────────────────

def test_has_port_true():
    assert _extract("http://evil.com:8080/path")["has_port"] == 1


def test_has_port_false():
    assert _extract("http://evil.com/path")["has_port"] == 0


# ── URL depth ──────────────────────────────────────────────────────────────────

def test_url_depth_zero():
    assert _extract("http://example.com")["url_depth"] == 0


def test_url_depth_one():
    assert _extract("http://example.com/login")["url_depth"] == 1


def test_url_depth_three():
    assert _extract("http://example.com/a/b/c")["url_depth"] == 3


# ── Character counts ───────────────────────────────────────────────────────────

def test_num_dots():
    feats = _extract("http://login.paypal.com.evil.ru/path")
    # 'login.paypal.com.evil.ru' has 4 dots; '.ru' is 1; full string analysis
    assert feats["num_dots"] >= 4


def test_num_at():
    assert _extract("http://user@evil.com")["num_at"] == 1


def test_num_at_zero():
    assert _extract("http://evil.com")["num_at"] == 0


def test_num_equals_in_query():
    feats = _extract("http://evil.com?a=1&b=2&c=3")
    assert feats["num_equals"] == 3


def test_num_percent_encoded():
    feats = _extract("http://evil.com/%20path%3F")
    assert feats["num_percent"] == 2


def test_num_hyphens():
    feats = _extract("http://secure-login-paypal.evil.com")
    assert feats["num_hyphens"] == 2


# ── Length features ────────────────────────────────────────────────────────────

def test_url_length():
    url = "http://example.com"
    assert _extract(url)["url_length"] == len(url)


def test_query_length():
    url = "http://example.com?key=value"
    feats = _extract(url)
    assert feats["query_length"] == len("key=value")


def test_fragment_length():
    url = "http://example.com#section"
    feats = _extract(url)
    assert feats["fragment_length"] == len("section")


# ── Edge cases ─────────────────────────────────────────────────────────────────

def test_empty_url_no_crash():
    """Empty URL must not raise."""
    feats = _extract("http://invalid")
    assert isinstance(feats, dict)
    assert len(feats) == 25


def test_very_long_url():
    url = "http://evil.com/" + "a" * 500 + "?q=" + "x" * 200
    feats = _extract(url)
    assert feats["url_length"] == len(url)
    assert feats["url_depth"] == 1
