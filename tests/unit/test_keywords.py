"""
tests/unit/test_keywords.py
─────────────────────────────
Unit tests for ml/features/keywords.py — KeywordFeatures.
"""

import urllib.parse

import pytest

from ml.features.keywords import KeywordFeatures, PHISHING_KEYWORDS


def _extract(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    return KeywordFeatures.extract(url, parsed)


def test_feature_count():
    feats = _extract("http://example.com")
    # 15 kw_* features + keyword_count + has_brand_name = 17
    assert len(feats) == 17


def test_all_features_are_int():
    feats = _extract("http://example.com/login")
    for k, v in feats.items():
        assert isinstance(v, int), f"'{k}' should be int, got {type(v)}"


# ── Keyword detection ──────────────────────────────────────────────────────────

def test_kw_login_detected():
    assert _extract("http://evil.com/login")["kw_login"] == 1


def test_kw_login_not_detected():
    assert _extract("http://evil.com/home")["kw_login"] == 0


def test_kw_paypal_detected():
    assert _extract("http://paypal-login.evil.com")["kw_paypal"] == 1


def test_kw_verify_detected():
    assert _extract("http://evil.com/verify?token=abc")["kw_verify"] == 1


def test_kw_password_detected():
    assert _extract("http://evil.com/reset-password")["kw_password"] == 1


def test_kw_wallet_detected():
    assert _extract("http://crypto-wallet.evil.com")["kw_wallet"] == 1


# ── Case insensitivity ─────────────────────────────────────────────────────────

def test_case_insensitive_detection():
    assert _extract("http://evil.com/LOGIN")["kw_login"] == 1
    assert _extract("http://evil.com/Login")["kw_login"] == 1


# ── Keyword count ──────────────────────────────────────────────────────────────

def test_keyword_count_zero():
    assert _extract("http://www.google.com")["keyword_count"] == 0


def test_keyword_count_one():
    assert _extract("http://evil.com/login")["keyword_count"] == 1


def test_keyword_count_multiple():
    feats = _extract("http://evil.com/secure/login/verify/payment")
    assert feats["keyword_count"] >= 4  # secure, login, verify, payment


def test_keyword_count_matches_individual_flags():
    url = "http://evil.com/login/verify/payment"
    feats = _extract(url)
    manual_count = sum(feats[f"kw_{kw}"] for kw in PHISHING_KEYWORDS)
    assert feats["keyword_count"] == manual_count


# ── Brand detection ────────────────────────────────────────────────────────────

def test_has_brand_name_paypal():
    assert _extract("http://paypal.evil.com")["has_brand_name"] == 1


def test_has_brand_name_apple():
    assert _extract("http://apple-support.evil.com/update")["has_brand_name"] == 1


def test_has_brand_name_false():
    assert _extract("http://randomsite.io")["has_brand_name"] == 0


def test_has_brand_name_legitimate_paypal():
    # Even legitimate paypal.com should detect 'paypal' as brand
    assert _extract("https://www.paypal.com")["has_brand_name"] == 1


# ── All keywords covered ───────────────────────────────────────────────────────

@pytest.mark.parametrize("keyword", PHISHING_KEYWORDS)
def test_each_keyword_detected(keyword: str):
    url = f"http://evil.com/{keyword}"
    feats = _extract(url)
    assert feats[f"kw_{keyword}"] == 1, f"Keyword '{keyword}' not detected in '{url}'"
