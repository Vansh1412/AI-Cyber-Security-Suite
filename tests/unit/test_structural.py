"""
tests/unit/test_structural.py
──────────────────────────────
Unit tests for ml/features/structural.py — StructuralFeatures.
"""

import urllib.parse

import pytest

from ml.features.structural import StructuralFeatures


def _extract(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    return StructuralFeatures.extract(url, parsed)


def test_feature_count():
    feats = _extract("https://www.example.com")
    assert len(feats) == 14  # has_port moved to lexical.py


def test_all_features_correct_types():
    feats = _extract("https://www.example.com/path")
    for k, v in feats.items():
        assert isinstance(v, (int, str)), f"'{k}' has unexpected type {type(v)}"


# ── TLD ────────────────────────────────────────────────────────────────────────

def test_tld_com():
    assert _extract("http://example.com")["tld"] == "com"


def test_tld_ru():
    assert _extract("http://example.ru")["tld"] == "ru"


def test_suspicious_tld_xyz():
    assert _extract("http://evil.xyz")["suspicious_tld"] == 1


def test_suspicious_tld_tk():
    assert _extract("http://free.tk")["suspicious_tld"] == 1


def test_legitimate_tld_com():
    assert _extract("http://google.com")["suspicious_tld"] == 0


def test_legitimate_tld_org():
    assert _extract("http://wikipedia.org")["suspicious_tld"] == 0


# ── Subdomains ─────────────────────────────────────────────────────────────────

def test_subdomain_count_none():
    feats = _extract("http://example.com")
    assert feats["subdomain_count"] == 0


def test_subdomain_count_www():
    feats = _extract("http://www.example.com")
    assert feats["subdomain_count"] == 1


def test_subdomain_count_multi():
    feats = _extract("http://a.b.c.example.com")
    assert feats["subdomain_count"] == 3


def test_multi_subdomains_flag():
    feats = _extract("http://a.b.c.example.com")
    assert feats["multi_subdomains"] == 1


def test_multi_subdomains_flag_false():
    feats = _extract("http://www.example.com")
    assert feats["multi_subdomains"] == 0


# ── Brand impersonation ────────────────────────────────────────────────────────

def test_brand_in_subdomain_paypal():
    feats = _extract("http://paypal.evil.com")
    assert feats["brand_in_subdomain"] == 1


def test_brand_in_subdomain_false():
    feats = _extract("http://www.paypal.com")
    assert feats["brand_in_subdomain"] == 0  # paypal IS the domain, not subdomain


# ── Fragment ────────────────────────────────────────────────────

def test_has_fragment_true():
    assert _extract("http://example.com/page#section")["has_fragment"] == 1


def test_has_fragment_false():
    assert _extract("http://example.com/page")["has_fragment"] == 0


# ── Query parameters ───────────────────────────────────────────────────────────

def test_query_param_count_zero():
    assert _extract("http://example.com/path")["query_param_count"] == 0


def test_query_param_count_three():
    assert _extract("http://example.com?a=1&b=2&c=3")["query_param_count"] == 3


# ── File extension ─────────────────────────────────────────────────────────────

def test_file_extension_php():
    assert _extract("http://evil.com/login.php")["file_extension"] == ".php"


def test_file_extension_none():
    assert _extract("http://evil.com/path")["file_extension"] == "none"


def test_has_suspicious_ext_exe():
    assert _extract("http://evil.com/payload.exe")["has_suspicious_ext"] == 1


def test_has_suspicious_ext_html_false():
    assert _extract("http://example.com/index.html")["has_suspicious_ext"] == 0


# ── Punycode ───────────────────────────────────────────────────────────────────

def test_punycode_domain():
    assert _extract("http://xn--pypal-4ve.com")["punycode_domain"] == 1


def test_no_punycode():
    assert _extract("http://paypal.com")["punycode_domain"] == 0


# ── Misc ───────────────────────────────────────────────────────────────────────

def test_has_www_true():
    assert _extract("http://www.example.com")["has_www"] == 1


def test_has_www_false():
    assert _extract("http://example.com")["has_www"] == 0


def test_domain_has_digits():
    assert _extract("http://bank123secure.com")["domain_has_digits"] == 1


def test_domain_no_digits():
    assert _extract("http://paypal.com")["domain_has_digits"] == 0


def test_hex_char_count():
    feats = _extract("http://evil.com/%20path%3F%41")
    assert feats["hex_char_count"] == 3
