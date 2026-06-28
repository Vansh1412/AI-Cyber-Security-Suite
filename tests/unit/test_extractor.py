"""
tests/unit/test_extractor.py
─────────────────────────────
Integration tests for ml/features/extractor.py — FeatureExtractor.

Tests the full end-to-end extraction pipeline:
  - Feature count and names
  - Type consistency
  - URL normalisation (bare domains, protocol-relative, missing scheme)
  - Zero-vector fallback on bad input
  - Known patterns: phishing URLs score higher on specific features
  - Batch fixture: all phishing + legitimate URL fixtures pass through cleanly
"""

import pytest

from ml.features.extractor import FeatureExtractor

EXPECTED_FEATURE_COUNT = 63  # 25 lexical + 14 structural + 7 statistical + 17 keywords


@pytest.fixture(scope="module")
def extractor():
    return FeatureExtractor()


# ── Basic contract ─────────────────────────────────────────────────────────────

def test_extract_returns_dict(extractor):
    result = extractor.extract("https://www.google.com")
    assert isinstance(result, dict)


def test_extract_feature_count(extractor):
    feats = extractor.extract("https://www.google.com")
    assert len(feats) == EXPECTED_FEATURE_COUNT, (
        f"Expected {EXPECTED_FEATURE_COUNT} features, got {len(feats)}: {list(feats.keys())}"
    )


def test_feature_names_consistent(extractor):
    """feature_names() must match keys returned by extract()."""
    names = extractor.feature_names()
    feats = extractor.extract("https://www.example.com")
    assert set(names) == set(feats.keys())


def test_numeric_features_are_numeric(extractor):
    feats = extractor.extract("https://www.example.com/path?q=1")
    for k, v in feats.items():
        if k not in ("tld", "file_extension"):
            assert isinstance(v, (int, float)), f"'{k}' has type {type(v)}"


# ── URL normalisation ──────────────────────────────────────────────────────────

def test_bare_domain_no_crash(extractor):
    """Bare domain without scheme should not raise."""
    feats = extractor.extract("evil.com")
    assert len(feats) == EXPECTED_FEATURE_COUNT


def test_bare_domain_url_length(extractor):
    feats = extractor.extract("evil.com")
    # Normalised to http://evil.com
    assert feats["url_length"] == len("http://evil.com")


def test_protocol_relative_no_crash(extractor):
    feats = extractor.extract("//evil.com/path")
    assert len(feats) == EXPECTED_FEATURE_COUNT


def test_empty_string_no_crash(extractor):
    """Empty string must not raise."""
    feats = extractor.extract("")
    assert isinstance(feats, dict)
    assert len(feats) == EXPECTED_FEATURE_COUNT


def test_none_like_string_no_crash(extractor):
    feats = extractor.extract("nan")
    assert isinstance(feats, dict)


# ── Known patterns ─────────────────────────────────────────────────────────────

def test_phishing_url_has_high_keyword_count(extractor):
    feats = extractor.extract("http://secure-login.paypal.verify.account.evil.com/payment/confirm")
    assert feats["keyword_count"] >= 4


def test_ip_url_detected(extractor):
    feats = extractor.extract("http://192.168.0.1/login")
    assert feats["has_ip"] == 1
    assert feats["kw_login"] == 1


def test_suspicious_tld_xyz(extractor):
    feats = extractor.extract("http://totally-legit.xyz")
    assert feats["suspicious_tld"] == 1


def test_punycode_detected(extractor):
    feats = extractor.extract("http://xn--pypal-4ve.com/verify")
    assert feats["punycode_domain"] == 1


def test_legitimate_google_entropy_reasonable(extractor):
    feats = extractor.extract("https://www.google.com")
    # Google's URL should have low keyword count and no suspicious TLD
    assert feats["keyword_count"] == 0
    assert feats["suspicious_tld"] == 0
    assert feats["has_ip"] == 0
    assert feats["https_flag"] == 1


def test_https_flag_correct(extractor):
    assert extractor.extract("https://example.com")["https_flag"] == 1
    assert extractor.extract("http://example.com")["https_flag"] == 0


# ── Batch fixture tests ────────────────────────────────────────────────────────

def test_all_phishing_fixtures_produce_full_feature_vector(extractor, phishing_urls):
    for url in phishing_urls:
        feats = extractor.extract(url)
        assert len(feats) == EXPECTED_FEATURE_COUNT, f"Failed for: {url}"


def test_all_legitimate_fixtures_produce_full_feature_vector(extractor, legitimate_urls):
    for url in legitimate_urls:
        feats = extractor.extract(url)
        assert len(feats) == EXPECTED_FEATURE_COUNT, f"Failed for: {url}"


def test_phishing_fixtures_higher_keyword_count_on_average(extractor, phishing_urls, legitimate_urls):
    phish_avg = sum(extractor.extract(u)["keyword_count"] for u in phishing_urls) / len(phishing_urls)
    legit_avg  = sum(extractor.extract(u)["keyword_count"] for u in legitimate_urls) / len(legitimate_urls)
    assert phish_avg > legit_avg, (
        f"Expected phishing keyword_count ({phish_avg:.2f}) > legit ({legit_avg:.2f})"
    )
