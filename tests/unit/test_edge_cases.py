"""
tests/unit/test_edge_cases.py
─────────────────────────────
Stress tests for the feature extraction pipeline to ensure API resilience.
"""

from __future__ import annotations

import pytest

from ml.features.extractor import FeatureExtractor


@pytest.fixture
def extractor():
    return FeatureExtractor()


def test_empty_string(extractor):
    feats = extractor.extract("")
    assert feats["url_length"] in (0, 14, 7)
    assert feats["has_ip"] == 0
    assert feats["https_flag"] == 0


def test_ip_only(extractor):
    feats = extractor.extract("192.168.1.1")
    assert feats["has_ip"] == 1
    assert feats["domain_length"] == 11
    assert feats["https_flag"] == 0


def test_unicode_domain(extractor):
    # API should not crash on unicode domains
    feats = extractor.extract("http://ñandu.cl/login")
    assert feats["url_length"] > 10
    assert feats["path_length"] == 6


def test_emoji_domain(extractor):
    feats = extractor.extract("https://😎.com/verify")
    assert feats["https_flag"] == 1
    assert feats["url_length"] > 5


def test_extremely_long_url(extractor):
    long_url = "http://example.com/" + "a" * 3000
    feats = extractor.extract(long_url)
    assert feats["url_length"] > 3000
    assert feats["path_length"] > 3000


def test_multiple_at_symbols(extractor):
    feats = extractor.extract("http://user@pass@evil.com@legit.com/path")
    assert feats["num_at"] == 3


def test_invalid_scheme(extractor):
    feats = extractor.extract("ftp://files.com/download")
    assert feats["https_flag"] == 0
    assert feats["domain_length"] == 9
