"""
tests/conftest.py
──────────────────
Shared pytest fixtures for the AI Cyber Security Suite test suite.

Fixtures
--------
phishing_urls   : list[str]  — known phishing URL samples
legitimate_urls : list[str]  — known legitimate URL samples
extractor       : FeatureExtractor — shared instance
"""

import pytest
from ml.features.extractor import FeatureExtractor


@pytest.fixture(scope="session")
def extractor() -> FeatureExtractor:
    """Single FeatureExtractor instance shared across the test session."""
    return FeatureExtractor()


@pytest.fixture(scope="session")
def phishing_urls() -> list[str]:
    return [
        "http://paypal-login.evil.com/verify?id=123&token=abc",
        "https://secure-login.bankofamerica.com.ru/signin/verify",
        "http://192.168.1.1/login?user=admin&pass=1234",
        "http://xn--pypal-4ve.com/update/account",              # punycode
        "http://evil.com:8080/invoice/payment/confirm.php",
        "http://a.b.c.d.e.f.com/very/deep/path/login",          # many subdomains
        "http://g00gle.verify-account.com/suspend/wallet",
        "http://malware.download.win/payload.exe",              # suspicious TLD + ext
    ]


@pytest.fixture(scope="session")
def legitimate_urls() -> list[str]:
    return [
        "https://www.google.com",
        "https://www.github.com/openai/gpt-4",
        "https://stackoverflow.com/questions/1234567",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "http://example.com",
        "https://api.openai.com/v1/chat/completions",
    ]
