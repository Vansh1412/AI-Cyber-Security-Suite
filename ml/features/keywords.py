"""
ml/features/keywords.py
────────────────────────
KeywordFeatures — 17 keyword/brand presence features.

Instead of a single binary "has phishing keyword" flag, each keyword gets
its own binary feature. This allows SHAP and tree-based models to learn
which specific words are the most predictive — e.g., "paypal" in a subdomain
is far more suspicious than "login" in a path.

Features
--------
One binary feature per keyword (15 keywords):
    kw_login, kw_verify, kw_secure, kw_update, kw_bank,
    kw_paypal, kw_account, kw_signin, kw_invoice, kw_payment,
    kw_confirm, kw_password, kw_suspend, kw_validate, kw_wallet

Plus two aggregate features:
    keyword_count   — total number of the above keywords found
    has_brand_name  — 1 if any of BRAND_NAMES appears in the full URL
"""

from urllib.parse import ParseResult

# ── Keyword lists ──────────────────────────────────────────────────────────────

PHISHING_KEYWORDS: list[str] = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "paypal",
    "account",
    "signin",
    "invoice",
    "payment",
    "confirm",
    "password",
    "suspend",
    "validate",
    "wallet",
]

BRAND_NAMES: frozenset[str] = frozenset({
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "ebay", "wellsfargo", "chase", "citibank",
    "hsbc", "barclays", "bankofamerica", "twitter", "linkedin",
    "dropbox", "docusign", "dhl", "fedex", "ups",
})


class KeywordFeatures:
    """
    Extracts 17 keyword-based features from a URL string.

    Usage
    -----
    parsed = urllib.parse.urlparse(url)
    features = KeywordFeatures.extract(url, parsed)
    """

    @staticmethod
    def extract(url: str, parsed: ParseResult) -> dict:  # noqa: ARG002
        """
        Parameters
        ----------
        url    : Raw URL string (search performed on lowercased version).
        parsed : urllib.parse.urlparse(url) result (unused here, kept for API
                 consistency with other feature modules).

        Returns
        -------
        dict[str, int]
            17 keyword feature key-value pairs.
        """
        url_lower = url.lower()
        features: dict[str, int] = {}

        # ── Per-keyword binary flags ───────────────────────────────────────────
        count = 0
        for kw in PHISHING_KEYWORDS:
            present = 1 if kw in url_lower else 0
            features[f"kw_{kw}"] = present
            count += present

        # ── Aggregate features ─────────────────────────────────────────────────
        features["keyword_count"]  = count
        features["has_brand_name"] = 1 if any(b in url_lower for b in BRAND_NAMES) else 0

        return features
