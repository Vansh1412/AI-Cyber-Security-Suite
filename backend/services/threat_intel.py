"""
backend/services/threat_intel.py
─────────────────────────────────
Threat Intelligence Layer.

Order of checks (fastest → slowest):
  1. Local hard blacklist        (exact match, 0ms)
  2. Heuristic Rule Engine       (regex + domain logic, 0ms)
  3. OpenPhish stub
  4. VirusTotal stub
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from src.utils.logger import logger

# ── 1. Hard Blacklist ─────────────────────────────────────────────────────────
LOCAL_BLACKLIST: set[str] = {
    "http://secure-login-paypal.com",
    "http://g00gle.com-verify.info",
    "http://appleid-update-billing.com",
}

# ── 2. Trusted Allowlist ──────────────────────────────────────────────────────
TRUSTED_DOMAINS: set[str] = {
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "linkedin.com",
    "wikipedia.org",
    "stackoverflow.com",
    "chat.openai.com",
    "githubusercontent.com",
    "googleusercontent.com",
    "reddit.com",
    "netflix.com",
    "paypal.com",
    "twitter.com",
    "facebook.com",
    "instagram.com",
}

# ── 3. Heuristic Rule Engine ──────────────────────────────────────────────────

# Major brands whose name must ONLY appear as the exact registered domain
BRAND_DOMAINS: dict[str, str] = {
    "paypal":    "paypal.com",
    "google":    "google.com",
    "apple":     "apple.com",
    "microsoft": "microsoft.com",
    "amazon":    "amazon.com",
    "facebook":  "facebook.com",
    "instagram": "instagram.com",
    "netflix":   "netflix.com",
    "dropbox":   "dropbox.com",
    "linkedin":  "linkedin.com",
    "twitter":   "twitter.com",
    "wellsfargo":"wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "chase":     "chase.com",
    "citibank":  "citibank.com",
    "steam":     "steampowered.com",
    "adobe":     "adobe.com",
    "docusign":  "docusign.com",
    "dhl":       "dhl.com",
    "fedex":     "fedex.com",
    "ups":       "ups.com",
    "usps":      "usps.com",
    "irs":       "irs.gov",
}

# Suspicious TLDs often abused in phishing campaigns
SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".club", ".work", ".info", ".biz", ".top", ".loan",
    ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cc", ".win", ".stream", ".download", ".racing",
    ".accountant", ".faith", ".science", ".cricket",
}

# Keywords that strongly indicate phishing/credential theft intent
PHISHING_KEYWORDS: list[str] = [
    "verify", "login", "signin", "secure", "account", "update",
    "confirm", "billing", "password", "credential", "bank",
    "wallet", "recover", "suspended", "unlock", "validate",
    "restore", "support", "helpdesk", "authorize",
]

# URL patterns associated with scam/phishing pages
SUSPICIOUS_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"/verify\?id=", re.I),
    re.compile(r"/validate\?token=", re.I),
    re.compile(r"/confirm\.php", re.I),
    re.compile(r"/account[_-]?(update|verify|suspend)", re.I),
    re.compile(r"/login\.php", re.I),
    re.compile(r"\.(com|net|org)\.(tk|ml|ga|cf|gq|cc|xyz|top)", re.I),
]

# IP address as hostname → almost always phishing/malware
IP_PATTERN = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
)


def _heuristic_check(url: str) -> dict | None:
    """
    Returns a threat dict if the URL matches heuristic phishing rules,
    or None if it appears clean (ML model should evaluate).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    hostname: str = (parsed.hostname or "").lower().strip()
    path_and_query: str = (parsed.path + "?" + parsed.query).lower()
    full_url_lower = url.lower()

    if not hostname:
        return None

    # ── Rule 0: Trusted Allowlist ─────────────────────────────────────────────
    # If it's a legitimate trusted domain (or direct subdomain), it's safe.
    for trusted in TRUSTED_DOMAINS:
        if _is_legitimate_domain(hostname, trusted):
            return None # Guaranteed clean

    # ── Rule 1: IP address as host ────────────────────────────────────────────
    if IP_PATTERN.match(hostname):
        logger.info("Heuristic [IP-as-host]: %s", url)
        return _threat("phishing", 0.97,
                       "Direct IP address used as hostname — classic phishing/malware pattern.",
                       "heuristic:ip-host")

    # ── Rule 2: Brand impersonation ───────────────────────────────────────────
    # e.g. "paypal-secure-login.xyz" contains "paypal" but is NOT paypal.com
    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in hostname and not _is_legitimate_domain(hostname, legit_domain):
            logger.info("Heuristic [Brand-Impersonation/%s]: %s", brand, url)
            return _threat("phishing", 0.96,
                           f"Domain impersonates '{brand}' (legitimate: {legit_domain}) — brand phishing.",
                           f"heuristic:brand:{brand}")

    # ── Rule 3: Suspicious TLD ────────────────────────────────────────────────
    tld = _get_tld(hostname)
    if tld in SUSPICIOUS_TLDS:
        # Count phishing keywords in the full URL — if ≥ 1, flag it
        kw_hits = [k for k in PHISHING_KEYWORDS if k in full_url_lower]
        if kw_hits:
            logger.info("Heuristic [Suspicious-TLD+Keywords/%s]: %s", tld, url)
            return _threat("phishing", 0.90,
                           f"Suspicious TLD '{tld}' combined with phishing keywords: {kw_hits[:3]}.",
                           "heuristic:suspicious-tld")

    # ── Rule 4: Suspicious path/query patterns ────────────────────────────────
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern.search(path_and_query):
            logger.info("Heuristic [Suspicious-Path-Pattern]: %s", url)
            return _threat("phishing", 0.88,
                           "URL path/query matches known phishing template.",
                           "heuristic:path-pattern")

    # ── Rule 5: Excessive subdomain depth (typo-squatting) ───────────────────
    # e.g. login.paypal.com-verify.info
    parts = hostname.split(".")
    if len(parts) >= 5:
        logger.info("Heuristic [Deep-Subdomain]: %s", url)
        return _threat("phishing", 0.82,
                       "Unusually deep subdomain nesting — common in redirect-chain phishing.",
                       "heuristic:deep-subdomain")

    # ── Rule 6: Hyphenated brand lookalike in hostname ────────────────────────
    # e.g. "paypal-secure.net", "amazon-support.info"
    hostname_plain = hostname.replace("-", "").replace(".", "")
    for brand in BRAND_DOMAINS:
        if brand in hostname_plain and not _is_legitimate_domain(hostname, BRAND_DOMAINS[brand]):
            kw_hits = [k for k in PHISHING_KEYWORDS if k in full_url_lower]
            if kw_hits:
                logger.info("Heuristic [Hyphen-Brand/%s]: %s", brand, url)
                return _threat("phishing", 0.91,
                               f"Hyphenated brand impersonation of '{brand}' with phishing keywords.",
                               f"heuristic:hyphen-brand:{brand}")

    return None  # Looks clean → pass to ML


# ── Helpers ───────────────────────────────────────────────────────────────────

def _threat(prediction: str, confidence: float, reason: str, source: str) -> dict:
    return {
        "prediction": prediction,
        "confidence": confidence,
        "reason": reason,
        "source": source,
    }


def _get_tld(hostname: str) -> str:
    """Return the last two dot-separated parts as the TLD, e.g. '.xyz'"""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return "." + parts[-1]
    return ""


def _is_legitimate_domain(hostname: str, legit_domain: str) -> bool:
    """
    Returns True if hostname IS the legitimate domain or a direct subdomain of it.
    e.g. "www.paypal.com" → True for "paypal.com"
         "paypal-secure.xyz" → False
    """
    return hostname == legit_domain or hostname.endswith("." + legit_domain)


# ── Service Class ─────────────────────────────────────────────────────────────

class ThreatIntelService:
    def __init__(self):
        self._client = httpx.AsyncClient(timeout=3.0)

    async def close(self):
        await self._client.aclose()

    async def check_url(self, url: str) -> dict | None:
        """
        Waterfalls through threat intel feeds.
        Returns a dict with {prediction, confidence, reason, source} if threat found.
        Returns None if clean → ML model should process.
        """
        # 1. Hard blacklist
        if url in LOCAL_BLACKLIST:
            logger.info("ThreatIntel Hit [Local Blacklist]: %s", url)
            return _threat("phishing", 1.0,
                           "URL found in high-confidence local blacklist.",
                           "blacklist")

        # 2. Heuristic rule engine (catches obvious brand phishing, IP hosts, etc.)
        heuristic_result = _heuristic_check(url)
        if heuristic_result:
            return heuristic_result

        # 3. OpenPhish Feed (stub — replace with real API call)
        if "openphish" in url.lower():
            logger.info("ThreatIntel Hit [OpenPhish]: %s", url)
            return _threat("phishing", 0.99,
                           "URL flagged by OpenPhish threat intelligence feed.",
                           "openphish")

        # 4. VirusTotal (stub — replace with real API call)
        if "virustotal" in url.lower():
            logger.info("ThreatIntel Hit [VirusTotal]: %s", url)
            return _threat("malware", 0.99,
                           "Flagged as malicious by 12/94 security vendors on VirusTotal.",
                           "virustotal")

        # All checks passed → let ML model evaluate
        return None


threat_intel_service = ThreatIntelService()
