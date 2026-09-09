"""
backend/services/threat_intel.py
─────────────────────────────────
Threat Intelligence Layer — Sprint 2 upgrade.

Order of checks (fastest → slowest):
  1. Local hard blacklist        (exact match, 0ms)
  2. Heuristic Rule Engine       (regex + domain logic, 0ms)
  3. PhishTank feed              (in-memory cached daily feed, 0ms after hydration)
  4. VirusTotal API v3           (async HTTP, ~200–800ms — only if key configured)

Each check returns either:
  • A threat dict  →  {prediction, confidence, reason, source}
  • None           →  URL appears clean; continue to next layer / ML

No check throws uncaught exceptions — errors are logged and degraded gracefully.
"""

from __future__ import annotations

import asyncio
import base64
import re
import time
from urllib.parse import urlparse

import httpx

from backend.core.config import settings
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
    "wellsfargo": "wellsfargo.com",
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
            return None  # Guaranteed clean

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
    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in hostname_plain and not _is_legitimate_domain(hostname, legit_domain):
            kw_hits = [k for k in PHISHING_KEYWORDS if k in full_url_lower]
            if kw_hits:
                logger.info("Heuristic [Hyphen-Brand/%s]: %s", brand, url)
                return _threat("phishing", 0.91,
                               f"Hyphenated brand impersonation of '{brand}' with phishing keywords.",
                               f"heuristic:hyphen-brand:{brand}")

    return None  # Looks clean → pass to next layer


# ── 4. PhishTank Feed ────────────────────────────────────────────────────────

class PhishTankFeed:
    """
    Maintains an in-memory set of known-phishing URLs sourced from PhishTank.
    Feed is refreshed asynchronously every PHISHTANK_REFRESH_INTERVAL_S seconds.
    Falls back gracefully if network is unavailable.
    """

    FEED_URL = "https://data.phishtank.com/data/online-valid.csv"

    def __init__(self) -> None:
        self._phishing_urls: set[str] = set()
        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()

    def _needs_refresh(self) -> bool:
        return (time.monotonic() - self._last_refresh) > settings.PHISHTANK_REFRESH_INTERVAL_S

    async def _refresh(self, client: httpx.AsyncClient) -> None:
        """Download and parse the PhishTank online-valid CSV feed."""
        async with self._lock:
            # Re-check inside lock to avoid stampede
            if not self._needs_refresh():
                return
            try:
                headers: dict[str, str] = {"User-Agent": "phishtank/AI-Cyber-Security-Suite"}
                if settings.PHISHTANK_API_KEY:
                    headers["Authorization"] = f"Bearer {settings.PHISHTANK_API_KEY}"

                resp = await client.get(self.FEED_URL, headers=headers, timeout=10.0)
                resp.raise_for_status()

                # CSV format: index,phish_id,url,phish_detail_url,submission_time,...
                urls: set[str] = set()
                for line in resp.text.splitlines()[1:]:  # skip header
                    parts = line.split(",", 3)
                    if len(parts) >= 3:
                        raw_url = parts[2].strip().strip('"')
                        if raw_url:
                            urls.add(raw_url)

                self._phishing_urls = urls
                self._last_refresh = time.monotonic()
                logger.info("PhishTank feed refreshed: %d entries loaded.", len(urls))
            except httpx.HTTPError as exc:
                logger.warning("PhishTank feed refresh failed (HTTP): %s", exc)
            except Exception as exc:
                logger.warning("PhishTank feed refresh failed (unexpected): %s", exc)

    async def check(self, url: str, client: httpx.AsyncClient) -> bool:
        """Return True if the URL is in the PhishTank feed."""
        if self._needs_refresh():
            await self._refresh(client)
        return url in self._phishing_urls


_phishtank_feed = PhishTankFeed()


# ── 5. VirusTotal API v3 ─────────────────────────────────────────────────────

def _vt_url_id(url: str) -> str:
    """VirusTotal v3 uses a URL-safe base64 encoding of the URL (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def _check_virustotal(url: str, client: httpx.AsyncClient) -> dict | None:
    """
    Query VirusTotal API v3 for a URL report.
    Returns a threat dict if the URL is flagged by ≥ VIRUSTOTAL_MALICIOUS_THRESHOLD vendors.
    Returns None if clean or if the key is not configured / quota exceeded.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return None  # No key configured — skip silently

    url_id = _vt_url_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        resp = await client.get(
            endpoint,
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=settings.VIRUSTOTAL_TIMEOUT_S,
        )

        if resp.status_code == 404:
            # URL not yet in VT database — submit it for future analysis (fire-and-forget)
            asyncio.create_task(_submit_virustotal(url, client))
            logger.info("VirusTotal: URL not found, submitted for analysis: %s", url)
            return None

        if resp.status_code == 429:
            logger.warning("VirusTotal: rate limit hit — skipping for this request.")
            return None

        resp.raise_for_status()
        data = resp.json()

        stats: dict = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious: int = stats.get("malicious", 0)
        suspicious: int = stats.get("suspicious", 0)
        total_flagged = malicious + suspicious

        if total_flagged >= settings.VIRUSTOTAL_MALICIOUS_THRESHOLD:
            logger.info("VirusTotal [Hit]: %s — %d vendors flagged.", url, total_flagged)
            return _threat(
                "malware" if malicious > suspicious else "phishing",
                min(0.99, 0.50 + (total_flagged / 94) * 0.49),
                f"Flagged as malicious/suspicious by {total_flagged}/94 security vendors on VirusTotal.",
                "virustotal",
            )

        logger.debug("VirusTotal [Clean]: %s — %d vendors flagged.", url, total_flagged)
        return None

    except httpx.TimeoutException:
        logger.warning("VirusTotal: request timed out for %s", url)
        return None
    except httpx.HTTPStatusError as exc:
        logger.warning("VirusTotal: HTTP %s for %s", exc.response.status_code, url)
        return None
    except Exception as exc:
        logger.warning("VirusTotal: unexpected error for %s: %s", url, exc)
        return None


async def _submit_virustotal(url: str, client: httpx.AsyncClient) -> None:
    """Submit a new URL to VirusTotal for analysis (best-effort, no return value)."""
    if not settings.VIRUSTOTAL_API_KEY:
        return
    try:
        await client.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            data={"url": url},
            timeout=5.0,
        )
    except Exception as exc:
        logger.debug("VirusTotal submit failed: %s", exc)


# ── Service Class ─────────────────────────────────────────────────────────────

class ThreatIntelService:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=3.0)

    async def close(self) -> None:
        await self._client.aclose()

    async def check_url(self, url: str) -> dict | None:
        """
        Waterfalls through threat intel feeds.
        Returns a dict with {prediction, confidence, reason, source} if threat found.
        Returns None if clean → ML model should process.
        """
        # ── Layer 1: Hard blacklist (0ms) ─────────────────────────────────────
        if url in LOCAL_BLACKLIST:
            logger.info("ThreatIntel Hit [Local Blacklist]: %s", url)
            return _threat(
                "phishing", 1.0,
                "URL found in high-confidence local blacklist.",
                "blacklist",
            )

        # ── Layer 2: Heuristic rule engine (0ms) ─────────────────────────────
        heuristic_result = _heuristic_check(url)
        if heuristic_result:
            return heuristic_result

        # ── Layer 3: PhishTank feed (0ms after hydration) ─────────────────────
        is_phishtank_hit = await _phishtank_feed.check(url, self._client)
        if is_phishtank_hit:
            logger.info("ThreatIntel Hit [PhishTank]: %s", url)
            return _threat(
                "phishing", 0.99,
                "URL found in PhishTank verified phishing database.",
                "phishtank",
            )

        # ── Layer 4: VirusTotal API v3 (async, ~200–800ms) ───────────────────
        vt_result = await _check_virustotal(url, self._client)
        if vt_result:
            return vt_result

        # All checks passed → let ML model evaluate
        return None


threat_intel_service = ThreatIntelService()
