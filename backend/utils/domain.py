"""
backend/utils/domain.py
─────────────────────────
Public Suffix List (PSL) aware domain normalization utility.

Supports:
- Canonical SLD+TLD registered domain extraction via tldextract
- Subdomain / FQDN tracking
- IP literal & IPv4-mapped IPv6 normalization
- Multi-tenant shared infrastructure domain flag
- Path extraction
"""

from __future__ import annotations

import contextlib
import ipaddress
from typing import Any
from urllib.parse import urlparse

import tldextract

# Known Multi-Tenant Cloud / CDN / Proxy suffixes where root-domain correlation must be excluded
SHARED_INFRASTRUCTURE_DOMAINS = {
    "github.io",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "awsapprunner.com",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudfront.net",
    "firebaseapp.com",
    "pages.dev",
}


def normalize_canonical_domain(raw_input: str) -> dict[str, Any]:
    """
    Canonical PSL-aware domain normalization algorithm.

    Returns dict:
      {
        "raw": raw_input,
        "registered_domain": str | None,
        "fqdn": str | None,
        "path": str,
        "is_ip": bool,
        "is_shared_infra": bool,
      }
    """
    if not raw_input or not isinstance(raw_input, str):
        return {
            "raw": str(raw_input),
            "registered_domain": None,
            "fqdn": None,
            "path": "/",
            "is_ip": False,
            "is_shared_infra": False,
        }

    s = raw_input.strip().lower().rstrip(".")
    if not s:
        return {
            "raw": raw_input,
            "registered_domain": None,
            "fqdn": None,
            "path": "/",
            "is_ip": False,
            "is_shared_infra": False,
        }

    # Strip brackets if IPv6 literal like [::1] or [::ffff:192.168.1.1]
    clean_host = s
    if clean_host.startswith("[") and "]" in clean_host:
        clean_host = clean_host[1:clean_host.index("]")]

    path = "/"
    if "://" in s or "/" in s:
        try:
            parsed = urlparse(s if "://" in s else f"http://{s}")
            s = parsed.hostname or s
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        except Exception:
            pass
    else:
        s = clean_host

    if s and s.startswith("[") and s.endswith("]"):
        s = s[1:-1]

    # Strip port if present (and not IPv6)
    if ":" in s and not s.startswith("[") and not s.endswith("]"):
        # Check if it's an unbracketed IPv6 like ::ffff:192.168.1.1
        try:
            ipaddress.ip_address(s)
        except ValueError:
            s = s.split(":")[0]

    # Convert Punycode / IDN to ASCII
    with contextlib.suppress(Exception):
        s = s.encode("idna").decode("ascii")

    # Check for IP literal (IPv4 or IPv6)
    try:
        ip = ipaddress.ip_address(s)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        ip_str = str(ip)
        return {
            "raw": raw_input,
            "registered_domain": ip_str,
            "fqdn": ip_str,
            "path": path,
            "is_ip": True,
            "is_shared_infra": False,
        }
    except ValueError:
        pass

    # Extract TLD / SLD via tldextract
    extracted = tldextract.extract(s)
    registered_domain = extracted.registered_domain.lower() if extracted.registered_domain else None
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""

    if registered_domain:
        fqdn = f"{subdomain}.{registered_domain}" if subdomain else registered_domain
    else:
        fqdn = s if s else None

    is_shared = registered_domain in SHARED_INFRASTRUCTURE_DOMAINS if registered_domain else False

    return {
        "raw": raw_input,
        "registered_domain": registered_domain,
        "fqdn": fqdn,
        "path": path,
        "is_ip": False,
        "is_shared_infra": is_shared,
    }
