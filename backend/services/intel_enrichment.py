"""
backend/services/intel_enrichment.py
──────────────────────────────────────
Sprint 4: Threat Intelligence Enrichment Service (Hardened).

Provides on-demand, explicit enrichment lookups:
  1. WHOIS domain age (days since registration) — with regex sanitization and 3s timeout.
  2. TLS certificate validity, issuer, expiry — over SSRF-validated sockets with SNI.
  3. Bounded HTTP redirect chain inspection — max 3 hops, 3s timeout, 50KB read ceiling.
  4. IP geolocation — optional, cached, using Authorization header (never in URL).

Security:
  - Centralized SSRF protection via `backend.core.security_network`.
  - Blocks RFC1918, 169.254.0.0/16, 0.0.0.0/8, link-local, loopback, multicast, etc.
  - DNS resolution fails closed.
  - Anti-DNS rebinding via IP-pinned connections.
  - Zero pickle loading.
  - Strict isolation; all external calls fail open returning structured fallback data.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from backend.core.config import settings
from backend.core.security_network import (
    SSRFSecurityError,
    resolve_and_validate_host,
    sanitize_domain_for_whois,
    validate_target_url,
)
from src.utils.logger import logger

# ── Operational Constants ─────────────────────────────────────────────────────
MAX_REDIRECTS: int = 3
HTTP_TIMEOUT_S: float = 3.0
WHOIS_TIMEOUT_S: float = 3.0
IPINFO_TIMEOUT_S: float = 2.5
MAX_BODY_BYTES: int = 50 * 1024  # 50 KB body read ceiling (DoS / decompression defense)
IPINFO_BASE_URL: str = "https://ipinfo.io"

# Simple in-memory cache for IP geolocation to conserve rate limits
_GEO_CACHE: dict[str, dict[str, Any]] = {}


# ── 1. WHOIS Domain Age ───────────────────────────────────────────────────────

def _sync_whois_lookup(domain: str) -> int | None:
    """Synchronous WHOIS query executed in a worker thread."""
    try:
        import whois  # type: ignore[import-untyped]

        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None

        # Safe fallback parsing for registries returning string dates (CR-S4-004)
        if isinstance(creation_date, str):
            clean_str = creation_date.strip()
            try:
                from dateutil import parser as date_parser
                creation_date = date_parser.parse(clean_str)
            except Exception:
                return None

        if not isinstance(creation_date, datetime):
            return None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age = (now - creation_date).days
        return max(age, 0)

    except Exception as exc:
        logger.debug("WHOIS lookup failed for '%s': %s", domain, exc)
        return None


async def get_domain_age_days(url_or_domain: str) -> int | None:
    """
    Look up the domain registration date via WHOIS and return age in days.
    Domain input is strictly sanitized with regex to prevent command injection.
    """
    clean_domain = sanitize_domain_for_whois(url_or_domain)
    if not clean_domain:
        return None

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_sync_whois_lookup, clean_domain),
            timeout=WHOIS_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        logger.warning("WHOIS lookup timed out for domain: %s", clean_domain)
        return None
    except Exception as exc:
        logger.warning("WHOIS query error for domain %s: %s", clean_domain, exc)
        return None


# ── 2. TLS Certificate Analysis ──────────────────────────────────────────────

def _sync_tls_inspect(ip_str: str, hostname: str, port: int) -> dict[str, Any]:
    """
    Connect to the pre-validated public IP address, wrap with TLS using the
    target hostname for SNI, and extract certificate metadata.
    """
    ctx = ssl.create_default_context()
    # Connect directly to the validated IP to prevent DNS rebinding
    with (
        socket.create_connection((ip_str, port), timeout=HTTP_TIMEOUT_S) as raw_sock,
        ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssl_sock,
    ):
        cert = ssl_sock.getpeercert()

    if not cert:
        return {"valid": False, "reason": "No certificate returned"}

    not_after_str = cert.get("notAfter", "")
    expires_at: str | None = None
    days_to_expiry: int | None = None

    if not_after_str:
        try:
            exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            expires_at = exp_dt.isoformat()
            days_to_expiry = (exp_dt - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    # Extract issuer
    issuer_raw = cert.get("issuer", ())
    issuer_parts = [v for item in issuer_raw for _, v in item if isinstance(v, str)]
    issuer = " ".join(issuer_parts) if issuer_parts else None

    # Extract subject
    subject_raw = cert.get("subject", ())
    subject_parts = [v for item in subject_raw for _, v in item if isinstance(v, str)]
    subject = " ".join(subject_parts) if subject_parts else None

    return {
        "valid": True,
        "issuer": issuer[:200] if issuer else None,
        "subject": subject[:200] if subject else None,
        "expires_at": expires_at,
        "days_to_expiry": days_to_expiry,
    }


async def get_tls_info(url: str) -> dict[str, Any] | None:
    """
    Inspect the TLS certificate for the target HTTPS URL.
    Enforces strict SSRF validation prior to socket creation and pins connection.
    """
    try:
        scheme, hostname, port, _ = validate_target_url(url)
    except SSRFSecurityError as exc:
        return {"valid": False, "reason": f"SSRF blocked: {exc}"}

    if scheme != "https":
        return {"valid": False, "reason": "Not an HTTPS URL"}

    try:
        validated_ips = await resolve_and_validate_host(hostname)
        target_ip = validated_ips[0]

        return await asyncio.wait_for(
            asyncio.to_thread(_sync_tls_inspect, target_ip, hostname, port),
            timeout=HTTP_TIMEOUT_S + 0.5,
        )
    except asyncio.TimeoutError:
        return {"valid": False, "reason": "TLS handshake timed out"}
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "reason": f"Certificate verification error: {str(exc)[:150]}"}
    except SSRFSecurityError as exc:
        return {"valid": False, "reason": f"SSRF blocked: {exc}"}
    except Exception as exc:
        logger.debug("TLS inspection failed for %s: %s", url, exc)
        return {"valid": False, "reason": "TLS inspection failed or connection refused"}


# ── 3. Bounded HTTP Redirect Chain Analysis ───────────────────────────────────

async def follow_redirect_chain(initial_url: str) -> dict[str, Any]:
    """
    Follow HTTP redirects up to MAX_REDIRECTS (3) hops.
    Requirements:
      - HTTP and HTTPS only.
      - Max 3 hops.
      - Max 3.0s timeout per hop.
      - Max 50 KB response read ceiling.
      - Strips sensitive headers (Authorization, Cookie).
      - Re-validates target and IP at every hop.
      - Pins destination connection to validated IP to prevent DNS rebinding.
    """
    chain: list[str] = [initial_url]
    current = initial_url
    redirect_count = 0

    for _ in range(MAX_REDIRECTS):
        try:
            scheme, hostname, port, path_and_query = validate_target_url(current)
            validated_ips = await resolve_and_validate_host(hostname)
            pinned_ip = validated_ips[0]
        except SSRFSecurityError as exc:
            logger.warning("Redirect chain halted by SSRF defense at %s: %s", current, exc)
            break

        # Construct pinned URL with IP address while setting Host header for routing/vhost
        # Note: If IPv6, format with brackets
        ip_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        pinned_request_url = f"{scheme}://{ip_host}:{port}{path_and_query}"

        headers = {
            "Host": hostname if (port in (80, 443)) else f"{hostname}:{port}",
            "User-Agent": "AI-Cyber-Security-Suite/4.0 (+https://internal.security)",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        }

        try:
            async with (
                httpx.AsyncClient(
                    follow_redirects=False,
                    timeout=HTTP_TIMEOUT_S,
                    verify=False,  # Intentionally inspection-mode for untrusted domains
                ) as client,
                client.stream(
                    "GET",
                    pinned_request_url,
                    headers=headers,
                    extensions={"sni_hostname": hostname} if scheme == "https" else {},
                ) as resp,
            ):
                # Enforce max 50KB response body ceiling
                total_bytes = 0
                async for chunk in resp.aiter_bytes():
                    total_bytes += len(chunk)
                    if total_bytes > MAX_BODY_BYTES:
                        logger.info("Redirect response exceeded %d bytes limit for %s", MAX_BODY_BYTES, current)
                        break

                # Check for redirect response codes (301, 302, 303, 307, 308)
                if resp.is_redirect and "location" in resp.headers:
                    raw_loc = resp.headers["location"].strip()
                    # Resolve relative redirect URLs safely
                    next_url = urljoin(current, raw_loc)

                    # Validate next URL scheme immediately
                    next_parsed = urlparse(next_url)
                    if next_parsed.scheme.lower() not in ("http", "https"):
                        logger.info("Redirect halted: prohibited scheme '%s'", next_parsed.scheme)
                        break

                    # Detect redirect loop
                    if next_url in chain:
                        logger.info("Redirect loop detected at %s", next_url)
                        break

                    redirect_count += 1
                    current = next_url
                    chain.append(current)
                    continue
                else:
                    # Reached terminal landing URL
                    break

        except Exception as exc:
            logger.debug("Redirect hop connection terminated for %s: %s", current, exc)
            break

    return {
        "redirect_count": redirect_count,
        "final_url": current,
        "chain": chain,
    }


# ── 4. IP Geolocation (Optional & Hardened) ───────────────────────────────────

async def get_ip_geolocation(url_or_host: str) -> dict[str, Any] | None:
    """
    Resolve domain's IP and fetch geolocation from ipinfo.io.
    - Strictly optional: disabled if IPINFO_API_KEY is unset/empty.
    - Token transmitted via Authorization: Bearer header (never in URL query string).
    - Caches IP responses to avoid rate-limit exhaustion.
    - Enforces strict SSRF validation.
    """
    api_key = getattr(settings, "IPINFO_API_KEY", "").strip()
    if not api_key:
        return None  # Gracefully disabled without key

    try:
        # Extract hostname
        if "://" in url_or_host:
            _, hostname, _, _ = validate_target_url(url_or_host)
        else:
            hostname = url_or_host.strip()

        validated_ips = await resolve_and_validate_host(hostname)
        target_ip = validated_ips[0]

        # Check cache
        if target_ip in _GEO_CACHE:
            return _GEO_CACHE[target_ip]

        geo_endpoint = f"{IPINFO_BASE_URL}/{target_ip}/json"
        headers = {"Authorization": f"Bearer {api_key}"}

        async with httpx.AsyncClient(timeout=IPINFO_TIMEOUT_S) as client:
            resp = await client.get(geo_endpoint, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "ip": data.get("ip", target_ip),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                }
                _GEO_CACHE[target_ip] = result
                return result

    except Exception as exc:
        logger.debug("IP geolocation lookup failed for %s: %s", url_or_host, exc)

    return None


# ── 5. Master Enrichment Orchestrator ────────────────────────────────────────

async def enrich_scan(url: str) -> dict[str, Any]:
    """
    Master orchestrator for threat intelligence enrichment.
    Executes WHOIS, TLS inspection, bounded redirect tracing, and IP geolocation.
    Isolated with fail-open partial returns.
    """
    t0 = time.perf_counter()

    # Pre-validate URL scheme
    try:
        validate_target_url(url)
    except SSRFSecurityError as exc:
        logger.warning("Enrichment pre-check rejected unsafe URL %s: %s", url, exc)
        return {
            "domain_age_days": None,
            "tls_info": {"valid": False, "reason": str(exc)},
            "redirect_count": 0,
            "final_url": url,
            "redirect_chain": [url],
            "geolocation": None,
            "enrichment_ms": 0.0,
            "blocked": True,
        }

    domain_age_task = get_domain_age_days(url)
    tls_task = get_tls_info(url)
    redirect_task = follow_redirect_chain(url)
    geo_task = get_ip_geolocation(url)

    results = await asyncio.gather(
        domain_age_task,
        tls_task,
        redirect_task,
        geo_task,
        return_exceptions=True,
    )

    def _unwrap(val: Any, default: Any = None) -> Any:
        return default if isinstance(val, Exception) else val

    domain_age = _unwrap(results[0])
    tls_info = _unwrap(results[1])
    redirect_info = _unwrap(results[2], {"redirect_count": 0, "final_url": url, "chain": [url]})
    geo_info = _unwrap(results[3])

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    logger.info("Enrichment completed for %s in %.1fms", url, elapsed_ms)

    return {
        "domain_age_days": domain_age,
        "tls_info": tls_info,
        "redirect_count": redirect_info.get("redirect_count", 0) if isinstance(redirect_info, dict) else 0,
        "final_url": redirect_info.get("final_url", url) if isinstance(redirect_info, dict) else url,
        "redirect_chain": redirect_info.get("chain", [url]) if isinstance(redirect_info, dict) else [url],
        "geolocation": geo_info,
        "enrichment_ms": elapsed_ms,
    }
