"""
backend/core/security_network.py
─────────────────────────────────
Sprint 4: Centralized SSRF-Safe Networking Layer.

Provides rigorous, defense-in-depth protection against Server-Side Request
Forgery (SSRF), DNS rebinding / TOCTOU attacks, cloud metadata exfiltration,
and private network probing.

All outbound network requests directed at target/scanned domains or IPs
MUST pass through this security boundary.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse

from src.utils.logger import logger


class SSRFSecurityError(Exception):
    """Raised when an outbound request targets a blocked or unsafe destination."""
    pass


# ── Blocked Network CIDRs ─────────────────────────────────────────────────────
# Covers RFC 1918, RFC 3927 (link-local), RFC 6598 (carrier NAT), loopback,
# multicast, cloud metadata (169.254.169.254), documentation, and IPv6 equivalents.
_BLOCKED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # Current network / localhost alias
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmark Testing
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),        # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),            # Discard-only
    ipaddress.ip_network("2001:db8::/32"),       # Documentation
    ipaddress.ip_network("fc00::/7"),            # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),           # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),            # Multicast
]

# Strict regex for domain validation in external lookup services (WHOIS, DNS)
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_blocked_ip(ip_str: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Evaluate whether an IP address belongs to any restricted or private range.

    Handles standard IPv4/IPv6, IPv4-mapped IPv6 (::ffff:127.0.0.1), and
    alternate encodings parsed by Python's `ipaddress` module.
    """
    try:
        if not isinstance(ip_str, ipaddress.IPv4Address | ipaddress.IPv6Address):
            ip = ipaddress.ip_address(str(ip_str).strip())
        else:
            ip = ip_str

        # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Check native properties
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True

        # Check against explicit CIDR blocklist
        return any(ip in net for net in _BLOCKED_NETWORKS)

    except ValueError:
        # Malformed IP address — fail-closed (treat as blocked)
        return True


def validate_target_url(url: str) -> tuple[str, str, int, str]:
    """
    Parse and validate target URL strictly for scheme and destination.

    Returns:
      (scheme, hostname, port, path_and_query)

    Raises:
      SSRFSecurityError if the scheme is not HTTP/HTTPS or hostname is missing/invalid.
    """
    if not url or not isinstance(url, str):
        raise SSRFSecurityError("Target URL cannot be empty.")

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        raise SSRFSecurityError(f"Unsupported URL scheme in '{url}'. Only HTTP and HTTPS are permitted.")

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFSecurityError(f"Malformed URL: {exc}") from exc

    if parsed.username or parsed.password:
        raise SSRFSecurityError("URLs containing embedded credentials (userinfo) are prohibited.")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFSecurityError(f"Prohibited protocol scheme: {scheme}")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SSRFSecurityError("URL must contain a valid hostname.")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise SSRFSecurityError(f"Invalid URL port: {exc}") from exc

    # Check for integer/hex decimal IP representations (e.g. 2130706433, 0x7f000001)
    if hostname.isdigit() or (hostname.startswith("0x") and len(hostname) <= 10):
        try:
            val = int(hostname, 0)
            if 0 <= val <= 0xFFFFFFFF:
                ip = ipaddress.IPv4Address(val)
                if is_blocked_ip(ip):
                    raise SSRFSecurityError(f"Direct IP access to blocked address '{hostname}' rejected.")
        except (ValueError, OverflowError):
            pass

    # If the hostname is an IP literal, validate immediately
    try:
        ip = ipaddress.ip_address(hostname)
        if is_blocked_ip(ip):
            raise SSRFSecurityError(f"Direct IP access to blocked address '{hostname}' rejected.")
    except ValueError:
        pass  # Hostname is a domain name — will be resolved and checked

    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query = f"{path_and_query}?{parsed.query}"

    return scheme, hostname, port, path_and_query


async def resolve_and_validate_host(hostname: str) -> list[str]:
    """
    Resolve all A and AAAA DNS records for a hostname and validate that
    EVERY resolved IP address is public and safe.

    Fail-Closed:
      - If ANY resolved IP is in a blocked network, rejects the host.
      - If resolution fails, times out, or returns no records, rejects the host.

    Returns:
      List of validated public IP string addresses.
    """
    hostname = hostname.strip().lower()
    if not hostname:
        raise SSRFSecurityError("Hostname cannot be empty.")

    # Check for integer/hex decimal IP representations
    if hostname.isdigit() or (hostname.startswith("0x") and len(hostname) <= 10):
        try:
            val = int(hostname, 0)
            if 0 <= val <= 0xFFFFFFFF:
                ip = ipaddress.IPv4Address(val)
                if is_blocked_ip(ip):
                    raise SSRFSecurityError(f"Target host '{hostname}' is a blocked IP address.")
                return [str(ip)]
        except (ValueError, OverflowError):
            pass

    # If hostname is already an IP literal, validate directly
    try:
        ip = ipaddress.ip_address(hostname)
        if is_blocked_ip(ip):
            raise SSRFSecurityError(f"Target host '{hostname}' is a blocked IP address.")
        return [str(ip)]
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        # Resolve all addresses (both IPv4 and IPv6)
        addr_info = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=3.0,
        )
    except asyncio.TimeoutError:
        raise SSRFSecurityError(f"DNS resolution timed out for '{hostname}'.")
    except Exception as exc:
        raise SSRFSecurityError(f"DNS resolution failed for '{hostname}': {exc}")

    if not addr_info:
        raise SSRFSecurityError(f"No DNS records found for host '{hostname}'.")

    validated_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if is_blocked_ip(ip_str):
            logger.warning("SSRF blocked: host '%s' resolved to unsafe IP '%s'", hostname, ip_str)
            raise SSRFSecurityError(f"Host '{hostname}' resolved to blocked IP address '{ip_str}'.")
        if ip_str not in validated_ips:
            validated_ips.append(ip_str)

    if not validated_ips:
        raise SSRFSecurityError(f"No valid public IP addresses resolved for host '{hostname}'.")

    return validated_ips


def sanitize_domain_for_whois(domain_or_url: str) -> str | None:
    """
    Sanitize and extract a clean domain name for WHOIS lookup.
    Strictly validates against domain character sets to prevent command injection
    or shell metacharacter execution.
    """
    if not domain_or_url or not isinstance(domain_or_url, str):
        return None

    raw = domain_or_url.strip().lower()
    # If a full URL was provided, extract hostname
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            raw = parsed.hostname or ""
        except Exception:
            return None

    # Strip port or path if present
    raw = raw.split("/")[0].split(":")[0].strip()

    # Strip leading www.
    if raw.startswith("www."):
        raw = raw[4:]

    if not raw or len(raw) > 253:
        return None

    # Strict domain regex check
    if not _DOMAIN_REGEX.match(raw):
        return None

    # Disallow IP literals in domain WHOIS
    try:
        ipaddress.ip_address(raw)
        return None
    except ValueError:
        pass

    return raw
