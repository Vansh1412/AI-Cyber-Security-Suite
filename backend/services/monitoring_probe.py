"""
backend/services/monitoring_probe.py
────────────────────────────────────
Sprint 5 Phase 5B: SSRF-Safe Network Monitoring Probe.

Performs outbound HTTP/HTTPS monitoring checks under strict security invariants:
  1. Complete pre-execution SSRF validation via backend.core.security_network.
  2. DNS resolution of all A/AAAA records (fail-closed if any record is unsafe).
  3. IP-pinning: TCP socket connects strictly to the validated public IP address.
  4. Preserves target hostname for HTTP Host header, TLS SNI, and certificate validation.
  5. Enforces verify=True (never bypassed, never verified against raw IP).
  6. Zero secondary DNS lookups on connection (immune to DNS rebinding TOCTOU).
  7. Bounded redirect chain traversal (max 3 hops) with full re-validation per hop.
  8. Streaming response body with hard 50 KB ceiling.
  9. Sanitized diagnostic details (no tokens, passwords, cookies, or raw bodies).
  10. Strict timeout hierarchy (per-hop and aggregate 20.0s ceiling).
"""

from __future__ import annotations

import asyncio
import os
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse

import httpcore
import httpx

from backend.core.security_network import (
    SSRFSecurityError,
    is_blocked_ip,
    resolve_and_validate_host,
    validate_target_url,
)
from src.utils.logger import logger

# ── Configuration Invariants ───────────────────────────────────────────────────

MAX_URL_LENGTH: int = 2048
MAX_REDIRECTS: int = 3
MAX_BODY_BYTES: int = 51200  # 50 KB hard cutoff

# Timeouts (in seconds)
DNS_TIMEOUT_S: float = 1.5
HTTP_CONNECT_TIMEOUT_S: float = 2.0
HTTP_READ_TIMEOUT_S: float = 3.0
PROBE_WALL_CLOCK_BUDGET: float = 20.0

DEFAULT_ALLOWED_PORTS: set[int] = {80, 443}


def _get_allowed_ports() -> set[int]:
    """Return configured allowed ports, defaulting strictly to 80 and 443."""
    env_val = os.getenv("MONITORING_ALLOWED_PORTS", "")
    if env_val.strip():
        ports: set[int] = set()
        for p in env_val.split(","):
            p_clean = p.strip()
            if p_clean.isdigit():
                ports.add(int(p_clean))
        if ports:
            return ports
    return DEFAULT_ALLOWED_PORTS


# ── Failure Taxonomy ───────────────────────────────────────────────────────────

class ProbeFailureCategory(str, Enum):
    SSRF_BLOCKED = "SSRF_BLOCKED"
    DNS_FAILURE = "DNS_FAILURE"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    TLS_VALIDATION_FAILURE = "TLS_VALIDATION_FAILURE"
    HTTP_CLIENT_ERROR = "HTTP_CLIENT_ERROR"
    HTTP_SERVER_ERROR = "HTTP_SERVER_ERROR"
    REDIRECT_LIMIT = "REDIRECT_LIMIT"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ProbeResult:
    """Sanitized outcome of an outbound monitoring probe."""

    success: bool
    status_code: int | None = None
    final_url: str = ""
    redirect_count: int = 0
    tls_valid: bool | None = None
    latency_ms: float = 0.0
    body_sample: str = ""
    failure_category: ProbeFailureCategory | None = None
    error_message: str | None = None


# ── Pinned Transport Layer ────────────────────────────────────────────────────

class PinnedIPBackend(httpcore.AsyncNetworkBackend):
    """
    Decouples TCP connection destination from TLS identity & certificate validation.

    Ensures:
      - TCP socket connects directly to self._pinned_ip (eliminating DNS rebinding).
      - TLS SNI extension transmits the original hostname.
      - Certificate verification strictly checks the original hostname.
      - HTTP Host header transmits the original hostname.
    """

    def __init__(self, pinned_ip: str):
        self._default = httpcore.AnyIOBackend()
        self._pinned_ip = pinned_ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        # Override destination host with the validated pinned IP address
        return await self._default.connect_tcp(
            host=self._pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args, **kwargs):
        return await self._default.connect_unix_socket(*args, **kwargs)

    async def sleep(self, seconds: float):
        await self._default.sleep(seconds)


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """
    httpx.AsyncHTTPTransport subclass that injects PinnedIPBackend into the underlying
    httpcore connection pool while keeping standard certificate verification enabled.
    """

    def __init__(self, pinned_ip: str, **kwargs):
        if kwargs.get("verify") is False:
            raise SSRFSecurityError("Insecure TLS (verify=False) is strictly prohibited.")
        super().__init__(**kwargs)
        self._pool._network_backend = PinnedIPBackend(pinned_ip)


# ── Monitoring Probe Service ──────────────────────────────────────────────────

class MonitoringProbe:
    """
    SSRF-safe network probe executing bounded HTTP/HTTPS monitoring checks.
    """

    def __init__(self, ssl_context: ssl.SSLContext | None = None) -> None:
        self.user_agent: str = "AI-Cyber-Security-Suite/5.0 (+https://internal.security)"
        self.ssl_context: ssl.SSLContext | None = ssl_context

    def _validate_url_syntax(self, url: str) -> tuple[str, str, int, str]:
        """
        Syntactically validate URL length, scheme, userinfo, and port.
        Raises SSRFSecurityError if invalid.
        """
        if not url or not isinstance(url, str):
            raise SSRFSecurityError("Target URL cannot be empty.")

        url_clean = url.strip()
        if len(url_clean) > MAX_URL_LENGTH:
            raise SSRFSecurityError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.")

        # Disallow userinfo / embedded credentials
        parsed = urlparse(url_clean)
        if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
            raise SSRFSecurityError("URLs containing embedded credentials (userinfo) are prohibited.")

        scheme, hostname, port, path_and_query = validate_target_url(url_clean)

        # Check port restrictions
        allowed_ports = _get_allowed_ports()
        if port not in allowed_ports:
            raise SSRFSecurityError(
                f"Prohibited target port {port}. Allowed ports are: {sorted(list(allowed_ports))}."
            )

        # Detect octal IP representations (e.g. 0177.0.0.1 or 017700000001)
        if self._is_octal_ip(hostname):
            raise SSRFSecurityError(f"Direct IP access to blocked address '{hostname}' rejected.")

        return scheme, hostname, port, path_and_query

    @staticmethod
    def _is_octal_ip(hostname: str) -> bool:
        """Detect and reject octal IP representations targeting private/loopback ranges."""
        parts = hostname.split(".")
        if all(p.isdigit() for p in parts) and any(p.startswith("0") and len(p) > 1 for p in parts):
            try:
                val = [int(p, 8) for p in parts]
                if len(val) == 4 and all(0 <= v <= 255 for v in val):
                    ip_str = ".".join(str(v) for v in val)
                    return is_blocked_ip(ip_str)
            except ValueError:
                pass
        if hostname.startswith("0") and hostname.isdigit() and len(hostname) > 1:
            try:
                val = int(hostname, 8)
                if 0 <= val <= 0xFFFFFFFF:
                    import ipaddress
                    ip = ipaddress.IPv4Address(val)
                    return is_blocked_ip(ip)
            except (ValueError, OverflowError):
                pass
        return False

    async def _resolve_and_pin_host(self, hostname: str) -> str:
        """
        Resolve all A/AAAA records for hostname through security_network.
        Fail-closed if any resolved IP is blocked or if resolution times out.
        Returns the pinned IP string.
        """
        try:
            validated_ips = await asyncio.wait_for(
                resolve_and_validate_host(hostname),
                timeout=DNS_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            raise SSRFSecurityError(f"DNS resolution timed out for '{hostname}'.")
        except SSRFSecurityError:
            raise
        except Exception as exc:
            raise SSRFSecurityError(f"DNS resolution failed for '{hostname}': {exc}")

        if not validated_ips:
            raise SSRFSecurityError(f"No valid public IP addresses resolved for host '{hostname}'.")

        return validated_ips[0]

    async def probe(self, initial_url: str) -> ProbeResult:
        """
        Execute an end-to-end SSRF-safe probe against initial_url with redirect tracking.
        Enforces outer PROBE_WALL_CLOCK_BUDGET (20.0s) timeout.
        """
        t0 = asyncio.get_running_loop().time()
        try:
            return await asyncio.wait_for(
                self._probe_inner(initial_url, t0),
                timeout=PROBE_WALL_CLOCK_BUDGET,
            )
        except asyncio.TimeoutError:
            latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
            logger.warning("[PROBE] Target '%s' exceeded aggregate 20.0s budget", initial_url)
            return ProbeResult(
                success=False,
                final_url=initial_url,
                latency_ms=latency_ms,
                failure_category=ProbeFailureCategory.CONNECTION_TIMEOUT,
                error_message="Aggregate probe execution budget (20.0s) timed out.",
            )

    async def _probe_inner(self, initial_url: str, t0: float) -> ProbeResult:
        """Traverse redirect chain up to MAX_REDIRECTS (3) hops."""
        chain: list[str] = [initial_url]
        current_url = initial_url
        redirect_count = 0

        for _hop_index in range(MAX_REDIRECTS + 1):
            # 1. Syntactic validation of current hop URL
            try:
                scheme, hostname, port, path_and_query = self._validate_url_syntax(current_url)
            except SSRFSecurityError as exc:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=ProbeFailureCategory.SSRF_BLOCKED,
                    error_message=f"SSRF validation failed: {exc}",
                )

            # 2. DNS resolution and IP pinning
            try:
                pinned_ip = await self._resolve_and_pin_host(hostname)
            except SSRFSecurityError as exc:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                cat = (
                    ProbeFailureCategory.DNS_FAILURE
                    if "DNS" in str(exc)
                    else ProbeFailureCategory.SSRF_BLOCKED
                )
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=cat,
                    error_message=f"SSRF/DNS resolution failed: {exc}",
                )

            # 3. Construct pinned transport
            verify_arg: bool | ssl.SSLContext = self.ssl_context if self.ssl_context is not None else True
            if verify_arg is False:
                raise SSRFSecurityError("Insecure TLS (verify=False) is strictly prohibited.")
            transport = PinnedAsyncHTTPTransport(pinned_ip=pinned_ip, verify=verify_arg)
            headers = {
                "Host": hostname if port in (80, 443) else f"{hostname}:{port}",
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
                "Connection": "close",
            }
            timeout = httpx.Timeout(
                connect=HTTP_CONNECT_TIMEOUT_S,
                read=HTTP_READ_TIMEOUT_S,
                write=2.0,
                pool=2.0,
            )

            # 4. Outbound HTTP request over pinned transport
            try:
                async with (
                    httpx.AsyncClient(
                        transport=transport,
                        verify=verify_arg,
                        follow_redirects=False,
                        timeout=timeout,
                    ) as client,
                    client.stream("GET", current_url, headers=headers) as resp,
                ):
                    # 5. Handle Redirects (3xx)
                        if resp.is_redirect and "location" in resp.headers:
                            if redirect_count >= MAX_REDIRECTS:
                                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                                return ProbeResult(
                                    success=False,
                                    final_url=current_url,
                                    redirect_count=redirect_count,
                                    latency_ms=latency_ms,
                                    failure_category=ProbeFailureCategory.REDIRECT_LIMIT,
                                    error_message=f"Exceeded maximum redirect limit of {MAX_REDIRECTS} hops.",
                                )

                            raw_loc = resp.headers["location"].strip()
                            next_url = urljoin(current_url, raw_loc)

                            # Loop detection
                            if next_url in chain:
                                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                                return ProbeResult(
                                    success=False,
                                    final_url=current_url,
                                    redirect_count=redirect_count,
                                    latency_ms=latency_ms,
                                    failure_category=ProbeFailureCategory.REDIRECT_LIMIT,
                                    error_message=f"Redirect loop detected at '{next_url}'.",
                                )

                            redirect_count += 1
                            current_url = next_url
                            chain.append(next_url)
                            continue  # Loop to next hop

                        # 6. Stream response body up to 50 KB
                        chunks: list[bytes] = []
                        total_bytes = 0
                        async for chunk in resp.aiter_bytes():
                            total_bytes += len(chunk)
                            if total_bytes > MAX_BODY_BYTES:
                                chunks.append(chunk[: MAX_BODY_BYTES - (total_bytes - len(chunk))])
                                break
                            chunks.append(chunk)

                        body_str = b"".join(chunks).decode("utf-8", errors="replace")
                        latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                        is_success = resp.status_code < 400
                        failure_cat = None
                        if not is_success:
                            failure_cat = (
                                ProbeFailureCategory.HTTP_CLIENT_ERROR
                                if resp.status_code < 500
                                else ProbeFailureCategory.HTTP_SERVER_ERROR
                            )

                        return ProbeResult(
                            success=is_success,
                            status_code=resp.status_code,
                            final_url=current_url,
                            redirect_count=redirect_count,
                            tls_valid=(scheme == "https"),
                            latency_ms=latency_ms,
                            body_sample=body_str[:1024],  # Bounded diagnostic sample
                            failure_category=failure_cat,
                            error_message=None if is_success else f"HTTP status {resp.status_code}",
                        )

            except (ssl.SSLCertVerificationError, httpx.ConnectError) as exc:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                err_str = str(exc).lower()
                cause = getattr(exc, "__cause__", None)
                cause_str = str(cause).lower() if cause else ""
                is_tls_failure = (
                    isinstance(exc, ssl.SSLCertVerificationError)
                    or isinstance(cause, ssl.SSLError)
                    or "certificate verify failed" in err_str
                    or "hostname mismatch" in err_str
                    or "certificate verify failed" in cause_str
                    or "hostname mismatch" in cause_str
                )
                if is_tls_failure:
                    return ProbeResult(
                        success=False,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        tls_valid=False,
                        latency_ms=latency_ms,
                        failure_category=ProbeFailureCategory.TLS_VALIDATION_FAILURE,
                        error_message=f"TLS certificate validation failed: {str(exc)[:150]}",
                    )
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=ProbeFailureCategory.HTTP_CLIENT_ERROR,
                    error_message=f"Connection error: {type(exc).__name__}",
                )
            except httpx.ConnectTimeout:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=ProbeFailureCategory.CONNECTION_TIMEOUT,
                    error_message="TCP connection timed out.",
                )
            except httpx.ReadTimeout:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=ProbeFailureCategory.CONNECTION_TIMEOUT,
                    error_message="HTTP response read timed out.",
                )
            except httpx.HTTPError as exc:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=ProbeFailureCategory.HTTP_CLIENT_ERROR,
                    error_message=f"HTTP network error: {type(exc).__name__}",
                )
            except Exception as exc:
                latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
                return ProbeResult(
                    success=False,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    latency_ms=latency_ms,
                    failure_category=ProbeFailureCategory.UNKNOWN,
                    error_message=f"Unexpected probe failure: {type(exc).__name__}",
                )

        latency_ms = round((asyncio.get_running_loop().time() - t0) * 1000, 2)
        return ProbeResult(
            success=False,
            final_url=current_url,
            redirect_count=redirect_count,
            latency_ms=latency_ms,
            failure_category=ProbeFailureCategory.REDIRECT_LIMIT,
            error_message="Exceeded redirect traversal loop.",
        )


# ── Singleton Instance ─────────────────────────────────────────────────────────
monitoring_probe = MonitoringProbe()
