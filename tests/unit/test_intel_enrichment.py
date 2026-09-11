"""
tests/unit/test_intel_enrichment.py
──────────────────────────────────────
Sprint 4: Unit tests for Centralized Network Security, SSRF defense,
WHOIS sanitization, TLS inspection, and redirect chain analysis.

All external network operations (DNS, socket, HTTP, WHOIS) are deterministically
mocked. Zero real outbound requests are made during test execution.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.core.security_network import (
    SSRFSecurityError,
    is_blocked_ip,
    resolve_and_validate_host,
    sanitize_domain_for_whois,
    validate_target_url,
)
from backend.services.intel_enrichment import (
    enrich_scan,
    follow_redirect_chain,
    get_domain_age_days,
    get_ip_geolocation,
    get_tls_info,
)


# ── 1. SSRF IP & Network Blocklist Tests ──────────────────────────────────────

class TestSSRFBlocklist:
    """Verify that all dangerous, internal, multicast, and metadata addresses are blocked."""

    @pytest.mark.parametrize(
        "ip_str",
        [
            # Loopback & Localhost
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",
            "0.0.0.0",
            # RFC 1918 Private
            "10.0.0.1",
            "10.254.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.1.254",
            # Cloud Metadata & Link-Local (CRITICAL)
            "169.254.169.254",
            "169.254.0.1",
            "169.254.255.255",
            # Carrier-Grade NAT (RFC 6598)
            "100.64.0.1",
            "100.127.255.255",
            # Multicast & Broadcast
            "224.0.0.1",
            "239.255.255.255",
            "255.255.255.255",
            # IPv6
            "::1",
            "::",
            "fe80::1",
            "fe80::dead:beef",
            "fc00::1",
            "fd00::1",
            "ff02::1",
            # IPv4-Mapped IPv6
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
        ],
    )
    def test_blocks_dangerous_addresses(self, ip_str: str):
        assert is_blocked_ip(ip_str) is True

    @pytest.mark.parametrize(
        "public_ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "142.250.190.46",
            "2606:4700:4700::1111",
        ],
    )
    def test_allows_valid_public_addresses(self, public_ip: str):
        assert is_blocked_ip(public_ip) is False

    def test_malformed_ip_fails_closed(self):
        assert is_blocked_ip("999.999.999.999") is True
        assert is_blocked_ip("not_an_ip") is True
        assert is_blocked_ip("") is True


# ── 2. URL Scheme & Target Validation Tests ───────────────────────────────────

class TestTargetURLValidation:
    def test_valid_http_and_https_urls(self):
        scheme, host, port, path = validate_target_url("https://example.com/login?q=1")
        assert scheme == "https"
        assert host == "example.com"
        assert port == 443
        assert path == "/login?q=1"

        scheme, host, port, path = validate_target_url("http://example.org:8080/test")
        assert scheme == "http"
        assert host == "example.org"
        assert port == 8080
        assert path == "/test"

    @pytest.mark.parametrize(
        "unsafe_url",
        [
            "file:///etc/passwd",
            "ftp://ftp.example.com",
            "gopher://gopher.example.com",
            "javascript:alert(1)",
            "data:text/html,test",
            "dict://127.0.0.1:11211",
            "https://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/status",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0/",
            "https://user:password@example.com/",
            "http://example.com:99999/",
            "http://example.com:invalid/",
            "",
            "not_a_url",
        ],
    )
    def test_rejects_unsafe_schemes_and_ip_literals(self, unsafe_url: str):
        with pytest.raises(SSRFSecurityError):
            validate_target_url(unsafe_url)


# ── 3. DNS Resolution & Anti-Rebinding Tests ─────────────────────────────────

class TestDNSResolutionSecurity:
    def test_public_hostname_resolves_and_validates(self):
        async def _test():
            fake_addrinfo = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
            ]
            with patch("asyncio.get_running_loop") as mock_loop_fn:
                mock_loop = MagicMock()
                mock_loop.getaddrinfo = AsyncMock(return_value=fake_addrinfo)
                mock_loop_fn.return_value = mock_loop

                ips = await resolve_and_validate_host("example.com")
                assert "93.184.216.34" in ips
                assert "93.184.216.35" in ips

        asyncio.run(_test())

    def test_hostname_resolving_to_private_ip_is_rejected(self):
        async def _test():
            # DNS answer includes a safe IP AND a private loopback IP (DNS rebinding simulation)
            fake_addrinfo = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]
            with patch("asyncio.get_running_loop") as mock_loop_fn:
                mock_loop = MagicMock()
                mock_loop.getaddrinfo = AsyncMock(return_value=fake_addrinfo)
                mock_loop_fn.return_value = mock_loop

                with pytest.raises(SSRFSecurityError, match="blocked IP address"):
                    await resolve_and_validate_host("rebind.attacker.com")

        asyncio.run(_test())

    def test_metadata_resolution_is_rejected(self):
        async def _test():
            fake_addrinfo = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0)),
            ]
            with patch("asyncio.get_running_loop") as mock_loop_fn:
                mock_loop = MagicMock()
                mock_loop.getaddrinfo = AsyncMock(return_value=fake_addrinfo)
                mock_loop_fn.return_value = mock_loop

                with pytest.raises(SSRFSecurityError, match="blocked IP address"):
                    await resolve_and_validate_host("aws-meta.attacker.com")

        asyncio.run(_test())

    def test_dns_failure_fails_closed(self):
        async def _test():
            with patch("asyncio.get_running_loop") as mock_loop_fn:
                mock_loop = MagicMock()
                mock_loop.getaddrinfo = AsyncMock(side_effect=socket.gaierror("Name or service not known"))
                mock_loop_fn.return_value = mock_loop

                with pytest.raises(SSRFSecurityError, match="DNS resolution failed"):
                    await resolve_and_validate_host("nonexistent.invalid")

        asyncio.run(_test())


# ── 4. WHOIS Sanitization & Execution Tests ───────────────────────────────────

class TestWHOISDomainSanitization:
    @pytest.mark.parametrize(
        "valid_input,expected_domain",
        [
            ("https://example.com/path", "example.com"),
            ("http://www.evil-phish.xyz:8080/test", "evil-phish.xyz"),
            ("sub.domain.co.uk", "sub.domain.co.uk"),
            ("target-brand.com", "target-brand.com"),
        ],
    )
    def test_sanitizes_valid_domains(self, valid_input: str, expected_domain: str):
        assert sanitize_domain_for_whois(valid_input) == expected_domain

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "example.com; rm -rf /",
            "example.com | cat /etc/passwd",
            "example.com `whoami`",
            "example.com $(reboot)",
            "127.0.0.1",
            "169.254.169.254",
            "invalid domain name with spaces.com",
            "-leading-hyphen.com",
            "trailing-hyphen-.com",
            "",
            "   ",
        ],
    )
    def test_rejects_malicious_and_non_domain_inputs(self, malicious_input: str):
        assert sanitize_domain_for_whois(malicious_input) is None

    def test_whois_lookup_calculates_correct_domain_age(self):
        async def _test():
            fake_whois = MagicMock()
            # Domain registered 2 years ago (730 days)
            registered_dt = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year - 2)
            fake_whois.creation_date = registered_dt

            fake_module = MagicMock()
            fake_module.whois.return_value = fake_whois

            with patch.dict("sys.modules", {"whois": fake_module}):
                age = await get_domain_age_days("https://example.com/path")
                assert age is not None
                assert 720 <= age <= 740

        asyncio.run(_test())

    def test_whois_lookup_timeout_fails_open(self):
        async def _test():
            with patch("backend.services.intel_enrichment._sync_whois_lookup", side_effect=Exception("Timeout")):
                age = await get_domain_age_days("https://slow-whois-server.com")
                assert age is None

        asyncio.run(_test())

    def test_whois_lookup_handles_string_date(self):
        async def _test():
            fake_whois = MagicMock()
            # Registry returns string date format
            fake_whois.creation_date = "2020-05-15 12:00:00"

            fake_module = MagicMock()
            fake_module.whois.return_value = fake_whois

            with patch.dict("sys.modules", {"whois": fake_module}):
                age = await get_domain_age_days("https://example.com/path")
                assert age is not None
                assert age > 1000

        asyncio.run(_test())

    def test_whois_lookup_handles_malformed_string_date(self):
        async def _test():
            fake_whois = MagicMock()
            fake_whois.creation_date = "not-a-valid-date-string"

            fake_module = MagicMock()
            fake_module.whois.return_value = fake_whois

            with patch.dict("sys.modules", {"whois": fake_module}):
                age = await get_domain_age_days("https://example.com/path")
                assert age is None

        asyncio.run(_test())


# ── 5. TLS Certificate Inspection Tests ───────────────────────────────────────

class TestTLSInspection:
    def test_tls_rejects_http_url(self):
        async def _test():
            res = await get_tls_info("http://example.com")
            assert res is not None
            assert res["valid"] is False
            assert "Not an HTTPS URL" in res.get("reason", "")

        asyncio.run(_test())

    def test_tls_rejects_private_ip(self):
        async def _test():
            res = await get_tls_info("https://127.0.0.1:8443")
            assert res is not None
            assert res["valid"] is False
            assert "SSRF blocked" in res.get("reason", "")

        asyncio.run(_test())

    def test_tls_inspects_valid_certificate(self):
        async def _test():
            fake_cert = {
                "notAfter": "Dec 31 23:59:59 2030 GMT",
                "issuer": (("organizationName", "DigiCert Inc"),),
                "subject": (("commonName", "example.com"),),
            }
            with patch("backend.services.intel_enrichment.resolve_and_validate_host", return_value=["93.184.216.34"]):
                with patch("backend.services.intel_enrichment._sync_tls_inspect", return_value={
                    "valid": True,
                    "issuer": "DigiCert Inc",
                    "subject": "example.com",
                    "expires_at": "2030-12-31T23:59:59+00:00",
                    "days_to_expiry": 1500,
                }):
                    res = await get_tls_info("https://example.com")
                    assert res is not None
                    assert res["valid"] is True
                    assert res["issuer"] == "DigiCert Inc"

        asyncio.run(_test())


# ── 6. Redirect Chain Bounded Execution Tests ─────────────────────────────────

class TestRedirectChainSecurity:
    def test_single_hop_returns_original_url(self):
        async def _test():
            fake_resp = MagicMock()
            fake_resp.is_redirect = False
            fake_resp.aiter_bytes = MagicMock(return_value=aiter_bytes_helper([b"<html>clean</html>"]))

            with patch("backend.services.intel_enrichment.resolve_and_validate_host", return_value=["93.184.216.34"]):
                with patch("httpx.AsyncClient.stream") as mock_stream:
                    mock_stream.return_value.__aenter__.return_value = fake_resp
                    result = await follow_redirect_chain("https://example.com")
                    assert result["redirect_count"] == 0
                    assert result["final_url"] == "https://example.com"
                    assert len(result["chain"]) == 1

        asyncio.run(_test())

    def test_redirect_halts_on_ssrf_destination(self):
        async def _test():
            # First hop is valid redirect to internal metadata
            fake_resp1 = MagicMock()
            fake_resp1.is_redirect = True
            fake_resp1.headers = {"location": "http://169.254.169.254/latest/meta-data/"}
            fake_resp1.aiter_bytes = MagicMock(return_value=aiter_bytes_helper([b"redirect"]))

            with patch("backend.services.intel_enrichment.resolve_and_validate_host", return_value=["93.184.216.34"]):
                with patch("httpx.AsyncClient.stream") as mock_stream:
                    mock_stream.return_value.__aenter__.return_value = fake_resp1
                    result = await follow_redirect_chain("https://example.com")
                    # Second hop to 169.254 is rejected by SSRF layer
                    assert result["redirect_count"] == 1
                    assert result["final_url"] == "http://169.254.169.254/latest/meta-data/"

        asyncio.run(_test())

    def test_redirect_enforces_max_3_hops(self):
        async def _test():
            def make_redirect_resp(target_url: str):
                r = MagicMock()
                r.is_redirect = True
                r.headers = {"location": target_url}
                r.aiter_bytes = MagicMock(return_value=aiter_bytes_helper([b"hop"]))
                return r

            responses = [
                make_redirect_resp("https://example.com/hop1"),
                make_redirect_resp("https://example.com/hop2"),
                make_redirect_resp("https://example.com/hop3"),
                make_redirect_resp("https://example.com/hop4"),  # Should never reach 4th hop
            ]

            with patch("backend.services.intel_enrichment.resolve_and_validate_host", return_value=["93.184.216.34"]):
                with patch("httpx.AsyncClient.stream") as mock_stream:
                    mock_stream.return_value.__aenter__.side_effect = responses
                    result = await follow_redirect_chain("https://example.com")
                    # Must be capped at exactly MAX_REDIRECTS (3)
                    assert result["redirect_count"] == 3

        asyncio.run(_test())

    def test_redirect_loop_halts_immediately(self):
        async def _test():
            def make_redirect_resp(target_url: str):
                r = MagicMock()
                r.is_redirect = True
                r.headers = {"location": target_url}
                r.aiter_bytes = MagicMock(return_value=aiter_bytes_helper([b"hop"]))
                return r

            # example.com -> example.com (circular redirect)
            responses = [make_redirect_resp("https://example.com")]

            with patch("backend.services.intel_enrichment.resolve_and_validate_host", return_value=["93.184.216.34"]):
                with patch("httpx.AsyncClient.stream") as mock_stream:
                    mock_stream.return_value.__aenter__.side_effect = responses
                    result = await follow_redirect_chain("https://example.com")
                    assert result["redirect_count"] == 0
                    assert len(result["chain"]) == 1

        asyncio.run(_test())


# ── 7. IP Geolocation Security Tests ──────────────────────────────────────────

class TestIPInfoSecurity:
    def test_disabled_when_api_key_missing(self):
        async def _test():
            with patch("backend.core.config.settings.IPINFO_API_KEY", ""):
                res = await get_ip_geolocation("https://example.com")
                assert res is None

        asyncio.run(_test())

    def test_uses_authorization_bearer_header_never_query_param(self):
        async def _test():
            with patch("backend.core.config.settings.IPINFO_API_KEY", "secret_token_123"):
                with patch("backend.services.intel_enrichment.resolve_and_validate_host", return_value=["93.184.216.34"]):
                    with patch("httpx.AsyncClient.get") as mock_get:
                        fake_res = MagicMock(status_code=200)
                        fake_res.json.return_value = {
                            "ip": "93.184.216.34",
                            "city": "Los Angeles",
                            "region": "California",
                            "country": "US",
                            "org": "AS15133 EdgeCast Networks",
                        }
                        mock_get.return_value = fake_res

                        data = await get_ip_geolocation("https://example.com")
                        assert data is not None
                        assert data["country"] == "US"

                        # Verify Authorization header was passed
                        args, kwargs = mock_get.call_args
                        assert "headers" in kwargs
                        assert kwargs["headers"]["Authorization"] == "Bearer secret_token_123"
                        # Verify secret token is NOT in URL
                        assert "secret_token" not in args[0]

        asyncio.run(_test())


# ── 8. Master Orchestrator Tests ──────────────────────────────────────────────

class TestMasterEnrichmentOrchestrator:
    def test_enrich_scan_returns_structured_payload(self):
        async def _test():
            with patch("backend.services.intel_enrichment.get_domain_age_days", return_value=365):
                with patch("backend.services.intel_enrichment.get_tls_info", return_value={"valid": True}):
                    with patch("backend.services.intel_enrichment.follow_redirect_chain", return_value={
                        "redirect_count": 0,
                        "final_url": "https://example.com",
                        "chain": ["https://example.com"],
                    }):
                        with patch("backend.services.intel_enrichment.get_ip_geolocation", return_value=None):
                            res = await enrich_scan("https://example.com")
                            assert res["domain_age_days"] == 365
                            assert res["tls_info"]["valid"] is True
                            assert res["redirect_count"] == 0
                            assert res["final_url"] == "https://example.com"
                            assert "enrichment_ms" in res

        asyncio.run(_test())

    def test_enrich_scan_rejects_blocked_url_immediately(self):
        async def _test():
            res = await enrich_scan("http://127.0.0.1:8000/admin")
            assert res.get("blocked") is True
            assert res["redirect_count"] == 0

        asyncio.run(_test())


# ── Helper for async byte generator ───────────────────────────────────────────

async def aiter_bytes_helper(chunks: list[bytes]):
    for c in chunks:
        yield c
