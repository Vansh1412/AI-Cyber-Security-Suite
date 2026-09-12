"""
tests/unit/test_monitoring_probe.py
───────────────────────────────────
Sprint 5 Phase 5B: Comprehensive Unit Tests for MonitoringProbe & Pinned Transport.

Tests all 27 mandatory probe security invariants:
  1. loopback rejection
  2. RFC1918 rejection
  3. link-local rejection
  4. metadata address rejection
  5. IPv4-mapped IPv6 rejection
  6. decimal IP rejection
  7. hexadecimal IP rejection
  8. octal IP rejection
  9. userinfo rejection
  10. invalid port rejection
  11. URL length enforcement
  12. all-A/AAAA resolution validation
  13. DNS failure closed
  14. pinned IP TCP destination
  15. original Host header
  16. original TLS SNI
  17. valid certificate succeeds
  18. mismatched certificate fails
  19. self-signed certificate fails
  20. verify=True remains enforced
  21. no second DNS lookup
  22. redirect revalidation
  23. redirect loop detection
  24. redirect depth >3
  25. response body <=50KB
  26. network timeout
  27. sanitized diagnostics
"""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import patch

import httpcore
import pytest

from backend.core.security_network import SSRFSecurityError
from backend.services.monitoring_probe import (
    MAX_BODY_BYTES,
    MAX_URL_LENGTH,
    MonitoringProbe,
    PinnedAsyncHTTPTransport,
    PinnedIPBackend,
    ProbeFailureCategory,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ── 1-8: IP & Format Rejections ───────────────────────────────────────────────

@pytest.mark.parametrize(
    "blocked_url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.2:80/admin",
    ],
)
async def test_probe_loopback_rejection(blocked_url: str):
    probe = MonitoringProbe()
    res = await probe.probe(blocked_url)
    assert not res.success
    assert res.failure_category in (ProbeFailureCategory.SSRF_BLOCKED, ProbeFailureCategory.DNS_FAILURE)
    assert "SSRF" in (res.error_message or "") or "blocked" in (res.error_message or "")


@pytest.mark.parametrize(
    "rfc1918_url",
    [
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.1/",
        "http://192.168.100.50:80/",
    ],
)
async def test_probe_rfc1918_rejection(rfc1918_url: str):
    probe = MonitoringProbe()
    res = await probe.probe(rfc1918_url)
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED


async def test_probe_link_local_rejection():
    probe = MonitoringProbe()
    res = await probe.probe("http://169.254.1.1/")
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED


async def test_probe_metadata_address_rejection():
    probe = MonitoringProbe()
    res = await probe.probe("http://169.254.169.254/latest/meta-data/")
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED


async def test_probe_ipv4_mapped_ipv6_rejection():
    probe = MonitoringProbe()
    res = await probe.probe("http://[::ffff:127.0.0.1]/")
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED


async def test_probe_decimal_ip_rejection():
    probe = MonitoringProbe()
    # 2130706433 == 127.0.0.1
    res = await probe.probe("http://2130706433/")
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED


async def test_probe_hexadecimal_ip_rejection():
    probe = MonitoringProbe()
    # 0x7f000001 == 127.0.0.1
    res = await probe.probe("http://0x7f000001/")
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED


async def test_probe_octal_ip_rejection():
    probe = MonitoringProbe()
    # 0177.0.0.1 == 127.0.0.1 in octal notation
    res = await probe.probe("http://0177.0.0.1/")
    assert not res.success
    assert res.failure_category in (ProbeFailureCategory.SSRF_BLOCKED, ProbeFailureCategory.DNS_FAILURE)


# ── 9-11: Userinfo, Port & Length Rejections ──────────────────────────────────

@pytest.mark.parametrize(
    "userinfo_url",
    [
        "http://user:password@example.com/",
        "http://admin@example.com/",
        "https://token:@example.com/api",
    ],
)
async def test_probe_userinfo_rejection(userinfo_url: str):
    probe = MonitoringProbe()
    res = await probe.probe(userinfo_url)
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED
    assert "userinfo" in (res.error_message or "").lower() or "credentials" in (res.error_message or "").lower()


@pytest.mark.parametrize("invalid_port", [22, 23, 25, 6379, 5432, 27017, 3306])
async def test_probe_invalid_port_rejection(invalid_port: int):
    probe = MonitoringProbe()
    res = await probe.probe(f"http://example.com:{invalid_port}/")
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED
    assert "port" in (res.error_message or "").lower()


async def test_probe_url_length_enforcement():
    probe = MonitoringProbe()
    long_url = "http://example.com/" + "a" * (MAX_URL_LENGTH + 10)
    res = await probe.probe(long_url)
    assert not res.success
    assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED
    assert "length" in (res.error_message or "").lower()


# ── 12-13: DNS Resolution Validation ──────────────────────────────────────────

async def test_probe_all_a_aaaa_resolution_validation():
    probe = MonitoringProbe()
    # If host resolves to both safe and unsafe IP, must fail closed
    with patch(
        "backend.services.monitoring_probe.resolve_and_validate_host",
        side_effect=SSRFSecurityError("Host resolved to blocked IP address '10.0.0.1'"),
    ):
        res = await probe.probe("http://dual-homed-malicious.com/")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED
        assert "10.0.0.1" in (res.error_message or "")


async def test_probe_dns_failure_closed():
    probe = MonitoringProbe()
    with patch(
        "backend.services.monitoring_probe.resolve_and_validate_host",
        side_effect=SSRFSecurityError("DNS resolution failed for 'nonexistent.xyz': NXDOMAIN"),
    ):
        res = await probe.probe("http://nonexistent.xyz/")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.DNS_FAILURE


# ── 14-16 & 21: Pinned Transport Semantics ────────────────────────────────────

async def test_pinned_transport_tcp_destination_and_no_second_dns():
    """Verify that PinnedIPBackend redirects connect_tcp to pinned IP without second DNS call."""
    captured_host = None
    captured_port = None

    class MockStream(httpcore.AsyncNetworkStream):
        async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

        async def write(self, buffer: bytes, timeout: float | None = None) -> None:
            pass

        async def aclose(self) -> None:
            pass

        async def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None):
            return self

    class InterceptBackend(httpcore.AsyncNetworkBackend):
        async def connect_tcp(self, host: str, port: int, timeout=None, local_address=None, socket_options=None):
            nonlocal captured_host, captured_port
            captured_host = host
            captured_port = port
            return MockStream()

        async def connect_unix_socket(self, *args, **kwargs):
            raise NotImplementedError

        async def sleep(self, seconds: float):
            await asyncio.sleep(0)

    pinned_ip = "93.184.216.34"
    backend = PinnedIPBackend(pinned_ip)
    backend._default = InterceptBackend()

    transport = PinnedAsyncHTTPTransport(pinned_ip="93.184.216.34")
    transport._pool._network_backend = backend

    # Hostname should NOT be resolved again by OS because connect_tcp uses pinned_ip directly
    with patch("socket.getaddrinfo", side_effect=AssertionError("Second DNS lookup occurred!")):
        stream = await backend.connect_tcp("unresolved-domain-test.com", 443)
        assert captured_host == pinned_ip
        assert captured_port == 443
        await stream.aclose()


async def test_pinned_transport_headers_and_sni_preservation():
    probe = MonitoringProbe()
    captured_request = None

    async def mock_resolve(hostname: str):
        return "93.184.216.34"

    with patch.object(probe, "_resolve_and_pin_host", side_effect=mock_resolve):
        # Mock client request execution inside _probe_inner
        class DummyResp:
            status_code = 200
            is_redirect = False
            headers = {"content-type": "text/html"}

            async def aiter_bytes(self):
                yield b"<html>Safe content</html>"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        class MockClient:
            def __init__(self, *args, **kwargs):
                self.transport = kwargs.get("transport")
                self.verify = kwargs.get("verify")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def stream(self, method, url, headers=None):
                nonlocal captured_request
                captured_request = {
                    "url": url,
                    "headers": headers,
                    "transport": self.transport,
                    "verify": self.verify,
                }
                return DummyResp()

        with patch("httpx.AsyncClient", side_effect=MockClient):
            res = await probe.probe("https://example.com/test-path")
            assert res.success
            assert res.status_code == 200
            assert captured_request is not None
            assert captured_request["headers"]["Host"] == "example.com"
            assert captured_request["verify"] is True
            # Confirm pinned transport was injected
            assert isinstance(captured_request["transport"], PinnedAsyncHTTPTransport)
            assert captured_request["transport"]._pool._network_backend._pinned_ip == "93.184.216.34"


# ── 17-20: HTTPS & Certificate Validation ─────────────────────────────────────

async def test_probe_mismatched_certificate_fails():
    probe = MonitoringProbe()
    with (
        patch.object(probe, "_resolve_and_pin_host", return_value="93.184.216.34"),
        patch(
            "httpx.AsyncClient.stream",
            side_effect=ssl.SSLCertVerificationError(
                1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch"
            ),
        ),
    ):
        res = await probe.probe("https://mismatched-cert.com/")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.TLS_VALIDATION_FAILURE
        assert res.tls_valid is False
        assert "certificate validation failed" in (res.error_message or "").lower()


async def test_probe_self_signed_certificate_fails():
    probe = MonitoringProbe()
    with (
        patch.object(probe, "_resolve_and_pin_host", return_value="93.184.216.34"),
        patch(
            "httpx.AsyncClient.stream",
            side_effect=ssl.SSLCertVerificationError(
                1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
            ),
        ),
    ):
        res = await probe.probe("https://self-signed.com/")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.TLS_VALIDATION_FAILURE
        assert res.tls_valid is False


# ── 22-24: Redirect Handling & Loop Detection ─────────────────────────────────

async def test_probe_redirect_revalidation_blocks_private_hop():
    probe = MonitoringProbe()

    # Hop 1: public.com -> redirects to http://192.168.1.1/admin
    async def mock_resolve(hostname: str):
        if hostname == "public.com":
            return ["93.184.216.34"]
        return ["192.168.1.1"]

    class RedirectResp:
        status_code = 302
        is_redirect = True
        headers = {"location": "http://192.168.1.1/admin"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    with (
        patch.object(probe, "_resolve_and_pin_host", side_effect=mock_resolve),
        patch("httpx.AsyncClient.stream", return_value=RedirectResp()),
    ):
        res = await probe.probe("http://public.com/")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.SSRF_BLOCKED
        assert "192.168.1.1" in res.final_url or "SSRF" in (res.error_message or "")


async def test_probe_redirect_loop_detection():
    probe = MonitoringProbe()

    # Loop: http://loop.com/a -> http://loop.com/b -> http://loop.com/a
    class LoopResp:
        def __init__(self, target_url: str):
            self.target_url = target_url
            self.status_code = 302
            self.is_redirect = True

        @property
        def headers(self):
            if "/a" in self.target_url:
                return {"location": "http://loop.com/b"}
            return {"location": "http://loop.com/a"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    with (
        patch.object(probe, "_resolve_and_pin_host", return_value="93.184.216.34"),
        patch(
            "httpx.AsyncClient.stream",
            side_effect=lambda method, url, headers=None: LoopResp(url),
        ),
    ):
        res = await probe.probe("http://loop.com/a")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.REDIRECT_LIMIT
        assert "loop" in (res.error_message or "").lower()


async def test_probe_redirect_depth_limit_exceeded():
    probe = MonitoringProbe()
    hop_counter = 0

    class DeepRedirectResp:
        status_code = 302
        is_redirect = True

        @property
        def headers(self):
            nonlocal hop_counter
            hop_counter += 1
            return {"location": f"http://chain.com/step{hop_counter}"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    with (
        patch.object(probe, "_resolve_and_pin_host", return_value="93.184.216.34"),
        patch("httpx.AsyncClient.stream", return_value=DeepRedirectResp()),
    ):
        res = await probe.probe("http://chain.com/step0")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.REDIRECT_LIMIT
        assert res.redirect_count == 3
        assert "limit" in (res.error_message or "").lower()


# ── 25: Body Size Ceiling ─────────────────────────────────────────────────────

async def test_probe_response_body_size_ceiling():
    probe = MonitoringProbe()

    class LargeBodyResp:
        status_code = 200
        is_redirect = False
        headers = {"content-type": "text/plain"}

        async def aiter_bytes(self):
            # Stream 100 KB in 10 KB chunks
            for _ in range(10):
                yield b"X" * 10240

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    with (
        patch.object(probe, "_resolve_and_pin_host", return_value="93.184.216.34"),
        patch("httpx.AsyncClient.stream", return_value=LargeBodyResp()),
    ):
        res = await probe.probe("http://example.com/large")
        assert res.success
        assert len(res.body_sample.encode("utf-8")) <= MAX_BODY_BYTES


# ── 26-27: Network Timeouts & Sanitization ────────────────────────────────────

async def test_probe_network_timeout_enforcement():
    probe = MonitoringProbe()

    async def slow_probe(*args, **kwargs):
        await asyncio.sleep(0.1)
        return None

    with (
        patch("backend.services.monitoring_probe.PROBE_WALL_CLOCK_BUDGET", 0.02),
        patch.object(probe, "_probe_inner", side_effect=slow_probe),
    ):
        res = await probe.probe("http://slow-target.com/")
        assert not res.success
        assert res.failure_category == ProbeFailureCategory.CONNECTION_TIMEOUT
        assert "timed out" in (res.error_message or "").lower()


async def test_probe_sanitized_diagnostics():
    probe = MonitoringProbe()
    res = await probe.probe("http://user:secret-pass@example.com/path?token=SECRET_JWT")
    assert not res.success
    # Ensure sensitive items are never present in error messages or URLs
    assert "secret-pass" not in (res.error_message or "")
    assert "SECRET_JWT" not in (res.error_message or "")


# ── Real TLS / SNI Cryptographic Verification ─────────────────────────────────

async def test_real_tls_sni_cryptographic_verification(monkeypatch):
    """
    CRITICAL REAL TLS/SNI CRYPTOGRAPHIC VERIFICATION:
    Creates a real local HTTPS server with a certificate for 'test.example'.
    Verifies:
      - URL hostname: test.example
      - TCP destination: 127.0.0.1
      - HTTP Host header: test.example:<port>
      - TLS SNI: test.example
      - Certificate validation: against test.example
      - verify: TRUE
    Then verifies that a server presenting a certificate for 'wrong.example'
    fails with SSLCertVerificationError / TLS_VALIDATION_FAILURE.
    Also verifies verify=False is strictly prohibited.
    """
    import datetime
    import ssl
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from backend.services.monitoring_probe import PinnedAsyncHTTPTransport

    # 1. Generate Root CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def _create_server_cert(san_name: str):
        s_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)
        s_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san_name)]))
            .issuer_name(ca_name)
            .public_key(s_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(san_name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(aki, critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return s_key, s_cert

    k_valid, c_valid = _create_server_cert("test.example")
    k_wrong, c_wrong = _create_server_cert("wrong.example")
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    with (
        tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f_vcert,
        tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f_vkey,
        tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f_wcert,
        tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f_wkey,
    ):
        f_vcert.write(c_valid.public_bytes(serialization.Encoding.PEM))
        f_vcert.flush()
        f_vkey.write(k_valid.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        f_vkey.flush()

        f_wcert.write(c_wrong.public_bytes(serialization.Encoding.PEM))
        f_wcert.flush()
        f_wkey.write(k_wrong.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        f_wkey.flush()

        v_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        v_ssl.load_cert_chain(f_vcert.name, f_vkey.name)

        w_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        w_ssl.load_cert_chain(f_wcert.name, f_wkey.name)

    captured_requests: list[str] = []
    captured_sni: list[str] = []

    def sni_callback(ssl_sock, server_name, initial_context):
        if server_name:
            captured_sni.append(server_name)
        return None

    v_ssl.sni_callback = sni_callback

    async def handle_client(reader, writer):
        data = await reader.read(1024)
        captured_requests.append(data.decode("latin1", errors="replace"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    # Configure client SSL context trusting only our local CA
    client_ssl_ctx = ssl.create_default_context(cadata=ca_pem.decode("ascii"))
    client_ssl_ctx.check_hostname = True
    client_ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    # 1. Start valid HTTPS server for test.example on 127.0.0.1
    server_v = await asyncio.start_server(handle_client, host="127.0.0.1", port=0, ssl=v_ssl)
    port_v = server_v.sockets[0].getsockname()[1]
    monkeypatch.setenv("MONITORING_ALLOWED_PORTS", f"80,443,{port_v}")

    probe_valid = MonitoringProbe(ssl_context=client_ssl_ctx)
    with patch.object(probe_valid, "_resolve_and_pin_host", return_value="127.0.0.1"):
        res_v = await probe_valid.probe(f"https://test.example:{port_v}/test")
        assert res_v.success is True, f"Valid TLS cert must succeed: {res_v.error_message}"
        assert res_v.status_code == 200
        assert res_v.tls_valid is True

        # Explicit assertion on server-side captured SNI extension
        assert captured_sni == ["test.example"], f"Expected SNI 'test.example', got {captured_sni}"

        # Verify HTTP Host header and original hostname preservation
        assert len(captured_requests) >= 1
        host_header = [line for line in captured_requests[0].split("\r\n") if line.lower().startswith("host:")]
        assert len(host_header) == 1
        assert f"test.example:{port_v}" in host_header[0]

    server_v.close()
    await server_v.wait_closed()

    # 2. Start mismatched HTTPS server for wrong.example on 127.0.0.1
    server_w = await asyncio.start_server(handle_client, host="127.0.0.1", port=0, ssl=w_ssl)
    port_w = server_w.sockets[0].getsockname()[1]
    monkeypatch.setenv("MONITORING_ALLOWED_PORTS", f"80,443,{port_v},{port_w}")

    probe_wrong = MonitoringProbe(ssl_context=client_ssl_ctx)
    with patch.object(probe_wrong, "_resolve_and_pin_host", return_value="127.0.0.1"):
        res_w = await probe_wrong.probe(f"https://test.example:{port_w}/test")
        assert res_w.success is False
        assert res_w.failure_category == ProbeFailureCategory.TLS_VALIDATION_FAILURE
        assert res_w.tls_valid is False
        assert "certificate verify failed" in (res_w.error_message or "").lower() or "hostname mismatch" in (res_w.error_message or "").lower()

    server_w.close()
    await server_w.wait_closed()

    # 3. Verify verify=False is strictly rejected
    with pytest.raises(SSRFSecurityError, match="Insecure TLS"):
        PinnedAsyncHTTPTransport(pinned_ip="127.0.0.1", verify=False)
