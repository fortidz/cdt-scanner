"""Coverage tests for browser.py edge cases (TLS, robots failures, encoding)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from cdt.scan.browser import BrowserScanner, _extract_tls, _parse_ssl_object


@pytest.fixture
async def scanner() -> AsyncIterator[BrowserScanner]:
    s = BrowserScanner(timeout_sec=2.0)
    try:
        yield s
    finally:
        await s.aclose()


def test_extract_tls__no_network_stream_returns_none() -> None:
    response = MagicMock()
    response.extensions = {}
    assert _extract_tls(response) is None


def test_extract_tls__no_ssl_object_returns_none() -> None:
    stream = MagicMock()
    stream.get_extra_info.return_value = None
    response = MagicMock()
    response.extensions = {"network_stream": stream}
    assert _extract_tls(response) is None


def test_parse_ssl_object__no_peer_cert_returns_partial_info() -> None:
    """Version + cipher are populated even when ``getpeercert`` returns empty."""

    ssl_obj = MagicMock()
    ssl_obj.version.return_value = "TLSv1.2"
    ssl_obj.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
    ssl_obj.getpeercert.return_value = b""

    info = _parse_ssl_object(ssl_obj)
    assert info.version == "TLSv1.2"
    assert info.cipher == "ECDHE-RSA-AES256-GCM-SHA384"
    assert info.cert_subject is None


def test_parse_ssl_object__bad_der_falls_through() -> None:
    """Garbage DER bytes don't crash — TLSInfo just lacks the cert details."""

    ssl_obj = MagicMock()
    ssl_obj.version.return_value = None
    ssl_obj.cipher.return_value = None
    ssl_obj.getpeercert.return_value = b"\x00\x01"

    with patch(
        "cdt.scan.browser.x509.load_der_x509_certificate",
        side_effect=ValueError("bad der"),
    ):
        info = _parse_ssl_object(ssl_obj)

    assert info.version is None
    assert info.cert_subject is None


@respx.mock
async def test_fetch_robots__network_error_returns_none(
    scanner: BrowserScanner,
) -> None:
    respx.get("https://acme.example/robots.txt").mock(
        side_effect=httpx.ConnectError("nope")
    )
    assert await scanner.fetch_robots("acme.example") is None


@respx.mock
async def test_fetch_robots__500_returns_none(scanner: BrowserScanner) -> None:
    respx.get("https://acme.example/robots.txt").mock(
        return_value=httpx.Response(503, text="bad")
    )
    assert await scanner.fetch_robots("acme.example") is None


@respx.mock
async def test_fetch__http_error_other_than_timeout(scanner: BrowserScanner) -> None:
    """A non-timeout HTTP error is captured into the error envelope."""

    respx.get("https://acme.example/").mock(
        side_effect=httpx.RemoteProtocolError("bad framing")
    )
    result = await scanner.fetch("https://acme.example/")
    assert result.status == 0
    assert result.error is not None
