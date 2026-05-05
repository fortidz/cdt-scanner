"""Tests for the browser-tier scanner — GET, redirects, robots, TLS."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from cdt.scan.browser import BrowserScanner
from cdt.scan.models import TLSInfo

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(rel: str) -> dict:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


@pytest.fixture
async def scanner() -> AsyncIterator[BrowserScanner]:
    s = BrowserScanner(timeout_sec=2.0)
    try:
        yield s
    finally:
        await s.aclose()


@respx.mock
async def test_fetch__200_with_headers_and_body(scanner: BrowserScanner) -> None:
    fixture = _load("http/headers/nginx_clean_response.json")
    respx.get("https://acme.example/").mock(
        return_value=httpx.Response(
            fixture["status"],
            headers=fixture["headers"],
            text=fixture["body"],
        )
    )

    result = await scanner.fetch("https://acme.example/")

    assert result.status == 200
    assert result.headers["server"] == "nginx/1.24.0"
    assert "Hello" in result.body_snippet
    assert result.error is None
    assert result.body_size > 0


@respx.mock
async def test_fetch__redirect_chain_captured(scanner: BrowserScanner) -> None:
    respx.get("https://acme.example/").mock(
        return_value=httpx.Response(301, headers={"location": "https://acme.example/new"})
    )
    respx.get("https://acme.example/new").mock(
        return_value=httpx.Response(
            302, headers={"location": "https://www.acme.example/final"}
        )
    )
    respx.get("https://www.acme.example/final").mock(
        return_value=httpx.Response(200, text="<html>final</html>")
    )

    result = await scanner.fetch("https://acme.example/")

    assert result.status == 200
    assert result.final_url == "https://www.acme.example/final"
    assert len(result.redirects) == 2
    assert "acme.example/new" in result.redirects[1] or "acme.example/" in result.redirects[0]


@respx.mock
async def test_fetch__timeout_triggers_retry_then_raises(
    scanner: BrowserScanner,
) -> None:
    """Three timeouts in a row → tenacity gives up → wrapper records error."""

    respx.get("https://timeout.example/").mock(side_effect=httpx.ConnectTimeout("slow"))

    result = await scanner.fetch("https://timeout.example/")

    assert result.status == 0
    assert result.error is not None
    assert "Timeout" in result.error or "Connect" in result.error


def test_fetch__tls_metadata_extracted() -> None:
    """``parse_tls`` builds a TLSInfo from a stub ``ssl_object`` API."""

    not_before = datetime(2026, 1, 1, tzinfo=UTC)
    not_after = not_before + timedelta(days=90)

    cert = MagicMock()
    cert.subject.rfc4514_string.return_value = "CN=acme.example"
    cert.issuer.rfc4514_string.return_value = "CN=Let's Encrypt R3"
    cert.not_valid_before_utc = not_before
    cert.not_valid_after_utc = not_after

    san_value = MagicMock()
    san_value.__iter__ = lambda self: iter([MagicMock(value="acme.example"),
                                            MagicMock(value="www.acme.example")])
    san_ext = MagicMock()
    san_ext.value = san_value
    cert.extensions.get_extension_for_class.return_value = san_ext

    ssl_obj = MagicMock()
    ssl_obj.version.return_value = "TLSv1.3"
    ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    ssl_obj.getpeercert.return_value = b"\x00\x01\x02"

    from unittest.mock import patch

    with patch("cdt.scan.browser.x509.load_der_x509_certificate", return_value=cert):
        info = BrowserScanner.parse_tls(ssl_obj)

    assert isinstance(info, TLSInfo)
    assert info.version == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.cert_subject == "CN=acme.example"
    assert info.cert_issuer == "CN=Let's Encrypt R3"
    assert info.not_before == not_before
    assert info.not_after == not_after
    assert "acme.example" in info.sans
    assert "www.acme.example" in info.sans


@respx.mock
async def test_fetch_robots__present_returns_body(scanner: BrowserScanner) -> None:
    body = "User-agent: *\nDisallow: /admin\n"
    respx.get("https://acme.example/robots.txt").mock(
        return_value=httpx.Response(200, text=body)
    )

    got = await scanner.fetch_robots("acme.example")
    assert got == body


@respx.mock
async def test_fetch_robots__404_returns_none(scanner: BrowserScanner) -> None:
    respx.get("https://acme.example/robots.txt").mock(
        return_value=httpx.Response(404, text="not found")
    )

    got = await scanner.fetch_robots("acme.example")
    assert got is None


@respx.mock
async def test_fetch__cloudflare_response_headers(scanner: BrowserScanner) -> None:
    fixture = _load("http/headers/cloudflare_response.json")
    respx.get("https://protected.example/").mock(
        return_value=httpx.Response(
            fixture["status"],
            headers=fixture["headers"],
            text=fixture["body"],
        )
    )

    result = await scanner.fetch("https://protected.example/")

    assert result.headers.get("server") == "cloudflare"
    assert "cf-ray" in result.headers
