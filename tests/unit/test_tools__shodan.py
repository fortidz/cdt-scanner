"""Tests for the Shodan wrapper (free InternetDB + optional Host API)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from cdt.discovery.cache import DiscoveryCache
from cdt.tools import ShodanInternetDBResult, ShodanWrapper
from cdt.tools.shodan_wrapper import _INTERNETDB_BASE

FIXTURES = Path(__file__).parent.parent / "fixtures" / "shodan"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


@pytest.fixture
async def wrapper(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[ShodanWrapper]:
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    w = ShodanWrapper(cache=cache)
    try:
        yield w
    finally:
        await w.aclose()


@respx.mock
async def test_internetdb__200_parses_ports_and_vulns(wrapper: ShodanWrapper) -> None:
    payload = _load("internetdb_aws_ec2.json")
    respx.get(f"{_INTERNETDB_BASE}/54.239.28.85").mock(
        return_value=httpx.Response(200, json=payload)
    )

    result = await wrapper.lookup_internetdb("54.239.28.85")

    assert isinstance(result, ShodanInternetDBResult)
    assert result.ports == [22, 80, 443]
    assert "CVE-2021-44228" in result.vulns
    assert "cloud" in result.tags


@respx.mock
async def test_internetdb__404_returns_empty_result(wrapper: ShodanWrapper) -> None:
    respx.get(f"{_INTERNETDB_BASE}/198.51.100.1").mock(
        return_value=httpx.Response(404, json={"detail": "no info"})
    )

    result = await wrapper.lookup_internetdb("198.51.100.1")

    assert result.ports == []
    assert result.vulns == []
    assert result.error is None


async def test_internetdb__cache_hit_skips_http(
    wrapper: ShodanWrapper, cache: DiscoveryCache
) -> None:
    cache.set(
        "shodan_internetdb",
        "internetdb::1.2.3.4",
        {"ip": "1.2.3.4", "ports": [443], "cpes": [], "hostnames": [],
         "tags": [], "vulns": [], "error": None},
    )
    with respx.mock:
        route = respx.get(f"{_INTERNETDB_BASE}/1.2.3.4").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await wrapper.lookup_internetdb("1.2.3.4")

    assert result.ports == [443]
    assert route.call_count == 0


@respx.mock
async def test_internetdb__network_error_returns_error_field(
    wrapper: ShodanWrapper,
) -> None:
    respx.get(f"{_INTERNETDB_BASE}/1.2.3.4").mock(
        side_effect=httpx.ConnectError("nope")
    )

    result = await wrapper.lookup_internetdb("1.2.3.4")

    assert result.error is not None
    assert result.ports == []


async def test_host_api__disabled_when_no_key(wrapper: ShodanWrapper) -> None:
    """No SHODAN_API_KEY in the env → ``enabled=False`` and no library call."""

    with patch("cdt.tools.shodan_wrapper._run_shodan_host") as spy:
        result = await wrapper.lookup_host("1.2.3.4")

    assert result.enabled is False
    assert result.asn is None
    spy.assert_not_called()


async def test_host_api__enabled_with_key_returns_host_data(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "secret")
    payload = _load("host_api_full.json")

    w = ShodanWrapper(cache=cache)
    try:
        with patch(
            "cdt.tools.shodan_wrapper._run_shodan_host", return_value=payload
        ):
            result = await w.lookup_host("104.16.0.1")
    finally:
        await w.aclose()

    assert result.enabled is True
    assert result.asn == 13335
    assert result.asn_org == "Cloudflare, Inc."
    assert len(result.banners) == 2
    assert result.last_update is not None


async def test_host_api__quota_exceeded_logged(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "secret")
    w = ShodanWrapper(cache=cache)
    try:
        with patch(
            "cdt.tools.shodan_wrapper._run_shodan_host",
            side_effect=RuntimeError("API rate limit reached"),
        ):
            result = await w.lookup_host("1.2.3.4")
    finally:
        await w.aclose()

    assert result.enabled is True
    assert result.error is not None
    assert "rate" in result.error.lower()


async def test_host_api__cache_hit_skips_call(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "secret")
    cache.set(
        "shodan_host",
        "host::5.6.7.8",
        {
            "ip": "5.6.7.8",
            "enabled": True,
            "asn": 13335,
            "asn_org": "Cloudflare",
            "isp": "Cloudflare",
            "banners": [],
            "last_update": None,
            "error": None,
        },
    )

    w = ShodanWrapper(cache=cache)
    try:
        with patch("cdt.tools.shodan_wrapper._run_shodan_host") as spy:
            result = await w.lookup_host("5.6.7.8")
    finally:
        await w.aclose()

    assert result.asn == 13335
    spy.assert_not_called()


@respx.mock
async def test_internetdb__bad_json_records_error(wrapper: ShodanWrapper) -> None:
    """A 200 with malformed body becomes ``error='invalid_json'``."""

    respx.get(f"{_INTERNETDB_BASE}/9.9.9.9").mock(
        return_value=httpx.Response(200, content=b"not json")
    )
    result = await wrapper.lookup_internetdb("9.9.9.9")

    assert result.error == "invalid_json"
