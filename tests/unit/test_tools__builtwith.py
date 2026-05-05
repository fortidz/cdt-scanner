"""Tests for the BuiltWith HTTP wrapper."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx

from cdt.discovery.cache import DiscoveryCache
from cdt.tools import BuiltWithResult, BuiltWithWrapper

FIXTURES = Path(__file__).parent.parent / "fixtures" / "builtwith"
BW_URL = "https://api.builtwith.com/v21/api.json"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


@pytest.fixture
async def wrapper_disabled(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[BuiltWithWrapper]:
    monkeypatch.delenv("BUILTWITH_API_KEY", raising=False)
    w = BuiltWithWrapper(cache=cache)
    try:
        yield w
    finally:
        await w.aclose()


@pytest.fixture
async def wrapper_enabled(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[BuiltWithWrapper]:
    monkeypatch.setenv("BUILTWITH_API_KEY", "secret-key")
    w = BuiltWithWrapper(cache=cache)
    try:
        yield w
    finally:
        await w.aclose()


async def test_builtwith__disabled_when_no_key(
    wrapper_disabled: BuiltWithWrapper,
) -> None:
    """No env key → ``enabled=False`` and the HTTP path is never hit."""

    with respx.mock:
        route = respx.get(BW_URL).mock(return_value=httpx.Response(200, json={}))
        result = await wrapper_disabled.lookup("tipti.market")

    assert isinstance(result, BuiltWithResult)
    assert result.enabled is False
    assert route.call_count == 0


@respx.mock
async def test_builtwith__200_parses_technologies(
    wrapper_enabled: BuiltWithWrapper,
) -> None:
    payload = _load("api_response_tipti.json")
    respx.get(BW_URL).mock(return_value=httpx.Response(200, json=payload))

    result = await wrapper_enabled.lookup("tipti.market")

    assert result.enabled is True
    names = {t["Name"] for t in result.technologies}
    assert {"Cloudflare", "WordPress", "nginx", "Google Analytics"}.issubset(names)
    # Dedupe across paths — WordPress appears in two paths but only once here.
    assert len([t for t in result.technologies if t["Name"] == "WordPress"]) == 1


@respx.mock
async def test_builtwith__cache_hit_skips_http(
    cache: DiscoveryCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BUILTWITH_API_KEY", "secret-key")
    cache.set(
        "builtwith",
        "lookup::tipti.market",
        {
            "domain": "tipti.market",
            "enabled": True,
            "technologies": [{"Name": "Cached"}],
            "error": None,
        },
    )

    w = BuiltWithWrapper(cache=cache)
    try:
        route = respx.get(BW_URL).mock(return_value=httpx.Response(200, json={}))
        result = await w.lookup("tipti.market")
    finally:
        await w.aclose()

    assert result.technologies == [{"Name": "Cached"}]
    assert route.call_count == 0


@respx.mock
async def test_builtwith__error_captured_on_5xx(
    wrapper_enabled: BuiltWithWrapper,
) -> None:
    respx.get(BW_URL).mock(return_value=httpx.Response(503, text="upstream"))
    result = await wrapper_enabled.lookup("acme.example")

    assert result.enabled is True
    assert result.error == "HTTP 503"
    assert result.technologies == []


@respx.mock
async def test_builtwith__429_logged_as_quota(
    wrapper_enabled: BuiltWithWrapper,
) -> None:
    respx.get(BW_URL).mock(return_value=httpx.Response(429, json={"error": "rate"}))
    result = await wrapper_enabled.lookup("acme.example")

    assert result.error == "HTTP 429"
