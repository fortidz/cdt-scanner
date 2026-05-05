"""Tests for the crt.sh-based Expander."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx

from cdt.discovery import DiscoveryCache, Expander, ExpansionResult
from cdt.discovery.expander import ExpanderConfig

FIXTURES = Path(__file__).parent.parent / "fixtures" / "crt_sh"
CRT_SH_URL = "https://crt.sh/"


def _load(name: str) -> list[dict[str, object]]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


@pytest.fixture
async def expander(cache: DiscoveryCache) -> AsyncIterator[Expander]:
    e = Expander(cache=cache)
    try:
        yield e
    finally:
        await e.aclose()


def _mock_alive(host: str) -> None:
    respx.head(f"https://{host}").mock(return_value=httpx.Response(200))


def _mock_dead(host: str) -> None:
    respx.head(f"https://{host}").mock(side_effect=httpx.ConnectError("dead"))


@respx.mock
async def test_expand__filters_mailservers_and_assets(expander: Expander) -> None:
    """mx*, mail*, smtp* and cdn*, static*, assets*, media*, img* are dropped."""

    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(200, json=_load("tipti_market.json"))
    )
    # Mark every realistic productive host as alive; everything else dead.
    for h in ["www", "app", "api", "shop", "portal", "admin", "secure", "tienda", "blog", "press"]:
        _mock_alive(f"{h}.tipti.market")
    # Catch-all for any other host the expander tries: route undefined → respx raises.
    # Mailservers / assets / non-prod must therefore have been filtered before probing.

    result = await expander.expand("tipti.market", max_sites=10)

    for unwanted in (
        "mx.tipti.market",
        "mail.tipti.market",
        "smtp.tipti.market",
        "imap.tipti.market",
        "pop.tipti.market",
        "cdn.tipti.market",
        "static.tipti.market",
        "assets.tipti.market",
        "media.tipti.market",
        "img.tipti.market",
    ):
        assert unwanted not in result.websites


@respx.mock
async def test_expand__drops_non_prod_subdomains(expander: Expander) -> None:
    """Subdomains containing dev/staging/test/uat/qa/sandbox/beta are dropped."""

    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(200, json=_load("tipti_market.json"))
    )
    for h in ["www", "app", "api", "shop", "portal", "admin", "secure", "tienda", "blog", "press"]:
        _mock_alive(f"{h}.tipti.market")

    result = await expander.expand("tipti.market", max_sites=20)

    for unwanted in (
        "api.dev.tipti.market",
        "staging.tipti.market",
        "test.tipti.market",
        "uat.tipti.market",
        "qa.tipti.market",
        "sandbox.tipti.market",
        "beta.tipti.market",
    ):
        assert unwanted not in result.websites


@respx.mock
async def test_expand__ranks_www_first(expander: Expander) -> None:
    """``www`` outranks all other priority labels."""

    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(200, json=_load("tipti_market.json"))
    )
    for h in ["www", "app", "api", "shop", "portal", "admin", "secure", "tienda", "blog", "press"]:
        _mock_alive(f"{h}.tipti.market")

    result = await expander.expand("tipti.market", max_sites=5)

    assert result.websites[0] == "www.tipti.market"
    # The full priority order must show up before the alphabetical fallback.
    priority_positions = {
        h: result.websites.index(h)
        for h in result.websites
        if h.split(".")[0] in {"www", "app", "portal", "tienda", "shop"}
    }
    assert priority_positions["www.tipti.market"] == 0


@respx.mock
async def test_expand__caps_at_max_sites(expander: Expander) -> None:
    """``max_sites=3`` returns at most 3 entries even with many alive."""

    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(200, json=_load("tipti_market.json"))
    )
    for h in ["www", "app", "api", "shop", "portal", "admin", "secure", "tienda", "blog", "press"]:
        _mock_alive(f"{h}.tipti.market")

    result = await expander.expand("tipti.market", max_sites=3)
    assert len(result.websites) == 3


@respx.mock
async def test_expand__cache_hit_skips_http(
    expander: Expander, cache: DiscoveryCache
) -> None:
    """A cache entry under ``expand::<apex>`` short-circuits the HTTP path."""

    pre = ExpansionResult(
        apex="tipti.market",
        websites=["www.tipti.market", "app.tipti.market"],
        total_subdomains_seen=12,
    )
    cache.set("crt_sh", "expand::tipti.market", pre.model_dump(mode="json"))
    route = respx.get(CRT_SH_URL).mock(return_value=httpx.Response(200, json=[]))

    result = await expander.expand("tipti.market", max_sites=5)

    assert result.websites == ["www.tipti.market", "app.tipti.market"]
    assert route.call_count == 0


@respx.mock
async def test_expand__dead_subdomains_dropped(cache: DiscoveryCache) -> None:
    """A subdomain whose HEAD probe fails is excluded from the output."""

    config = ExpanderConfig(liveness_timeout_sec=0.5)
    e = Expander(cache=cache, config=config)
    try:
        respx.get(CRT_SH_URL).mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"common_name": "www.acme.test", "name_value": "www.acme.test"},
                    {"common_name": "ghost.acme.test", "name_value": "ghost.acme.test"},
                ],
            )
        )
        _mock_alive("www.acme.test")
        _mock_dead("ghost.acme.test")

        result = await e.expand("acme.test", max_sites=5)
    finally:
        await e.aclose()

    assert "www.acme.test" in result.websites
    assert "ghost.acme.test" not in result.websites
