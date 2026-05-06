"""Tests for the crt.sh-based Expander + DNS bruteforce fallback (Fase 9 #1.2)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import dns.resolver
import httpx
import pytest
import respx

from cdt.discovery import DiscoveryCache, Expander, ExpansionResult
from cdt.discovery.expander import ExpanderConfig

FIXTURES = Path(__file__).parent.parent / "fixtures" / "crt_sh"
BRUTEFORCE_TEST_LIST = (
    Path(__file__).parent.parent / "fixtures" / "subdomain_bruteforce_test.txt"
)
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


# ===========================================================================
# Fase 9 #1.2 — DNS bruteforce fallback when crt.sh is down or thin
# ===========================================================================


def _bruteforce_resolver(alive_hosts: set[str]) -> AsyncMock:
    """Build an AsyncMock resolver where ``alive_hosts`` get an A record
    and everything else raises ``NXDOMAIN``."""

    async def _resolve(name: object, rrtype: str) -> object:
        host = str(name).rstrip(".").lower()
        if rrtype != "A":
            raise dns.resolver.NoAnswer()
        if host in alive_hosts:
            return [MagicMock(address="1.2.3.4")]
        raise dns.resolver.NXDOMAIN()

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


def _bruteforce_config() -> ExpanderConfig:
    return ExpanderConfig(
        bruteforce_list_path=BRUTEFORCE_TEST_LIST,
        bruteforce_concurrency=20,
        crt_sh_min_results=5,
        enable_bruteforce_fallback=True,
        liveness_timeout_sec=0.5,
    )


@respx.mock
async def test_expand__falls_back_to_bruteforce_when_crt_sh_502(
    cache: DiscoveryCache,
) -> None:
    """crt.sh 502 -> ``_CrtShFailed`` -> bruteforce activates and returns alive subs."""

    respx.get(CRT_SH_URL).mock(return_value=httpx.Response(502, text="Bad Gateway"))

    alive = {"openbanking.bcp.example", "loginunico.bcp.example"}
    resolver = _bruteforce_resolver(alive)
    config = _bruteforce_config()

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        # All HEAD probes for alive hosts should pass.
        for host in alive:
            _mock_alive(host)
        result = await e.expand("bcp.example", max_sites=5)
    finally:
        await e.aclose()

    assert isinstance(result, ExpansionResult)
    assert result.source == "bruteforce"
    assert "openbanking.bcp.example" in result.websites
    assert "loginunico.bcp.example" in result.websites


@respx.mock
async def test_expand__falls_back_when_crt_sh_returns_empty(
    cache: DiscoveryCache,
) -> None:
    """crt.sh 200 [] -> bruteforce activates."""

    respx.get(CRT_SH_URL).mock(return_value=httpx.Response(200, json=[]))

    alive = {"www.bcp.example"}
    resolver = _bruteforce_resolver(alive)
    config = _bruteforce_config()

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        _mock_alive("www.bcp.example")
        result = await e.expand("bcp.example", max_sites=5)
    finally:
        await e.aclose()

    assert result.source == "bruteforce"
    assert "www.bcp.example" in result.websites


@respx.mock
async def test_expand__falls_back_when_crt_sh_returns_few_results(
    cache: DiscoveryCache,
) -> None:
    """crt.sh returns 2 (below crt_sh_min_results=5) -> merge with bruteforce."""

    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"common_name": "www.bcp.example", "name_value": "www.bcp.example"},
                {"common_name": "api.bcp.example", "name_value": "api.bcp.example"},
            ],
        )
    )

    # Bruteforce surfaces a hostname crt.sh missed.
    alive = {
        "www.bcp.example",  # also from crt.sh — must dedup
        "api.bcp.example",  # ditto
        "openbanking.bcp.example",  # only from bruteforce
        "zonasegura.bcp.example",   # only from bruteforce
    }
    resolver = _bruteforce_resolver(alive)
    config = _bruteforce_config()

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        for host in alive:
            _mock_alive(host)
        result = await e.expand("bcp.example", max_sites=10)
    finally:
        await e.aclose()

    assert result.source == "merged"
    # Bruteforce-only hostnames present.
    assert "openbanking.bcp.example" in result.websites
    assert "zonasegura.bcp.example" in result.websites


@respx.mock
async def test_expand__no_fallback_when_crt_sh_succeeds(
    cache: DiscoveryCache,
) -> None:
    """crt.sh returns >= crt_sh_min_results -> bruteforce skipped, resolver untouched."""

    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"common_name": f"sub{i}.bcp.example",
                 "name_value": f"sub{i}.bcp.example"}
                for i in range(6)
            ],
        )
    )

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=AssertionError("DNS must not be touched"))
    config = _bruteforce_config()

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        for i in range(6):
            _mock_alive(f"sub{i}.bcp.example")
        result = await e.expand("bcp.example", max_sites=10)
    finally:
        await e.aclose()

    assert result.source == "crt_sh"
    resolver.resolve.assert_not_called()


@respx.mock
async def test_expand__bruteforce_filters_dead_subdomains(
    cache: DiscoveryCache,
) -> None:
    """Bruteforce list has names that resolve; HEAD probe drops dead hosts."""

    respx.get(CRT_SH_URL).mock(side_effect=httpx.ConnectError("crt down"))

    alive_dns = {"www.bcp.example", "api.bcp.example", "admin.bcp.example"}
    resolver = _bruteforce_resolver(alive_dns)
    config = _bruteforce_config()

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        # Only www and api are HTTP-alive; admin returns connect error.
        _mock_alive("www.bcp.example")
        _mock_alive("api.bcp.example")
        _mock_dead("admin.bcp.example")
        result = await e.expand("bcp.example", max_sites=5)
    finally:
        await e.aclose()

    assert result.source == "bruteforce"
    assert "www.bcp.example" in result.websites
    assert "api.bcp.example" in result.websites
    assert "admin.bcp.example" not in result.websites


@respx.mock
async def test_expand__bruteforce_concurrent_with_semaphore(
    cache: DiscoveryCache,
) -> None:
    """Concurrency cap is enforced — peak in-flight resolver calls <= bruteforce_concurrency."""

    respx.get(CRT_SH_URL).mock(side_effect=httpx.ConnectError("crt down"))

    in_flight = 0
    peak = 0
    import asyncio as _asyncio

    async def _resolve(name: object, rrtype: str) -> object:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            await _asyncio.sleep(0.01)
            return [MagicMock(address="1.2.3.4")]
        finally:
            in_flight -= 1

    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=_resolve)

    config = ExpanderConfig(
        bruteforce_list_path=BRUTEFORCE_TEST_LIST,
        bruteforce_concurrency=3,  # tight cap to make the assertion meaningful
        crt_sh_min_results=5,
        enable_bruteforce_fallback=True,
        liveness_timeout_sec=0.5,
    )

    # Catch every HEAD against *.bcp.example so the post-bruteforce
    # liveness probe doesn't blow up on missing respx routes; the
    # assertion in this test is only about the resolver concurrency.
    respx.head(url__regex=r"https://.+\.bcp\.example/?$").mock(
        return_value=httpx.Response(200)
    )

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        await e.expand("bcp.example", max_sites=5)
    finally:
        await e.aclose()

    assert peak <= 3, f"peak concurrent = {peak}, expected <= 3"


@respx.mock
async def test_expand__source_in_result_reflects_path_taken(
    cache: DiscoveryCache,
) -> None:
    """``ExpansionResult.source`` ∈ {crt_sh, bruteforce, merged, cache}."""

    # Run 1: crt.sh succeeds -> source=crt_sh
    respx.get(CRT_SH_URL).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"common_name": f"sub{i}.bcp.example",
                 "name_value": f"sub{i}.bcp.example"}
                for i in range(6)
            ],
        )
    )
    config = _bruteforce_config()
    e = Expander(cache=cache, config=config)
    try:
        for i in range(6):
            _mock_alive(f"sub{i}.bcp.example")
        first = await e.expand("bcp.example", max_sites=10)
    finally:
        await e.aclose()
    assert first.source == "crt_sh"

    # Run 2 (cache hot): same apex -> source=cache
    e2 = Expander(cache=cache, config=config)
    try:
        second = await e2.expand("bcp.example", max_sites=10)
    finally:
        await e2.aclose()
    assert second.source == "cache"


async def test_expand__bruteforce_disabled_skips_fallback(
    cache: DiscoveryCache,
) -> None:
    """``enable_bruteforce_fallback=False`` -> no DNS calls even when crt.sh empty."""

    config = ExpanderConfig(
        bruteforce_list_path=BRUTEFORCE_TEST_LIST,
        enable_bruteforce_fallback=False,
        liveness_timeout_sec=0.5,
    )
    resolver = AsyncMock()
    resolver.resolve = AsyncMock(side_effect=AssertionError("Resolver must not be touched"))

    e = Expander(cache=cache, config=config, resolver=resolver)
    try:
        with respx.mock:
            respx.get(CRT_SH_URL).mock(side_effect=httpx.ConnectError("crt down"))
            result = await e.expand("bcp.example", max_sites=5)
    finally:
        await e.aclose()

    assert result.websites == []
    resolver.resolve.assert_not_called()
