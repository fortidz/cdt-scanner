"""Tests for the Brave Search wrapper (Validate + Discover modes)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx

from cdt.discovery import BraveSearch, DiscoveryCache, ValidationResult
from cdt.discovery.models import IssueCode
from cdt.errors import QuotaError
from cdt.models import AccountIn

FIXTURES = Path(__file__).parent.parent / "fixtures" / "brave"
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"


def _load(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


@pytest.fixture
async def client(cache: DiscoveryCache) -> AsyncIterator[BraveSearch]:
    bs = BraveSearch(api_key="test-key", cache=cache, min_interval_sec=0.0)
    try:
        yield bs
    finally:
        await bs.aclose()


@respx.mock
async def test_validate__site_match_returns_confirmed(client: BraveSearch) -> None:
    """≥1 result inside ``site:<apex>`` → confirmed=True with apex as canonical."""

    respx.get(BRAVE_URL).mock(
        return_value=httpx.Response(200, json=_load("validate_tipti_match.json"))
    )
    account = AccountIn(Title="Tipti", Country="Ecuador", Website="tipti.market")

    result = await client.validate(account)

    assert isinstance(result, ValidationResult)
    assert result.confirmed is True
    assert result.canonical_url == "tipti.market"
    assert result.issue is None


@respx.mock
async def test_validate__no_results_returns_mismatch_with_suggestion(
    client: BraveSearch,
) -> None:
    """0 hits in site: scope → POSSIBLE_MISMATCH; second un-scoped query
    populates the suggestion + top_candidates list."""

    route = respx.get(BRAVE_URL)
    route.side_effect = [
        httpx.Response(200, json=_load("validate_no_results.json")),
        httpx.Response(200, json=_load("discover_top_score.json")),
    ]

    account = AccountIn(Title="Tipti", Country="Ecuador", Website="tipti.market")

    result = await client.validate(account)

    assert result.confirmed is False
    assert result.issue == IssueCode.POSSIBLE_MISMATCH
    assert result.suggestion is not None
    assert "tipti" in result.suggestion
    assert len(result.top_candidates) >= 1


@respx.mock
async def test_validate__cache_hit_skips_http(
    client: BraveSearch, cache: DiscoveryCache
) -> None:
    """A pre-populated cache entry must short-circuit before any HTTP call."""

    cache.set(
        "brave_search",
        "validate::tipti::tipti.market",
        {
            "confirmed": True,
            "canonical_url": "tipti.market",
            "issue": None,
            "suggestion": None,
            "top_candidates": [],
            "needs_semantic_check": False,
        },
    )
    route = respx.get(BRAVE_URL).mock(return_value=httpx.Response(200, json={}))

    account = AccountIn(Title="Tipti", Country="Ecuador", Website="tipti.market")
    result = await client.validate(account)

    assert result.confirmed is True
    assert route.call_count == 0


@respx.mock
async def test_validate__rate_limit_429_raises_quota_error(client: BraveSearch) -> None:
    """HTTP 429 from Brave is mapped to QuotaError (E06), not retried."""

    respx.get(BRAVE_URL).mock(return_value=httpx.Response(429, json={"error": "rate"}))
    account = AccountIn(Title="Tipti", Country="Ecuador", Website="tipti.market")

    with pytest.raises(QuotaError):
        await client.validate(account)


@respx.mock
async def test_discover__top_score_above_threshold_confirmed(client: BraveSearch) -> None:
    """A top result clearly above threshold + gap → confirmed."""

    respx.get(BRAVE_URL).mock(
        return_value=httpx.Response(200, json=_load("discover_top_score.json"))
    )
    account = AccountIn(Title="Tipti", Country="Ecuador")

    result = await client.discover(account)

    assert result.confirmed is True
    assert result.canonical_url == "tipti.ec"
    assert result.issue is None


@respx.mock
async def test_discover__low_score_returns_low_confidence(client: BraveSearch) -> None:
    """Top results that don't clear threshold/gap → LOW_CONFIDENCE + top 3."""

    respx.get(BRAVE_URL).mock(
        return_value=httpx.Response(200, json=_load("discover_low_confidence.json"))
    )
    account = AccountIn(Title="Acme Corp", Country="Ecuador")

    result = await client.discover(account)

    assert result.confirmed is False
    assert result.issue == IssueCode.LOW_CONFIDENCE
    assert 1 <= len(result.top_candidates) <= 3


@respx.mock
async def test_discover__blacklist_penalises(client: BraveSearch) -> None:
    """A result on a blacklisted domain receives -10 and ranks last."""

    payload = {
        "web": {
            "results": [
                {
                    "title": "Tipti",
                    "url": "https://www.linkedin.com/company/tipti",
                    "description": "LinkedIn page",
                },
                {
                    "title": "Tipti",
                    "url": "https://www.tipti.market/",
                    "description": "Sitio oficial",
                },
            ]
        }
    }
    respx.get(BRAVE_URL).mock(return_value=httpx.Response(200, json=payload))
    account = AccountIn(Title="Tipti", Country="Ecuador")

    result = await client.discover(account)

    assert result.top_candidates[0].url == "https://www.tipti.market/"
    blacklisted = [c for c in result.top_candidates if "linkedin.com" in c.url]
    if blacklisted:
        assert blacklisted[0].score < 0


@respx.mock
async def test_discover__country_filter_applied(client: BraveSearch) -> None:
    """The ``country`` query param is set from ``account.country``."""

    route = respx.get(BRAVE_URL).mock(
        return_value=httpx.Response(200, json={"web": {"results": []}})
    )
    account = AccountIn(Title="Tipti", Country="Ecuador")

    await client.discover(account)

    assert route.call_count == 1
    request = route.calls[0].request
    params = dict(request.url.params)
    assert params.get("country") == "ec"
    assert "Tipti" in params.get("q", "")
