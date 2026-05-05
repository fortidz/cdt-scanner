"""Brave Search API wrapper for Validate + Discover modes.

Override on v0.4 §4: the spec specifies Google CSE; we use Brave because Google
deprecated "Search the entire web" for new Programmable Search Engines.

Endpoint:  ``https://api.search.brave.com/res/v1/web/search``
Auth:      ``X-Subscription-Token: <BRAVE_SEARCH_API_KEY>``
Free tier: 1 req/s. Brave returns ``X-RateLimit-*`` headers and a 429 on bust.
"""

from __future__ import annotations

import asyncio
import time
from types import TracebackType
from typing import Any, Self

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from cdt.discovery.cache import DiscoveryCache
from cdt.discovery.models import IssueCode, SearchResult, ValidationResult
from cdt.discovery.normalize import apex_of
from cdt.errors import NetworkError, QuotaError
from cdt.models import AccountIn

_BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
_PROVIDER_NAME = "brave_search"
_DISCOVER_THRESHOLD = 6.0
_DISCOVER_GAP = 3.0

_DEFAULT_BLACKLIST: frozenset[str] = frozenset(
    {
        "linkedin.com",
        "facebook.com",
        "paginasamarillas.com",
        "crunchbase.com",
        "bloomberg.com",
        "emis.com",
        "zoominfo.com",
        "dnb.com",
    }
)

_COUNTRY_CODE: dict[str, str] = {
    "Perú": "pe",
    "Peru": "pe",
    "Ecuador": "ec",
    "Chile": "cl",
    "Bolivia": "bo",
    "Paraguay": "py",
    "Uruguay": "uy",
    "Venezuela": "ve",
}

log = structlog.get_logger()


class BraveSearch:
    """Async wrapper around the Brave Search Web API.

    Caches every successful response; rate-limits to ``min_interval_sec`` per
    request (default 1 s for the free tier). Tests pass ``min_interval_sec=0``.
    """

    def __init__(
        self,
        api_key: str,
        cache: DiscoveryCache,
        timeout_sec: float = 10.0,
        min_interval_sec: float = 1.0,
        blacklist: frozenset[str] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
        self._cache = cache
        self._timeout = timeout_sec
        self._min_interval = min_interval_sec
        self._blacklist = blacklist if blacklist is not None else _DEFAULT_BLACKLIST
        self._lock = asyncio.Lock()
        self._last_call: float = 0.0
        self._client = client or httpx.AsyncClient(
            timeout=timeout_sec,
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": api_key,
            },
        )
        self._owns_client = client is None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def validate(self, account: AccountIn) -> ValidationResult:
        """Validate that ``account.title`` is associated with ``account.website``.

        Strategy: ``"<Title>" site:<apex>``. ≥1 hit → confirmed. 0 hits →
        ``POSSIBLE_MISMATCH`` plus a second un-scoped query for ``suggestion``
        and ``top_candidates``.
        """

        apex = apex_of(account.website)
        title_norm = _normalize_title(account.title)
        cache_key = f"validate::{title_norm}::{apex}"

        cached = self._cache.get(_PROVIDER_NAME, cache_key)
        if cached is not None:
            log.info("discovery_used_cache", mode="validate", apex=apex)
            return ValidationResult.model_validate(cached)

        primary_query = f'"{account.title}" site:{apex}'
        primary = await self._search(primary_query)
        results = _parse_results(primary)

        if results:
            outcome = ValidationResult(
                confirmed=True,
                canonical_url=apex,
                issue=None,
            )
            self._cache.set(_PROVIDER_NAME, cache_key, outcome.model_dump(mode="json"))
            log.info("discovery_validate_ok", apex=apex, hits=len(results))
            return outcome

        # 0 results in site: scope → broaden to find a suggestion.
        secondary_query = f'"{account.title}"'
        secondary = await self._search(secondary_query)
        candidates = _parse_results(secondary)
        ranked = _rank(candidates, account=account, blacklist=self._blacklist)
        top3 = ranked[:3]
        suggestion = top3[0].url if top3 else None

        outcome = ValidationResult(
            confirmed=False,
            canonical_url=None,
            issue=IssueCode.POSSIBLE_MISMATCH,
            suggestion=suggestion,
            top_candidates=top3,
        )
        self._cache.set(_PROVIDER_NAME, cache_key, outcome.model_dump(mode="json"))
        log.warning(
            "discovery_validate_fail",
            apex=apex,
            issue=IssueCode.POSSIBLE_MISMATCH.value,
            top_candidate=suggestion,
        )
        return outcome

    async def discover(self, account: AccountIn) -> ValidationResult:
        """Discover the account's website when no Website was provided.

        Score every result and pick the top one if it clears both an absolute
        threshold and a gap above the runner-up.
        """

        country_code = _COUNTRY_CODE.get(account.country, "")
        title_norm = _normalize_title(account.title)
        cache_key = f"discover::{title_norm}::{country_code}"

        cached = self._cache.get(_PROVIDER_NAME, cache_key)
        if cached is not None:
            log.info("discovery_used_cache", mode="discover", country=country_code)
            return ValidationResult.model_validate(cached)

        query = f"{account.title} {account.country}".strip()
        params: dict[str, str] = {}
        if country_code:
            params["country"] = country_code

        raw = await self._search(query, extra_params=params)
        results = _parse_results(raw)
        ranked = _rank(results, account=account, blacklist=self._blacklist)

        if not ranked:
            outcome = ValidationResult(
                confirmed=False,
                canonical_url=None,
                issue=IssueCode.NO_RESULTS,
                top_candidates=[],
            )
            self._cache.set(_PROVIDER_NAME, cache_key, outcome.model_dump(mode="json"))
            log.warning("discovery_discover_fail", title=account.title, reason="no_results")
            return outcome

        top = ranked[0]
        runner_up_score = ranked[1].score if len(ranked) > 1 else 0.0

        if top.score >= _DISCOVER_THRESHOLD and (top.score - runner_up_score) >= _DISCOVER_GAP:
            try:
                canonical = apex_of(top.url)
            except Exception:  # noqa: BLE001
                canonical = None
            outcome = ValidationResult(
                confirmed=True,
                canonical_url=canonical,
                issue=None,
                top_candidates=ranked[:3],
            )
            self._cache.set(_PROVIDER_NAME, cache_key, outcome.model_dump(mode="json"))
            log.info(
                "discovery_discover_ok",
                title=account.title,
                country=country_code,
                top=canonical,
                score=top.score,
            )
            return outcome

        outcome = ValidationResult(
            confirmed=False,
            canonical_url=None,
            issue=IssueCode.LOW_CONFIDENCE,
            top_candidates=ranked[:3],
        )
        self._cache.set(_PROVIDER_NAME, cache_key, outcome.model_dump(mode="json"))
        log.warning(
            "discovery_discover_fail",
            title=account.title,
            reason="low_confidence",
            top_score=top.score,
            gap=top.score - runner_up_score,
        )
        return outcome

    async def _search(
        self,
        query: str,
        extra_params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            if self._min_interval > 0:
                now = time.monotonic()
                wait = self._last_call + self._min_interval - now
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_call = time.monotonic()

        params: dict[str, str] = {"q": query, "count": "10"}
        if extra_params:
            params.update(extra_params)

        return await self._fetch(params)

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    async def _fetch(self, params: dict[str, str]) -> dict[str, Any]:
        try:
            response = await self._client.get(_BRAVE_ENDPOINT, params=params)
        except httpx.TimeoutException:
            raise
        except httpx.NetworkError:
            raise

        if response.status_code == 429:
            log.warning("brave_quota_exceeded", status=429)
            raise QuotaError("Brave Search rate-limit exceeded (HTTP 429)")
        if response.status_code >= 500:
            raise NetworkError(f"Brave Search returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise NetworkError(f"Brave Search returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise NetworkError(f"Brave Search returned non-JSON body: {exc}") from exc

        return payload if isinstance(payload, dict) else {}


def _normalize_title(title: str) -> str:
    return " ".join(title.lower().split())


def _parse_results(payload: dict[str, Any]) -> list[SearchResult]:
    web = payload.get("web") or {}
    raw_results = web.get("results") or []
    parsed: list[SearchResult] = []
    for entry in raw_results:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url:
            continue
        title = entry.get("title")
        snippet = entry.get("description") or entry.get("snippet") or ""
        parsed.append(
            SearchResult(
                url=url,
                title=title if isinstance(title, str) else "",
                snippet=snippet if isinstance(snippet, str) else "",
            )
        )
    return parsed


def _rank(
    results: list[SearchResult],
    *,
    account: AccountIn,
    blacklist: frozenset[str],
) -> list[SearchResult]:
    """Apply the heuristic scoring described in the user spec.

    +5  domain TLD matches the account's country ccTLD
    +3  result title contains account.title (case-insensitive)
    +2  result url contains the account.title slug
    -10 domain (or apex) is in the blacklist
    """

    cc = _COUNTRY_CODE.get(account.country, "")
    title_lc = account.title.lower()
    slug = _slugify(account.title)

    scored: list[SearchResult] = []
    for r in results:
        try:
            apex = apex_of(r.url)
        except Exception as exc:  # noqa: BLE001 — invalid URLs in 3rd-party data
            log.debug("discovery_score_skip", url=r.url, error=str(exc))
            continue

        score = 0.0
        if cc and (apex.endswith(f".{cc}") or apex == cc):
            score += 5.0
        if title_lc and title_lc in r.title.lower():
            score += 3.0
        if slug and slug in r.url.lower():
            score += 2.0
        if apex in blacklist:
            score -= 10.0

        scored.append(
            SearchResult(
                url=r.url,
                title=r.title,
                snippet=r.snippet,
                score=score,
            )
        )

    scored.sort(key=lambda s: s.score, reverse=True)
    return scored


def _slugify(s: str) -> str:
    return "".join(c for c in s.lower() if c.isalnum())
