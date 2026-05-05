"""BuiltWith wrapper — opt-in only when ``BUILTWITH_API_KEY`` is set.

BuiltWith has no SDK we want to ship; we hit the v21 JSON endpoint directly.
30-day cache because the data drifts slowly and the free trial gives only
1 000 lookups total.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from cdt.discovery.cache import DiscoveryCache

log = structlog.get_logger()

_PROVIDER = "builtwith"
_BASE_URL = "https://api.builtwith.com/v21/api.json"
_DEFAULT_TTL_HOURS = 24 * 30


class BuiltWithResult(BaseModel):
    domain: str
    enabled: bool = False
    technologies: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class BuiltWithWrapper:
    def __init__(
        self,
        cache: DiscoveryCache,
        timeout_sec: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache = cache
        self._timeout = timeout_sec
        self._api_key = os.environ.get("BUILTWITH_API_KEY") or None
        self._client = client or httpx.AsyncClient(timeout=timeout_sec)
        self._owns_client = client is None

    @property
    def enabled(self) -> bool:
        return self._api_key is not None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def lookup(self, domain: str) -> BuiltWithResult:
        if self._api_key is None:
            log.info("builtwith_skipped", domain=domain, reason="no_api_key")
            return BuiltWithResult(domain=domain, enabled=False)

        cache_key = f"lookup::{domain.lower()}"
        cached = self._cache.get(_PROVIDER, cache_key)
        if cached is not None:
            log.info("builtwith_used_cache", domain=domain)
            return BuiltWithResult.model_validate(cached)

        log.info("builtwith_started", domain=domain)
        try:
            response = await self._fetch(domain)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            log.warning(
                "builtwith_failed",
                domain=domain,
                error=f"{type(exc).__name__}: {exc}",
            )
            return BuiltWithResult(domain=domain, enabled=True, error=str(exc))

        if response.status_code != 200:
            log.warning(
                "builtwith_failed",
                domain=domain,
                status=response.status_code,
            )
            if response.status_code == 429:
                log.warning(
                    "builtwith_quota_exceeded", domain=domain, status=429
                )
            return BuiltWithResult(
                domain=domain,
                enabled=True,
                error=f"HTTP {response.status_code}",
            )

        try:
            payload = response.json()
        except ValueError:
            return BuiltWithResult(
                domain=domain, enabled=True, error="invalid_json"
            )

        techs = _flatten_technologies(payload)
        result = BuiltWithResult(domain=domain, enabled=True, technologies=techs)
        self._cache.set(
            _PROVIDER,
            cache_key,
            result.model_dump(mode="json"),
            ttl_hours=_DEFAULT_TTL_HOURS,
        )
        log.info("builtwith_ok", domain=domain, count=len(techs))
        return result

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    async def _fetch(self, domain: str) -> httpx.Response:
        params = {"KEY": self._api_key or "", "LOOKUP": domain}
        return await self._client.get(_BASE_URL, params=params)


def _flatten_technologies(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """BuiltWith v21 nests Technologies under Results[0].Result.Paths[*]."""

    results = payload.get("Results")
    if not isinstance(results, list) or not results:
        return []

    first = results[0]
    if not isinstance(first, dict):
        return []
    result_obj = first.get("Result")
    if not isinstance(result_obj, dict):
        return []
    paths = result_obj.get("Paths")
    if not isinstance(paths, list):
        return []

    seen: set[str] = set()
    flat: list[dict[str, Any]] = []
    for path in paths:
        if not isinstance(path, dict):
            continue
        for tech in path.get("Technologies", []) or []:
            if not isinstance(tech, dict):
                continue
            name = tech.get("Name")
            if isinstance(name, str) and name not in seen:
                seen.add(name)
                flat.append(tech)
    return flat
