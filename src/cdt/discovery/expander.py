"""crt.sh-based subdomain expansion (v0.4 §4.3).

We pull the certificate transparency log for ``apex``, filter out everything
that is not a productive web subdomain, probe the survivors with HEAD, and
return up to ``max_sites`` ranked by the configured priority list.
"""

from __future__ import annotations

import asyncio
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
from cdt.discovery.models import ExpansionResult

log = structlog.get_logger()

_PROVIDER_NAME = "crt_sh"
_CRT_SH_URL = "https://crt.sh/"


class ExpanderConfig:
    """Tunables loaded from ``config/discovery.yaml`` (or defaults)."""

    def __init__(
        self,
        mailserver_prefixes: list[str] | None = None,
        asset_prefixes: list[str] | None = None,
        non_prod_keywords: list[str] | None = None,
        site_priority: list[str] | None = None,
        liveness_timeout_sec: float = 5.0,
    ) -> None:
        self.mailserver_prefixes = mailserver_prefixes or [
            "mx", "mail", "smtp", "imap", "pop",
        ]
        self.asset_prefixes = asset_prefixes or [
            "cdn", "static", "assets", "media", "img",
        ]
        self.non_prod_keywords = non_prod_keywords or [
            "dev", "staging", "test", "uat", "qa", "sandbox", "beta",
        ]
        self.site_priority = site_priority or [
            "www", "app", "portal", "tienda", "shop", "api", "admin", "secure",
        ]
        self.liveness_timeout_sec = liveness_timeout_sec


class Expander:
    def __init__(
        self,
        cache: DiscoveryCache,
        timeout_sec: float = 15.0,
        config: ExpanderConfig | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache = cache
        self._timeout = timeout_sec
        self._config = config or ExpanderConfig()
        self._client = client or httpx.AsyncClient(
            timeout=timeout_sec,
            follow_redirects=False,
            headers={"User-Agent": "cdt-scanner/0.1 (expander)"},
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

    async def expand(self, apex: str, max_sites: int = 5) -> ExpansionResult:
        apex = apex.lower().strip()
        cache_key = f"expand::{apex}"
        cached = self._cache.get(_PROVIDER_NAME, cache_key)
        if cached is not None:
            log.info("discovery_used_cache", mode="expand", apex=apex)
            return ExpansionResult.model_validate(cached)

        log.info("discovery_expand_started", apex=apex)
        entries = await self._fetch_crt_sh(apex)
        names = _extract_names(entries)
        kept, total = _filter_names(names, apex, self._config)

        live = await self._probe_live(kept)
        ranked = _rank_subdomains(live, self._config.site_priority)
        websites = ranked[:max_sites]

        outcome = ExpansionResult(
            apex=apex,
            websites=websites,
            total_subdomains_seen=total,
        )
        self._cache.set(_PROVIDER_NAME, cache_key, outcome.model_dump(mode="json"))
        log.info(
            "discovery_expand_ok",
            apex=apex,
            kept=len(websites),
            total=total,
        )
        return outcome

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    async def _fetch_crt_sh(self, apex: str) -> list[dict[str, Any]]:
        response = await self._client.get(
            _CRT_SH_URL,
            params={"q": apex, "output": "json"},
        )
        if response.status_code != 200:
            return []
        try:
            payload = response.json()
        except ValueError:
            return []
        if not isinstance(payload, list):
            return []
        return [e for e in payload if isinstance(e, dict)]

    async def _probe_live(self, hosts: list[str]) -> list[str]:
        if not hosts:
            return []

        async def _probe(host: str) -> str | None:
            url = f"https://{host}"
            try:
                response = await self._client.head(
                    url,
                    timeout=self._config.liveness_timeout_sec,
                )
            except (httpx.TimeoutException, httpx.NetworkError):
                log.debug("discovery_expand_dead_sub", host=host, reason="network")
                return None
            if response.status_code >= 500 or response.status_code == 0:
                log.debug(
                    "discovery_expand_dead_sub",
                    host=host,
                    status=response.status_code,
                )
                return None
            return host

        results = await asyncio.gather(*(_probe(h) for h in hosts))
        return [h for h in results if h is not None]


def _extract_names(entries: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for e in entries:
        cn = e.get("common_name")
        if isinstance(cn, str):
            names.add(cn.strip().lower())
        nv = e.get("name_value")
        if isinstance(nv, str):
            for part in nv.splitlines():
                cleaned = part.strip().lower()
                if cleaned:
                    names.add(cleaned)
    return names


def _filter_names(
    names: set[str], apex: str, config: ExpanderConfig
) -> tuple[list[str], int]:
    apex = apex.lower()
    suffix = f".{apex}"
    kept: list[str] = []
    total = 0
    for n in names:
        if "*" in n:
            continue
        if not (n == apex or n.endswith(suffix)):
            continue
        total += 1
        if n == apex:
            # bare apex is captured under Website01 elsewhere; expander only
            # surfaces strict subdomains.
            continue

        labels = n.split(".")
        first_label = labels[0]
        if first_label in config.mailserver_prefixes:
            continue
        if first_label in config.asset_prefixes:
            continue
        if any(kw in labels[:-len(apex.split("."))] for kw in config.non_prod_keywords):
            continue

        kept.append(n)
    return kept, total


def _rank_subdomains(hosts: list[str], priority: list[str]) -> list[str]:
    priority_index = {label: i for i, label in enumerate(priority)}
    fallback = len(priority)

    def key(host: str) -> tuple[int, str]:
        first = host.split(".")[0]
        return priority_index.get(first, fallback), host

    return sorted(set(hosts), key=key)
