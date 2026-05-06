"""Subdomain expansion (v0.4 §4.3 + Fase 9 #1.2 resilience).

Two strategies:

  1. **crt.sh certificate transparency** (primary). Authoritative,
     covers all certificates ever issued for the apex. Slow-changing,
     cached 24 h. When the service is up and returns enough results
     (``crt_sh_min_results``), we trust it exclusively.

  2. **DNS bruteforce** (fallback). Probes a curated static list
     (``config/subdomain_bruteforce.txt``, ~240 names) via parallel
     A-record lookups under a semaphore. Fires when crt.sh fails
     (5xx / timeout / network error) OR returns thin results
     (< ``crt_sh_min_results``). When crt.sh produced a thin set, the
     two are merged; otherwise bruteforce is the sole source.

The dispatcher records the strategy it took in
``ExpansionResult.source`` so callers can adjust trust downstream.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

import dns.exception
import dns.resolver
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

if TYPE_CHECKING:  # pragma: no cover — typing-only import
    import dns.asyncresolver

log = structlog.get_logger()

_PROVIDER_NAME = "crt_sh"
_CRT_SH_URL = "https://crt.sh/"
_DEFAULT_BRUTEFORCE_LIST = Path("config/subdomain_bruteforce.txt")

# Hard ceiling on probes per apex regardless of list length — defends
# the resolver / network from a runaway list edit.
_MAX_BRUTEFORCE_CANDIDATES = 300

# TTLs in hours: crt.sh is slow-changing + authoritative; bruteforce is
# best-effort and may miss subdomains, so cache for less.
_CACHE_TTL_CRT_SH_HOURS = 24
_CACHE_TTL_BRUTEFORCE_HOURS = 6


# ---------------------------------------------------------------------------
# Internal sentinel for crt.sh state
# ---------------------------------------------------------------------------


class _CrtShFailed(Exception):
    """Raised by ``_fetch_crt_sh`` when the API itself failed (5xx,
    timeout, network error). Distinct from "responded but empty" so the
    dispatcher can decide whether to merge or replace."""


class ExpanderConfig:
    """Tunables loaded from ``config/discovery.yaml`` (or defaults)."""

    def __init__(
        self,
        mailserver_prefixes: list[str] | None = None,
        asset_prefixes: list[str] | None = None,
        non_prod_keywords: list[str] | None = None,
        site_priority: list[str] | None = None,
        liveness_timeout_sec: float = 5.0,
        # ----- Fase 9 #1.2 bruteforce fallback knobs -----
        bruteforce_list_path: Path | str = _DEFAULT_BRUTEFORCE_LIST,
        bruteforce_concurrency: int = 50,
        crt_sh_min_results: int = 5,
        enable_bruteforce_fallback: bool = True,
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
        self.bruteforce_list_path = Path(bruteforce_list_path)
        self.bruteforce_concurrency = bruteforce_concurrency
        self.crt_sh_min_results = crt_sh_min_results
        self.enable_bruteforce_fallback = enable_bruteforce_fallback


class Expander:
    def __init__(
        self,
        cache: DiscoveryCache,
        timeout_sec: float = 15.0,
        config: ExpanderConfig | None = None,
        client: httpx.AsyncClient | None = None,
        resolver: dns.asyncresolver.Resolver | None = None,
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
        # Lazy-init resolver so tests can stub it without paying the
        # ``dns.asyncresolver.Resolver()`` system-config read.
        self._resolver = resolver
        # Bruteforce list cached on first use; reading 240 short lines
        # is cheap but doing it per-account is silly.
        self._bruteforce_list_cache: list[str] | None = None

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

    # ----- public entrypoint --------------------------------------------

    async def expand(self, apex: str, max_sites: int = 5) -> ExpansionResult:
        apex = apex.lower().strip()
        cache_key = f"expand::{apex}"
        cached = self._cache.get(_PROVIDER_NAME, cache_key)
        if cached is not None:
            log.info("discovery_used_cache", mode="expand", apex=apex)
            outcome = ExpansionResult.model_validate(cached)
            return outcome.model_copy(update={"source": "cache"})

        log.info("discovery_expand_started", apex=apex)

        # 1. Try crt.sh.
        crt_sh_subdomains: list[str] = []
        crt_sh_total = 0
        crt_sh_failed = False
        crt_sh_reason = ""
        log.info("expander_source_started", source="crt_sh", apex=apex)
        try:
            entries = await self._fetch_crt_sh(apex)
        except _CrtShFailed as exc:
            crt_sh_failed = True
            crt_sh_reason = str(exc)
            log.warning(
                "expander_source_failed",
                source="crt_sh",
                apex=apex,
                reason=crt_sh_reason,
            )
        else:
            names = _extract_names(entries)
            crt_sh_subdomains, crt_sh_total = _filter_names(
                names, apex, self._config
            )
            log.info(
                "expander_source_completed",
                source="crt_sh",
                apex=apex,
                count=len(crt_sh_subdomains),
                total=crt_sh_total,
            )

        # 2. Decide whether to also run bruteforce.
        must_fallback = self._should_fallback(crt_sh_failed, crt_sh_subdomains)

        bruteforce_subdomains: list[str] = []
        if must_fallback:
            bruteforce_subdomains = await self._bruteforce_subdomains(
                apex, exclude=set(crt_sh_subdomains)
            )

        # 3. Merge + filter + rank.
        merged = list(dict.fromkeys(crt_sh_subdomains + bruteforce_subdomains))
        live = await self._probe_live(merged)
        ranked = _rank_subdomains(live, self._config.site_priority)
        websites = ranked[:max_sites]

        source, ttl_hours = self._classify_source(
            crt_sh_failed, crt_sh_subdomains, bruteforce_subdomains
        )
        outcome = ExpansionResult(
            apex=apex,
            websites=websites,
            total_subdomains_seen=crt_sh_total + len(bruteforce_subdomains),
            source=source,
        )
        self._cache.set(
            _PROVIDER_NAME,
            cache_key,
            outcome.model_dump(mode="json"),
            ttl_hours=ttl_hours,
        )
        log.info(
            "expander_completed",
            apex=apex,
            source=source,
            final_count=len(websites),
            cache_ttl_hours=ttl_hours,
        )
        return outcome

    # ----- crt.sh fetch (primary) ---------------------------------------

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    async def _fetch_crt_sh(self, apex: str) -> list[dict[str, Any]]:
        """Fetch certificate-transparency entries for ``apex``.

        Distinguishes API failure from an honest empty answer:
          - HTTP 5xx / timeout / network error → ``_CrtShFailed`` raise.
          - HTTP 4xx                            → ``[]`` (input issue,
                                                  bruteforce won't fix it).
          - HTTP 2xx with non-list payload      → ``[]`` (treated empty).
          - HTTP 2xx with list payload          → returned as-is.
        """

        try:
            response = await self._client.get(
                _CRT_SH_URL,
                params={"q": apex, "output": "json"},
            )
        except httpx.TimeoutException as exc:
            raise _CrtShFailed("timeout") from exc
        except httpx.NetworkError as exc:
            raise _CrtShFailed(f"network: {exc}") from exc

        if response.status_code >= 500:
            raise _CrtShFailed(f"http_{response.status_code}")
        if response.status_code != 200:
            return []
        try:
            payload = response.json()
        except ValueError:
            return []
        if not isinstance(payload, list):
            return []
        return [e for e in payload if isinstance(e, dict)]

    # ----- bruteforce (fallback) ----------------------------------------

    async def _bruteforce_subdomains(
        self, apex: str, *, exclude: set[str] | None = None
    ) -> list[str]:
        """DNS-probe each name from the bruteforce list against ``apex``.

        Returns FQDNs with at least one A record (HEAD-probing is left
        to ``_probe_live`` so DNS-alive but HTTP-dead hosts get filtered
        in the merged step).

        ``exclude`` skips names already present in the crt.sh result so
        we don't re-resolve the same FQDN twice in the merge path.
        """

        if not self._config.enable_bruteforce_fallback:
            log.info(
                "expander_bruteforce_disabled",
                apex=apex,
                reason="config",
            )
            return []

        names = self._load_bruteforce_list()
        if not names:
            log.warning(
                "expander_bruteforce_list_empty", apex=apex,
                path=str(self._config.bruteforce_list_path),
            )
            return []

        exclude = exclude or set()
        candidates = [
            f"{name}.{apex}"
            for name in names
            if f"{name}.{apex}" not in exclude
        ]
        # Hard cap on probe budget.
        candidates = candidates[:_MAX_BRUTEFORCE_CANDIDATES]

        log.info(
            "expander_bruteforce_started",
            apex=apex,
            candidates=len(candidates),
        )

        if not candidates:
            return []

        resolver = self._get_resolver()
        semaphore = asyncio.Semaphore(self._config.bruteforce_concurrency)

        async def _probe_one(fqdn: str) -> str | None:
            async with semaphore:
                try:
                    answer = await resolver.resolve(fqdn, "A")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return None
                except dns.exception.DNSException:
                    return None
                # If we got an answer object, it has at least one record.
                # Tolerate stub mocks that return a non-iterable truthy.
                if not answer:
                    return None
                return fqdn

        resolved = await asyncio.gather(
            *(_probe_one(c) for c in candidates),
            return_exceptions=False,
        )
        alive = [r for r in resolved if r is not None]

        # Filter mailserver / asset / non-prod prefixes the same way
        # crt.sh names are filtered, so ranked output is consistent.
        kept, _total = _filter_names(set(alive), apex, self._config)
        log.info(
            "expander_bruteforce_completed",
            apex=apex,
            resolved=len(alive),
            kept=len(kept),
        )
        return kept

    def _load_bruteforce_list(self) -> list[str]:
        if self._bruteforce_list_cache is not None:
            return self._bruteforce_list_cache

        path = self._config.bruteforce_list_path
        if not path.exists():
            log.warning("expander_bruteforce_list_missing", path=str(path))
            self._bruteforce_list_cache = []
            return self._bruteforce_list_cache

        names: list[str] = []
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                names.append(line.lower())
        except OSError as exc:
            log.warning(
                "expander_bruteforce_list_read_failed",
                path=str(path),
                error=str(exc),
            )
            self._bruteforce_list_cache = []
            return self._bruteforce_list_cache

        # Dedup preserving order.
        self._bruteforce_list_cache = list(dict.fromkeys(names))
        return self._bruteforce_list_cache

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        if self._resolver is None:
            import dns.asyncresolver as _r

            self._resolver = _r.Resolver()
        return self._resolver

    # ----- liveness probe (shared) --------------------------------------

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

    # ----- dispatch helpers ---------------------------------------------

    def _should_fallback(
        self, crt_sh_failed: bool, crt_sh_subdomains: list[str]
    ) -> bool:
        if not self._config.enable_bruteforce_fallback:
            return False
        if crt_sh_failed:
            return True
        if len(crt_sh_subdomains) < self._config.crt_sh_min_results:
            return True
        return False

    def _classify_source(
        self,
        crt_sh_failed: bool,
        crt_sh_subdomains: list[str],
        bruteforce_subdomains: list[str],
    ) -> tuple[str, int]:
        """Decide ``source`` label + cache TTL.

        Returns ``(source, ttl_hours)``.
        """

        if crt_sh_failed and bruteforce_subdomains:
            return "bruteforce", _CACHE_TTL_BRUTEFORCE_HOURS
        if crt_sh_failed:
            # crt.sh died and bruteforce produced nothing: still cache
            # short so a transient outage doesn't poison the cache 24h.
            return "bruteforce", _CACHE_TTL_BRUTEFORCE_HOURS
        if not crt_sh_subdomains and bruteforce_subdomains:
            return "bruteforce", _CACHE_TTL_BRUTEFORCE_HOURS
        if crt_sh_subdomains and bruteforce_subdomains:
            return "merged", _CACHE_TTL_BRUTEFORCE_HOURS
        return "crt_sh", _CACHE_TTL_CRT_SH_HOURS


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
