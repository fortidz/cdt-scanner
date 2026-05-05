"""Shodan integration: free InternetDB + optional paid Host API (v0.4 §14.5.2).

InternetDB needs no key and is always available. The Host API is paid; if
``SHODAN_API_KEY`` is unset the wrapper short-circuits to ``enabled=False``
on every call.

Both endpoints are cached for 7 days via ``DiscoveryCache`` because Shodan's
data is mostly stable and the free InternetDB endpoint has informal 1 RPS
throttling we want to avoid hitting.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
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

_INTERNETDB_PROVIDER = "shodan_internetdb"
_HOST_PROVIDER = "shodan_host"
_INTERNETDB_BASE = "https://internetdb.shodan.io"
_DEFAULT_TTL_HOURS = 24 * 7


class ShodanInternetDBResult(BaseModel):
    ip: str
    ports: list[int] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class ShodanHostResult(BaseModel):
    ip: str
    enabled: bool = False
    asn: int | None = None
    asn_org: str | None = None
    isp: str | None = None
    banners: list[dict[str, Any]] = Field(default_factory=list)
    last_update: datetime | None = None
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class ShodanWrapper:
    def __init__(
        self,
        cache: DiscoveryCache,
        internetdb_timeout: float = 10.0,
        host_api_timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache = cache
        self._internetdb_timeout = internetdb_timeout
        self._host_timeout = host_api_timeout
        self._api_key = os.environ.get("SHODAN_API_KEY") or None
        self._client = client or httpx.AsyncClient(timeout=internetdb_timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def lookup_internetdb(self, ip: str) -> ShodanInternetDBResult:
        cache_key = f"internetdb::{ip}"
        cached = self._cache.get(_INTERNETDB_PROVIDER, cache_key)
        if cached is not None:
            log.info("shodan_used_cache", endpoint="internetdb", ip=ip)
            return ShodanInternetDBResult.model_validate(cached)

        log.info("shodan_started", endpoint="internetdb", ip=ip)
        try:
            response = await self._fetch_internetdb(ip)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            log.warning(
                "shodan_failed",
                endpoint="internetdb",
                ip=ip,
                error=f"{type(exc).__name__}: {exc}",
            )
            return ShodanInternetDBResult(ip=ip, error=str(exc))

        if response.status_code == 404:
            empty = ShodanInternetDBResult(ip=ip)
            self._cache.set(
                _INTERNETDB_PROVIDER,
                cache_key,
                empty.model_dump(mode="json"),
                ttl_hours=_DEFAULT_TTL_HOURS,
            )
            log.info("shodan_ok", endpoint="internetdb", ip=ip, status=404)
            return empty
        if response.status_code != 200:
            log.warning(
                "shodan_failed",
                endpoint="internetdb",
                ip=ip,
                status=response.status_code,
            )
            return ShodanInternetDBResult(
                ip=ip, error=f"HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError:
            return ShodanInternetDBResult(ip=ip, error="invalid_json")

        result = ShodanInternetDBResult(
            ip=ip,
            ports=_int_list(payload.get("ports")),
            cpes=_str_list(payload.get("cpes")),
            hostnames=_str_list(payload.get("hostnames")),
            tags=_str_list(payload.get("tags")),
            vulns=_str_list(payload.get("vulns")),
        )
        self._cache.set(
            _INTERNETDB_PROVIDER,
            cache_key,
            result.model_dump(mode="json"),
            ttl_hours=_DEFAULT_TTL_HOURS,
        )
        log.info(
            "shodan_ok",
            endpoint="internetdb",
            ip=ip,
            ports=len(result.ports),
            vulns=len(result.vulns),
        )
        return result

    async def lookup_host(self, ip: str) -> ShodanHostResult:
        if self._api_key is None:
            log.info("shodan_skipped", endpoint="host", ip=ip, reason="no_api_key")
            return ShodanHostResult(ip=ip, enabled=False)

        cache_key = f"host::{ip}"
        cached = self._cache.get(_HOST_PROVIDER, cache_key)
        if cached is not None:
            log.info("shodan_used_cache", endpoint="host", ip=ip)
            return ShodanHostResult.model_validate(cached)

        log.info("shodan_started", endpoint="host", ip=ip)
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(_run_shodan_host, self._api_key, ip),
                timeout=self._host_timeout,
            )
        except TimeoutError:
            log.warning("shodan_failed", endpoint="host", ip=ip, error="timeout")
            return ShodanHostResult(ip=ip, enabled=True, error="timeout")
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "rate" in msg.lower() or "quota" in msg.lower() or "429" in msg:
                log.warning("shodan_quota_exceeded", endpoint="host", ip=ip, error=msg)
            else:
                log.warning("shodan_failed", endpoint="host", ip=ip, error=msg)
            return ShodanHostResult(ip=ip, enabled=True, error=msg)

        last_update = _parse_dt(data.get("last_update"))
        result = ShodanHostResult(
            ip=ip,
            enabled=True,
            asn=_int_or_none(data.get("asn")),
            asn_org=_str_or_none(data.get("org")),
            isp=_str_or_none(data.get("isp")),
            banners=_dict_list(data.get("data")),
            last_update=last_update,
        )
        self._cache.set(
            _HOST_PROVIDER,
            cache_key,
            result.model_dump(mode="json"),
            ttl_hours=_DEFAULT_TTL_HOURS,
        )
        log.info(
            "shodan_ok", endpoint="host", ip=ip, banners=len(result.banners)
        )
        return result

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    async def _fetch_internetdb(self, ip: str) -> httpx.Response:
        return await self._client.get(
            f"{_INTERNETDB_BASE}/{ip}", timeout=self._internetdb_timeout
        )


def _run_shodan_host(api_key: str, ip: str) -> dict[str, Any]:
    import shodan

    api = shodan.Shodan(api_key)
    return dict(api.host(ip))


def _int_list(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for v in value:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, dict)]


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value).lstrip("AS"))
    except (TypeError, ValueError):
        return None


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None
