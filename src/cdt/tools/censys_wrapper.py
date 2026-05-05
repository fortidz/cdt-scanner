"""Censys wrapper — Hosts.view + Certs.search (v0.4 §14.5.2).

The censys library is synchronous and reads ``CENSYS_API_ID`` /
``CENSYS_API_SECRET`` from the environment by default. We instantiate the
clients lazily inside the worker thread because they perform a config
file lookup at import time that we do not want to pay during ``__init__``.

If credentials are absent at construction, every method short-circuits to
``enabled=False`` without touching the library.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

from cdt.discovery.cache import DiscoveryCache

log = structlog.get_logger()

_HOST_PROVIDER = "censys_host"
_CERT_PROVIDER = "censys_cert"
_DEFAULT_TTL_HOURS = 24 * 7
_MAX_CERT_RESULTS = 50


class CensysHostResult(BaseModel):
    ip: str
    enabled: bool = False
    services: list[dict[str, Any]] = Field(default_factory=list)
    autonomous_system: dict[str, Any] | None = None
    dns_names: list[str] = Field(default_factory=list)
    operating_system: str | None = None
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class CensysCertResult(BaseModel):
    domain: str
    enabled: bool = False
    certs: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class CensysWrapper:
    def __init__(
        self,
        cache: DiscoveryCache,
        timeout_sec: float = 30.0,
    ) -> None:
        self._cache = cache
        self._timeout = timeout_sec
        self._api_id = os.environ.get("CENSYS_API_ID") or None
        self._api_secret = os.environ.get("CENSYS_API_SECRET") or None
        self._enabled = bool(self._api_id and self._api_secret)

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def lookup_host(self, ip: str) -> CensysHostResult:
        if not self._enabled:
            log.info("censys_skipped", endpoint="host", ip=ip, reason="no_credentials")
            return CensysHostResult(ip=ip, enabled=False)

        cache_key = f"host::{ip}"
        cached = self._cache.get(_HOST_PROVIDER, cache_key)
        if cached is not None:
            log.info("censys_used_cache", endpoint="host", ip=ip)
            return CensysHostResult.model_validate(cached)

        log.info("censys_started", endpoint="host", ip=ip)
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(
                    _run_censys_host, self._api_id, self._api_secret, ip
                ),
                timeout=self._timeout,
            )
        except TimeoutError:
            log.warning("censys_failed", endpoint="host", ip=ip, error="timeout")
            return CensysHostResult(ip=ip, enabled=True, error="timeout")
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "rate" in msg.lower() or "429" in msg or "quota" in msg.lower():
                log.warning("censys_quota_exceeded", endpoint="host", ip=ip, error=msg)
            else:
                log.warning("censys_failed", endpoint="host", ip=ip, error=msg)
            return CensysHostResult(ip=ip, enabled=True, error=msg)

        result = CensysHostResult(
            ip=ip,
            enabled=True,
            services=_dict_list(data.get("services")),
            autonomous_system=_dict_or_none(data.get("autonomous_system")),
            dns_names=_str_list(data.get("dns", {}).get("names")),
            operating_system=_str_or_none(data.get("operating_system", {}).get("product"))
            if isinstance(data.get("operating_system"), dict)
            else _str_or_none(data.get("operating_system")),
        )
        self._cache.set(
            _HOST_PROVIDER,
            cache_key,
            result.model_dump(mode="json"),
            ttl_hours=_DEFAULT_TTL_HOURS,
        )
        log.info(
            "censys_ok",
            endpoint="host",
            ip=ip,
            services=len(result.services),
            dns=len(result.dns_names),
        )
        return result

    async def search_certs(self, domain: str) -> CensysCertResult:
        if not self._enabled:
            log.info(
                "censys_skipped", endpoint="certs", domain=domain, reason="no_credentials"
            )
            return CensysCertResult(domain=domain, enabled=False)

        cache_key = f"certs::{domain.lower()}"
        cached = self._cache.get(_CERT_PROVIDER, cache_key)
        if cached is not None:
            log.info("censys_used_cache", endpoint="certs", domain=domain)
            return CensysCertResult.model_validate(cached)

        log.info("censys_started", endpoint="certs", domain=domain)
        try:
            certs = await asyncio.wait_for(
                asyncio.to_thread(
                    _run_censys_certs, self._api_id, self._api_secret, domain
                ),
                timeout=self._timeout,
            )
        except TimeoutError:
            log.warning(
                "censys_failed", endpoint="certs", domain=domain, error="timeout"
            )
            return CensysCertResult(domain=domain, enabled=True, error="timeout")
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "rate" in msg.lower() or "429" in msg or "quota" in msg.lower():
                log.warning(
                    "censys_quota_exceeded", endpoint="certs", domain=domain, error=msg
                )
            else:
                log.warning("censys_failed", endpoint="certs", domain=domain, error=msg)
            return CensysCertResult(domain=domain, enabled=True, error=msg)

        result = CensysCertResult(
            domain=domain,
            enabled=True,
            certs=_dict_list(certs),
        )
        self._cache.set(
            _CERT_PROVIDER,
            cache_key,
            result.model_dump(mode="json"),
            ttl_hours=_DEFAULT_TTL_HOURS,
        )
        log.info(
            "censys_ok", endpoint="certs", domain=domain, count=len(result.certs)
        )
        return result


def _run_censys_host(api_id: str | None, api_secret: str | None, ip: str) -> dict[str, Any]:
    from censys.search import CensysHosts

    client = CensysHosts(api_id=api_id, api_secret=api_secret)
    return dict(client.view(ip))


def _run_censys_certs(
    api_id: str | None, api_secret: str | None, domain: str
) -> list[dict[str, Any]]:
    from censys.search import CensysCerts

    client = CensysCerts(api_id=api_id, api_secret=api_secret)
    query = f"names: {domain}"
    out: list[dict[str, Any]] = []
    for page in client.search(query, per_page=_MAX_CERT_RESULTS, pages=1):
        if isinstance(page, list):
            out.extend(d for d in page if isinstance(d, dict))
        if len(out) >= _MAX_CERT_RESULTS:
            break
    return out[:_MAX_CERT_RESULTS]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, dict)]


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None]


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
