"""Asyncio rate-limited pool + cancellation-aware scan runner.

The pool is the canonical pattern from ``cdt-scanner-dev`` skill §3.2: a global
``Semaphore(concurrency)`` plus a per-key ``Lock`` + ``last_call_time``
throttle. ``ScanRunner`` builds on top to add per-item exception isolation —
one site failing must not abort the run.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

import structlog

from cdt.scan.browser import BrowserScanner
from cdt.scan.models import BrowserResult, PassiveResult
from cdt.scan.passive import PassiveScanner

T = TypeVar("T")
R = TypeVar("R")

log = structlog.get_logger()


class RateLimitedPool:
    """Global concurrency cap + per-key request rate cap."""

    def __init__(self, concurrency: int = 20, per_key_rps: float = 2.0) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._per_key_locks: dict[str, asyncio.Lock] = {}
        self._per_key_last: dict[str, float] = {}
        self._min_interval = 1.0 / per_key_rps if per_key_rps > 0 else 0.0

    async def run(
        self,
        items: list[T],
        worker: Callable[[T], Awaitable[R]],
        key_fn: Callable[[T], str],
    ) -> list[R]:
        async def _wrap(item: T) -> R:
            async with self._sem:
                key = key_fn(item)
                lock = self._per_key_locks.setdefault(key, asyncio.Lock())
                async with lock:
                    if self._min_interval > 0:
                        last = self._per_key_last.get(key, 0.0)
                        wait = last + self._min_interval - time.monotonic()
                        if wait > 0:
                            await asyncio.sleep(wait)
                    self._per_key_last[key] = time.monotonic()
                return await worker(item)

        return await asyncio.gather(*(_wrap(i) for i in items))


class ScanRunner:
    """Wraps ``RateLimitedPool`` with per-item exception isolation.

    A failure in one URL is captured into the ``error`` field of the result
    instead of bubbling up and killing the rest of the run.
    """

    def __init__(self, pool: RateLimitedPool | None = None) -> None:
        self._pool = pool or RateLimitedPool()

    async def scan_many(
        self,
        urls: list[str],
        scanner: PassiveScanner | BrowserScanner,
        key_fn: Callable[[str], str] | None = None,
    ) -> list[PassiveResult | BrowserResult]:
        if not urls:
            return []

        kf = key_fn or _default_key

        async def _worker(url: str) -> PassiveResult | BrowserResult:
            try:
                if isinstance(scanner, PassiveScanner):
                    return await scanner.scan(url)
                return await scanner.fetch(url)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan_runner_item_failed", url=url, error=str(exc))
                return _error_envelope(scanner, url, exc)

        results = await self._pool.run(urls, _worker, kf)
        return list(results)


def _default_key(url: str) -> str:
    """Extract a per-key throttle bucket from ``url``.

    Falls back to the raw input if normalisation fails — better to throttle
    too aggressively than to crash the run.
    """

    from cdt.discovery.normalize import apex_of  # local import: avoid cycle

    try:
        return apex_of(url)
    except Exception:  # noqa: BLE001
        return url


def _error_envelope(
    scanner: PassiveScanner | BrowserScanner,
    url: str,
    exc: BaseException,
) -> PassiveResult | BrowserResult:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    msg = f"{type(exc).__name__}: {exc}"
    if isinstance(scanner, PassiveScanner):
        return PassiveResult(url=url, scanned_at=now, errors=[msg])
    return BrowserResult(url=url, status=0, final_url=url, scanned_at=now, error=msg)
