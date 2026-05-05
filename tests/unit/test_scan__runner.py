"""Tests for RateLimitedPool + ScanRunner."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from cdt.discovery.cache import DiscoveryCache
from cdt.scan.browser import BrowserScanner
from cdt.scan.models import BrowserResult, PassiveResult
from cdt.scan.passive import IPRangesIndex, PassiveScanner
from cdt.scan.runner import RateLimitedPool, ScanRunner


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


async def test_pool__concurrency_limit_enforced() -> None:
    """At most ``concurrency`` workers run at any given moment."""

    pool = RateLimitedPool(concurrency=3, per_key_rps=1000)
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def worker(item: int) -> int:
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        async with lock:
            in_flight -= 1
        return item

    items = list(range(10))
    results = await pool.run(items, worker, key_fn=lambda i: f"k{i}")
    assert sorted(results) == items
    assert peak <= 3


async def test_pool__per_key_rate_limit_throttles() -> None:
    """Two requests on the same key are forced apart by ~1/rps seconds."""

    pool = RateLimitedPool(concurrency=10, per_key_rps=20.0)  # 50ms apart
    timestamps: list[float] = []

    async def worker(item: int) -> int:
        timestamps.append(asyncio.get_running_loop().time())
        return item

    await pool.run([1, 2], worker, key_fn=lambda _i: "shared")

    gap = timestamps[1] - timestamps[0]
    assert gap >= 0.04  # 50ms minus scheduler jitter


async def test_runner__exception_in_one_does_not_kill_run(cache: DiscoveryCache) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)

        async def bad_scan(url: str) -> PassiveResult:
            if "bad" in url:
                raise RuntimeError("simulated failure")
            return PassiveResult(url=url, scanned_at=datetime.now(UTC))

        scanner.scan = bad_scan  # type: ignore[method-assign]
        runner = ScanRunner(pool=RateLimitedPool(concurrency=2, per_key_rps=1000))

        results = await runner.scan_many(
            ["https://ok.example", "https://bad.example", "https://ok2.example"],
            scanner,
            key_fn=lambda u: u,
        )
    finally:
        await idx.aclose()

    assert len(results) == 3
    bad = next(r for r in results if "bad" in r.url)
    assert isinstance(bad, PassiveResult)
    assert bad.errors  # non-empty error list


async def test_runner__results_preserve_order(cache: DiscoveryCache) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)

        async def fast_scan(url: str) -> PassiveResult:
            return PassiveResult(url=url, scanned_at=datetime.now(UTC))

        scanner.scan = fast_scan  # type: ignore[method-assign]
        runner = ScanRunner(pool=RateLimitedPool(concurrency=4, per_key_rps=1000))

        urls = [f"https://acme-{i}.example" for i in range(8)]
        results = await runner.scan_many(urls, scanner, key_fn=lambda u: u)
    finally:
        await idx.aclose()

    assert [r.url for r in results] == urls


async def test_runner__handles_empty_input(cache: DiscoveryCache) -> None:
    idx = IPRangesIndex(cache=cache)
    try:
        scanner = PassiveScanner(ip_ranges=idx)
        runner = ScanRunner()
        results = await runner.scan_many([], scanner)
    finally:
        await idx.aclose()
    assert results == []


async def test_runner__delegates_to_browser_scanner_fetch() -> None:
    """``ScanRunner.scan_many`` calls ``BrowserScanner.fetch`` for browser items."""

    bs = BrowserScanner()
    try:
        bs.fetch = AsyncMock(  # type: ignore[method-assign]
            return_value=BrowserResult(
                url="https://acme.example/",
                status=200,
                final_url="https://acme.example/",
                scanned_at=datetime.now(UTC),
            )
        )
        runner = ScanRunner(pool=RateLimitedPool(concurrency=2, per_key_rps=1000))
        results = await runner.scan_many(
            ["https://acme.example/"], bs, key_fn=lambda u: u
        )
    finally:
        await bs.aclose()

    assert len(results) == 1
    assert isinstance(results[0], BrowserResult)
    assert results[0].status == 200
