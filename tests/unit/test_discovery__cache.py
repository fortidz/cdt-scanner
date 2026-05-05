"""Tests for the JSON-on-disk DiscoveryCache."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from cdt.discovery.cache import DiscoveryCache


@pytest.fixture
def cache(tmp_path: Path) -> DiscoveryCache:
    return DiscoveryCache(base_dir=tmp_path)


def test_cache__set_and_get_round_trip(cache: DiscoveryCache) -> None:
    """A value written under (provider, key) is read back identically."""

    value = {"hits": 3, "top": "https://acme.com/"}
    cache.set("brave_search", "validate::acme::acme.com", value)

    got = cache.get("brave_search", "validate::acme::acme.com")
    assert got == value


def test_cache__expired_returns_none(tmp_path: Path) -> None:
    """An entry past its expires_at_iso must be treated as a miss."""

    cache = DiscoveryCache(base_dir=tmp_path, default_ttl_hours=24)
    cache.set("brave_search", "k", {"x": 1})

    # Rewrite the file with an already-past expiration to simulate staleness.
    target = next((tmp_path / "brave_search").iterdir())
    expired_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    target.write_text(
        f'{{"key":"k","value":{{"x":1}},"expires_at_iso":"{expired_at}"}}',
        encoding="utf-8",
    )

    assert cache.get("brave_search", "k") is None


def test_cache__missing_key_returns_none(cache: DiscoveryCache) -> None:
    """No file for the key → ``get`` returns None without raising."""

    assert cache.get("brave_search", "never-written") is None


def test_cache__atomic_write_no_partial_files(tmp_path: Path) -> None:
    """If ``os.replace`` fails mid-rename, no corrupted entry is left visible."""

    cache = DiscoveryCache(base_dir=tmp_path)

    with patch("cdt.discovery.cache.os.replace", side_effect=OSError("boom")):
        with pytest.raises(OSError, match="boom"):
            cache.set("brave_search", "atomic-key", {"x": 1})

    # The cache reports a miss…
    assert cache.get("brave_search", "atomic-key") is None

    # …and no leftover ``.tmp`` or partial ``.json`` files are visible.
    provider_dir = tmp_path / "brave_search"
    leftover = list(provider_dir.iterdir()) if provider_dir.exists() else []
    assert leftover == [], f"unexpected leftover files: {leftover}"
