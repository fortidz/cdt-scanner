"""File-based JSON cache for discovery results.

Each entry lives at ``<base_dir>/<provider>/<sha256(key)>.json`` and contains
``{"key", "value", "expires_at_iso"}``. Writes are atomic via a temp file +
``os.replace`` so a partial write cannot leave a corrupted entry visible.

Inspectable on disk on purpose — operators can ``cat`` an entry to debug
discovery issues without bringing in ``diskcache`` semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class DiscoveryCache:
    def __init__(self, base_dir: Path, default_ttl_hours: int = 168) -> None:
        self._base = Path(base_dir)
        self._default_ttl = default_ttl_hours

    def _path_for(self, provider: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._base / provider / f"{digest}.json"

    def get(self, provider: str, key: str) -> dict[str, Any] | None:
        path = self._path_for(provider, key)
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        expires_at_iso = raw.get("expires_at_iso")
        if not isinstance(expires_at_iso, str):
            return None
        try:
            expires_at = datetime.fromisoformat(expires_at_iso)
        except ValueError:
            return None
        if expires_at <= datetime.now(UTC):
            return None

        value = raw.get("value")
        return value if isinstance(value, dict) else None

    def set(
        self,
        provider: str,
        key: str,
        value: dict[str, Any],
        ttl_hours: int | None = None,
    ) -> None:
        ttl = ttl_hours if ttl_hours is not None else self._default_ttl
        expires_at = datetime.now(UTC) + timedelta(hours=ttl)
        payload = {
            "key": key,
            "value": value,
            "expires_at_iso": expires_at.isoformat(),
        }

        path = self._path_for(provider, key)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: serialise to a sibling temp file then os.replace.
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".",
            suffix=".tmp",
            dir=str(path.parent),
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except Exception:
            # Avoid leaving a stale temp file behind on any failure.
            tmp_path.unlink(missing_ok=True)
            raise
