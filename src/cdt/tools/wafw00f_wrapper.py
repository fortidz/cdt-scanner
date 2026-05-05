"""wafw00f as a library (NOT subprocess) per v0.4 §14.5.2.

wafw00f's main loop is synchronous — we run it in a worker thread to keep the
asyncio scheduler free. Multiple plugin hits collapse to a single vendor by a
fixed priority list; a generic match (no specific plugin) sets ``generic=True``
and leaves ``vendor=None`` so downstream scoring (Phase 5) can decide what
weight to give it.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

log = structlog.get_logger()

_DEFAULT_UA = "CDT-Scanner/0.1 (+https://github.com/fortidz/cdt-scanner)"

# Higher-priority vendors win when multiple plugins match. Anything not in the
# list falls through to alphabetical order — deterministic, no ties.
_VENDOR_PRIORITY: tuple[str, ...] = (
    "Cloudflare",
    "AWS_CloudFront_WAF",
    "Akamai",
    "Azure_FrontDoor_WAF",
    "Fortinet_FortiWeb",
    "Imperva",
)


class WafDetection(BaseModel):
    url: str
    vendor: str | None = None
    generic: bool = False
    raw_hits: list[str] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class WafW00fWrapper:
    def __init__(
        self,
        timeout_sec: float = 30.0,
        user_agent: str | None = None,
    ) -> None:
        self._timeout = timeout_sec
        self._ua = user_agent or os.environ.get("CDT_USER_AGENT") or _DEFAULT_UA

    async def detect(self, url: str) -> WafDetection:
        log.info("wafw00f_started", url=url)
        try:
            hits, generic = await asyncio.wait_for(
                asyncio.to_thread(_run_wafw00f, url, self._ua),
                timeout=self._timeout,
            )
        except TimeoutError:
            log.warning("wafw00f_error", url=url, error="timeout")
            return WafDetection(url=url, vendor=None, generic=False, raw_hits=[])
        except Exception as exc:  # noqa: BLE001
            log.warning("wafw00f_error", url=url, error=str(exc))
            return WafDetection(url=url, vendor=None, generic=False, raw_hits=[])

        if not hits and not generic:
            log.info("wafw00f_no_match", url=url)
            return WafDetection(url=url, vendor=None, generic=False, raw_hits=[])

        if not hits and generic:
            log.info("wafw00f_detected", url=url, vendor=None, generic=True)
            return WafDetection(url=url, vendor=None, generic=True, raw_hits=[])

        vendor = _pick_vendor(hits)
        log.info("wafw00f_detected", url=url, vendor=vendor, hits=len(hits))
        return WafDetection(
            url=url,
            vendor=vendor,
            generic=False,
            raw_hits=list(hits),
        )


def _pick_vendor(hits: list[str]) -> str:
    if len(hits) == 1:
        return hits[0]
    for preferred in _VENDOR_PRIORITY:
        if preferred in hits:
            return preferred
    return sorted(hits)[0]


def _run_wafw00f(url: str, user_agent: str) -> tuple[list[str], bool]:
    """Synchronous wafw00f invocation. Returns ``(plugin_hits, generic_match)``."""

    from wafw00f.main import WAFW00F  # local import: heavy module

    headers: dict[str, str] = {"User-Agent": user_agent}
    scanner = WAFW00F(target=url, headers=headers)
    try:
        scanner.normalRequest()
    except Exception:  # noqa: BLE001
        # If the baseline request fails, plugin probes won't be reliable
        # either — give up cleanly.
        return [], False

    plugin_hits: list[str] = []
    try:
        identified = scanner.identwaf(findall=True)
    except Exception:  # noqa: BLE001
        identified = []
    if isinstance(identified, list):
        plugin_hits = [str(h) for h in identified if h]

    generic_match = False
    if not plugin_hits:
        try:
            generic_match = bool(scanner.genericdetect())
        except Exception:  # noqa: BLE001
            generic_match = False

    return plugin_hits, generic_match


# Silence "unused import" reports where ``Any`` would otherwise be flagged
# in interpreters that strip type-only references.
_ = Any
