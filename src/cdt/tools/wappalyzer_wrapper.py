"""python-Wappalyzer wrapper (v0.4 §14.5.2 — primary tech stack signal).

Wappalyzer is a synchronous library: ``WebPage.new_from_url`` blocks while
``requests`` fetches HTML, then ``Wappalyzer.analyze_with_categories`` runs
the rule engine. We wrap both calls in a worker thread.

The library reads its rule pack at import time; ``Wappalyzer.latest()``
caches it on the class, so repeated calls in tests don't re-download.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

log = structlog.get_logger()

_DEFAULT_UA = "CDT-Scanner/0.1 (+https://github.com/fortidz/cdt-scanner)"

_WEB_SERVER_CATEGORIES: tuple[str, ...] = ("web-servers", "Web servers")
_CMS_CATEGORIES: tuple[str, ...] = ("cms", "CMS")
_CDN_CATEGORIES: tuple[str, ...] = ("cdn", "CDN")
_FRAMEWORK_CATEGORIES: tuple[str, ...] = (
    "javascript-frameworks",
    "JavaScript frameworks",
    "miscellaneous",
    "Miscellaneous",
    "web-frameworks",
    "Web frameworks",
)


class WappalyzerResult(BaseModel):
    url: str
    technologies: dict[str, list[str]] = Field(default_factory=dict)
    web_server: str | None = None
    cms: str | None = None
    cdn: str | None = None
    frameworks: list[str] = Field(default_factory=list)
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class WappalyzerWrapper:
    def __init__(
        self,
        timeout_sec: float = 30.0,
        user_agent: str | None = None,
    ) -> None:
        self._timeout = timeout_sec
        self._ua = user_agent or os.environ.get("CDT_USER_AGENT") or _DEFAULT_UA

    async def detect(self, url: str) -> WappalyzerResult:
        log.info("wappalyzer_started", url=url)
        try:
            techs = await asyncio.wait_for(
                asyncio.to_thread(_run_wappalyzer, url, self._ua),
                timeout=self._timeout,
            )
        except TimeoutError:
            log.warning("wappalyzer_failed", url=url, error="timeout")
            return WappalyzerResult(url=url, error="timeout")
        except Exception as exc:  # noqa: BLE001
            log.warning("wappalyzer_failed", url=url, error=str(exc))
            return WappalyzerResult(url=url, error=str(exc))

        result = WappalyzerResult(
            url=url,
            technologies=techs,
            web_server=_first_in_categories(techs, _WEB_SERVER_CATEGORIES),
            cms=_first_in_categories(techs, _CMS_CATEGORIES),
            cdn=_first_in_categories(techs, _CDN_CATEGORIES),
            frameworks=_collect_categories(techs, _FRAMEWORK_CATEGORIES),
        )
        log.info(
            "wappalyzer_ok",
            url=url,
            cms=result.cms,
            web_server=result.web_server,
            cdn=result.cdn,
            frameworks=len(result.frameworks),
        )
        return result


def _run_wappalyzer(url: str, user_agent: str) -> dict[str, list[str]]:
    """Sync invocation of python-Wappalyzer; returns ``{category: [tech_names]}``."""

    from Wappalyzer import Wappalyzer, WebPage

    wapp = Wappalyzer.latest()
    page = WebPage.new_from_url(url, headers={"User-Agent": user_agent})
    raw: Any = wapp.analyze_with_categories(page)

    out: dict[str, list[str]] = {}
    if not isinstance(raw, dict):
        return out

    for tech_name, payload in raw.items():
        if not isinstance(payload, dict):
            continue
        categories = payload.get("categories") or []
        if not isinstance(categories, list):
            continue
        for cat in categories:
            cat_str = str(cat)
            out.setdefault(cat_str, []).append(str(tech_name))
    return out


def _first_in_categories(
    techs: dict[str, list[str]], names: tuple[str, ...]
) -> str | None:
    for name in names:
        values = techs.get(name)
        if values:
            return values[0]
    return None


def _collect_categories(
    techs: dict[str, list[str]], names: tuple[str, ...]
) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        for value in techs.get(name, []):
            if value not in seen:
                seen.add(value)
                out.append(value)
    return out
