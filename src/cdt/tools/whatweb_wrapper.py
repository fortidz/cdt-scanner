"""whatweb subprocess wrapper (v0.4 §14.5.2).

whatweb writes one JSON object per scanned site to ``--log-json``. We invoke
it via ``subprocess.run`` in a worker thread, then map the plugin output to
normalised fields (web server, CMS, CDN/WAF signals).

Aggression level is configurable per call: Tier 2 default is 3 (Aggressive,
~5–15 requests). Tier 3 bumps to 4 (Heavy). The orchestrator (Phase 6+)
chooses the value; this wrapper stays tier-agnostic.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

log = structlog.get_logger()

_DEFAULT_UA = "CDT-Scanner/0.1 (+https://github.com/fortidz/cdt-scanner)"

_CMS_PLUGINS: tuple[str, ...] = ("WordPress", "Drupal", "Joomla", "Magento")
_CDN_PLUGINS: tuple[str, ...] = ("Cloudflare", "CloudFront", "Akamai", "Fastly")
_WAF_PLUGINS: tuple[str, ...] = (
    "Cloudflare",
    "CloudFront",
    "FortiWeb",
    "Imperva",
    "AkamaiGHost",
)


class WhatWebResult(BaseModel):
    url: str
    plugins: dict[str, list[str]] = Field(default_factory=dict)
    http_server: str | None = None
    cms: str | None = None
    cdn_signals: list[str] = Field(default_factory=list)
    waf_signals: list[str] = Field(default_factory=list)
    raw_json: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    exit_code: int | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class WhatWebWrapper:
    def __init__(
        self,
        timeout_sec: float = 60.0,
        user_agent: str | None = None,
        aggression_level: int = 3,
    ) -> None:
        self._timeout = timeout_sec
        self._ua = user_agent or os.environ.get("CDT_USER_AGENT") or _DEFAULT_UA
        self._aggression = aggression_level

    async def detect(self, url: str, aggression: int | None = None) -> WhatWebResult:
        level = aggression if aggression is not None else self._aggression
        log.info("whatweb_started", url=url, aggression=level)

        try:
            exit_code, raw = await asyncio.wait_for(
                asyncio.to_thread(_run_whatweb, url, level, self._ua),
                timeout=self._timeout,
            )
        except TimeoutError:
            log.warning("whatweb_failed", url=url, error="timeout")
            return WhatWebResult(url=url, error="timeout", exit_code=None)
        except Exception as exc:  # noqa: BLE001
            log.warning("whatweb_failed", url=url, error=str(exc))
            return WhatWebResult(url=url, error=str(exc), exit_code=None)

        if exit_code != 0 and not raw:
            log.warning("whatweb_failed", url=url, exit_code=exit_code)
            return WhatWebResult(
                url=url,
                error=f"whatweb exit {exit_code}",
                exit_code=exit_code,
            )

        plugins = _flatten_plugins(raw)
        result = WhatWebResult(
            url=url,
            plugins=plugins,
            http_server=_pick_first(plugins.get("HTTPServer")),
            cms=_pick_cms(plugins),
            cdn_signals=_match_signals(plugins, _CDN_PLUGINS),
            waf_signals=_match_signals(plugins, _WAF_PLUGINS),
            raw_json=raw,
            error=None,
            exit_code=exit_code,
        )
        log.info(
            "whatweb_ok",
            url=url,
            cms=result.cms,
            http_server=result.http_server,
            cdn=len(result.cdn_signals),
            waf=len(result.waf_signals),
        )
        return result


def _run_whatweb(
    url: str, aggression: int, user_agent: str
) -> tuple[int, dict[str, Any]]:
    """Synchronous whatweb invocation. Returns ``(exit_code, parsed_json)``."""

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json_path = Path(tmp.name)

    try:
        cmd = [
            "whatweb",
            "-q",
            "-a",
            str(aggression),
            f"--log-json={json_path}",
            "-U",
            user_agent,
            "--no-errors",
            url,
        ]
        proc = subprocess.run(  # noqa: S603 — args are list, no shell
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            text = json_path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""

        parsed: dict[str, Any] = {}
        if text:
            # whatweb emits a JSON array (one object per scanned URL).
            decoded: Any
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, list) and decoded:
                first = decoded[0]
                if isinstance(first, dict):
                    parsed = first
            elif isinstance(decoded, dict):
                parsed = decoded
        return proc.returncode, parsed
    finally:
        json_path.unlink(missing_ok=True)


def _flatten_plugins(raw: dict[str, Any]) -> dict[str, list[str]]:
    """``raw['plugins']`` shape is ``{plugin_name: {string: [...], version: [...]}}``.

    We collapse each plugin's string + version arrays into a single list of
    matched values; downstream callers don't need the sub-keys.
    """

    plugins = raw.get("plugins")
    if not isinstance(plugins, dict):
        return {}

    out: dict[str, list[str]] = {}
    for name, payload in plugins.items():
        if not isinstance(payload, dict):
            continue
        values: list[str] = []
        for key in ("string", "version", "module", "account"):
            v = payload.get(key)
            if isinstance(v, list):
                values.extend(str(item) for item in v if item is not None)
        if not values:
            # plugin matched but exposed no extractable detail — keep the name
            values = [name]
        out[name] = values
    return out


def _pick_first(values: list[str] | None) -> str | None:
    if not values:
        return None
    return values[0]


def _pick_cms(plugins: dict[str, list[str]]) -> str | None:
    for cms in _CMS_PLUGINS:
        if cms in plugins:
            return cms
    return None


def _match_signals(
    plugins: dict[str, list[str]], catalog: tuple[str, ...]
) -> list[str]:
    return [name for name in catalog if name in plugins]
