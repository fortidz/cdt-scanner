"""Nikto subprocess wrapper with streaming + early termination (v0.4 §14.5.2).

Tier 2 runs nikto in *probe* mode: it stops as soon as the three target
fields (``WAFVendor``, ``CMSFramework``, ``WebServer``) are resolved, or
when the request cap (400) is hit, whichever comes first. Tier 3 runs the
full tuning matrix without early termination, capped only by ``-maxtime``.

The wrapper writes one entry to ``nikto_runs.jsonl`` per run (regardless
of termination reason) per v0.4 §14.5.2.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cdt.discovery.normalize import parse_url
from cdt.errors import InputError

log = structlog.get_logger()

_DEFAULT_UA = "CDT-Scanner/0.1 (+https://github.com/fortidz/cdt-scanner)"
_DEFAULT_JOURNAL = Path("./out/nikto_runs.jsonl")

STOP_FIELDS: tuple[str, ...] = ("WAFVendor", "CMSFramework", "WebServer")
HARD_REQ_CAP = 400
HARD_TIME_CAP_SEC = 300


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class NiktoFinding(BaseModel):
    osvdb_id: str | None = None
    msg: str
    severity: str = "Medium"
    url_path: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class NiktoResult(BaseModel):
    url: str
    mode: str  # tier2 | tier3 | skipped
    termination: str
    reqs_sent: int = 0
    elapsed_sec: float = 0.0
    findings: list[NiktoFinding] = Field(default_factory=list)
    resolved_fields: list[str] = Field(default_factory=list)
    scanned_at: datetime
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class _OnSkipConfig(BaseModel):
    emit_finding: bool = False
    finding_code: str = "NIKTO_SKIPPED_SENSITIVE_DOMAIN"
    severity: str = "Low"
    message: str = "Nikto skipped due to nikto_skip.yaml rule."

    model_config = ConfigDict(extra="ignore")


class _AllowlistConfig(BaseModel):
    version: str = "1.0.0"
    skip_suffixes: list[str] = Field(default_factory=list)
    skip_apex: list[str] = Field(default_factory=list)
    on_skip: _OnSkipConfig = Field(default_factory=_OnSkipConfig)

    model_config = ConfigDict(extra="ignore")


class NiktoSkipAllowlist:
    """Encapsulates the skip rules + matching logic from ``nikto_skip.yaml``."""

    def __init__(self, config: _AllowlistConfig) -> None:
        self._suffixes = [s.lower() for s in config.skip_suffixes]
        self._apex = [a.lower() for a in config.skip_apex]
        self._on_skip = config.on_skip

    @classmethod
    def from_yaml(cls, path: Path) -> NiktoSkipAllowlist:
        with path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        config = _AllowlistConfig.model_validate(raw)
        return cls(config)

    @classmethod
    def empty(cls) -> NiktoSkipAllowlist:
        return cls(_AllowlistConfig())

    def matches(self, url: str) -> bool:
        try:
            parts = parse_url(url)
        except InputError:
            return False
        apex = parts["apex"].lower()
        host = (
            f"{parts['subdomain']}.{apex}".lower()
            if parts["subdomain"]
            else apex
        )

        for suffix in self._suffixes:
            if host.endswith(suffix.lower()):
                return True
        for ap in self._apex:
            if apex == ap.lower() or host == ap.lower():
                return True
        return False


# ---------------------------------------------------------------------------
# Wrapper
# ---------------------------------------------------------------------------


class NiktoWrapper:
    def __init__(
        self,
        allowlist: NiktoSkipAllowlist,
        timeout_sec: float = 320.0,
        user_agent: str | None = None,
        journal_path: Path | None = None,
    ) -> None:
        self._allowlist = allowlist
        self._timeout = timeout_sec
        self._ua = user_agent or os.environ.get("CDT_USER_AGENT") or _DEFAULT_UA
        self._journal_path = journal_path or _DEFAULT_JOURNAL

    async def run_tier2(
        self, url: str, initial_state: dict[str, str | None]
    ) -> NiktoResult:
        unresolved = [f for f in STOP_FIELDS if not initial_state.get(f)]
        if not unresolved:
            log.info("nikto_skipped", url=url, reason="all_fields_resolved")
            result = self._make_skipped(
                url, mode="tier2", termination="not_needed",
                resolved=[f for f in STOP_FIELDS if initial_state.get(f)],
            )
            self._write_journal(result, trigger_reason="not_needed")
            return result

        if self._allowlist.matches(url):
            log.info("nikto_skipped", url=url, reason="allowlist")
            result = self._make_skipped(
                url, mode="tier2", termination="skipped_allowlist", resolved=[]
            )
            self._write_journal(result, trigger_reason="allowlist")
            return result

        if shutil.which("nikto") is None:
            log.warning("nikto_skipped", url=url, reason="binary_missing")
            result = self._make_skipped(
                url,
                mode="tier2",
                termination="binary_missing",
                resolved=[],
                error="nikto not found in PATH",
            )
            self._write_journal(result, trigger_reason="binary_missing")
            return result

        return await self._stream_tier2(url, initial_state, unresolved)

    async def run_tier3(self, url: str) -> NiktoResult:
        if self._allowlist.matches(url):
            log.info("nikto_skipped", url=url, reason="allowlist")
            result = self._make_skipped(
                url, mode="tier3", termination="skipped_allowlist", resolved=[]
            )
            self._write_journal(result, trigger_reason="allowlist")
            return result

        if shutil.which("nikto") is None:
            log.warning("nikto_skipped", url=url, reason="binary_missing")
            result = self._make_skipped(
                url,
                mode="tier3",
                termination="binary_missing",
                resolved=[],
                error="nikto not found in PATH",
            )
            self._write_journal(result, trigger_reason="binary_missing")
            return result

        return await self._stream_tier3(url)

    # ---- streaming runs ---------------------------------------------------

    async def _stream_tier2(
        self,
        url: str,
        initial_state: dict[str, str | None],
        unresolved: list[str],
    ) -> NiktoResult:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            output_path = Path(tmp.name)

        cmd = [
            "nikto", "-host", url,
            "-Tuning", "b,a,5",
            "-Pause", "2",
            "-maxtime", str(HARD_TIME_CAP_SEC),
            "-Format", "json",
            "-output", str(output_path),
            "-useragent", self._ua,
            "-nointeractive",
        ]
        log.info("nikto_started", url=url, mode="tier2", unresolved=unresolved)

        state = dict(initial_state)
        start = time.monotonic()
        reqs = 0
        termination = "completed"

        try:
            proc = await _start_nikto_proc(cmd)
        except FileNotFoundError as exc:
            output_path.unlink(missing_ok=True)
            return self._make_error(
                url, mode="tier2", termination="error", error=str(exc)
            )

        try:
            assert proc.stdout is not None
            while True:
                if time.monotonic() - start > self._timeout:
                    termination = "timeout"
                    break

                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").rstrip("\n")

                if _line_is_request(line):
                    reqs += 1

                updates = _parse_nikto_line(line)
                state.update({k: v for k, v in updates.items() if v})

                resolved_now = {f for f in STOP_FIELDS if state.get(f)}
                if set(unresolved).issubset(resolved_now):
                    termination = "resolved_all_fields"
                    break
                if reqs >= HARD_REQ_CAP:
                    termination = "request_cap"
                    break
        finally:
            await _terminate(proc)

        elapsed = time.monotonic() - start
        findings = _parse_output_json(output_path)
        output_path.unlink(missing_ok=True)

        resolved_fields = [f for f in STOP_FIELDS if state.get(f)]
        result = NiktoResult(
            url=url,
            mode="tier2",
            termination=termination,
            reqs_sent=reqs,
            elapsed_sec=elapsed,
            findings=findings,
            resolved_fields=resolved_fields,
            scanned_at=datetime.now(UTC),
        )
        self._write_journal(
            result,
            trigger_reason=",".join(f"unresolved_{f}" for f in unresolved),
            tuning="b,a,5",
        )
        log.info(
            "nikto_ok" if termination == "completed" else "nikto_early_term",
            url=url,
            termination=termination,
            reqs=reqs,
            elapsed=round(elapsed, 2),
            findings=len(findings),
        )
        return result

    async def _stream_tier3(self, url: str) -> NiktoResult:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            output_path = Path(tmp.name)

        cmd = [
            "nikto", "-host", url,
            "-Tuning", "1,2,3,4,5,6,7,8,9,0,a,b,c,x",
            "-maxtime", "900",
            "-Format", "json",
            "-output", str(output_path),
            "-useragent", self._ua,
            "-nointeractive",
        ]
        log.info("nikto_started", url=url, mode="tier3")

        start = time.monotonic()
        reqs = 0
        termination = "completed"

        try:
            proc = await _start_nikto_proc(cmd)
        except FileNotFoundError as exc:
            output_path.unlink(missing_ok=True)
            return self._make_error(
                url, mode="tier3", termination="error", error=str(exc)
            )

        try:
            assert proc.stdout is not None
            while True:
                if time.monotonic() - start > self._timeout:
                    termination = "timeout"
                    break
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                if _line_is_request(line_bytes.decode("utf-8", errors="replace")):
                    reqs += 1
        finally:
            await _terminate(proc)

        elapsed = time.monotonic() - start
        findings = _parse_output_json(output_path)
        output_path.unlink(missing_ok=True)

        result = NiktoResult(
            url=url,
            mode="tier3",
            termination=termination,
            reqs_sent=reqs,
            elapsed_sec=elapsed,
            findings=findings,
            resolved_fields=[],
            scanned_at=datetime.now(UTC),
        )
        self._write_journal(
            result, trigger_reason="tier3_full", tuning="1,2,3,4,5,6,7,8,9,0,a,b,c,x"
        )
        log.info(
            "nikto_ok",
            url=url,
            termination=termination,
            reqs=reqs,
            findings=len(findings),
        )
        return result

    # ---- helpers ----------------------------------------------------------

    def _make_skipped(
        self,
        url: str,
        *,
        mode: str,
        termination: str,
        resolved: list[str],
        error: str | None = None,
    ) -> NiktoResult:
        return NiktoResult(
            url=url,
            mode="skipped" if mode == "skipped" else mode,
            termination=termination,
            reqs_sent=0,
            elapsed_sec=0.0,
            findings=[],
            resolved_fields=resolved,
            scanned_at=datetime.now(UTC),
            error=error,
        )

    def _make_error(
        self,
        url: str,
        *,
        mode: str,
        termination: str,
        error: str,
    ) -> NiktoResult:
        return NiktoResult(
            url=url,
            mode=mode,
            termination=termination,
            scanned_at=datetime.now(UTC),
            error=error,
        )

    def _write_journal(
        self,
        result: NiktoResult,
        *,
        trigger_reason: str,
        tuning: str = "",
    ) -> None:
        try:
            self._journal_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "timestamp": result.scanned_at.isoformat().replace("+00:00", "Z"),
                "url": result.url,
                "tier": result.mode,
                "trigger_reason": trigger_reason,
                "tuning": tuning,
                "reqs_sent": result.reqs_sent,
                "elapsed_sec": round(result.elapsed_sec, 2),
                "termination": result.termination,
                "resolved_fields": list(result.resolved_fields),
            }
            with self._journal_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:
            log.warning("nikto_journal_write_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Module-level helpers (patchable in tests)
# ---------------------------------------------------------------------------


_REQUEST_LINE_RE = re.compile(r"^\+\s+/")
_SERVER_LINE_RE = re.compile(r"^\+\s+Server:\s*(.+)$", re.IGNORECASE)
_CMS_KEYWORDS: dict[str, str] = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "magento": "Magento",
}
_WAF_KEYWORDS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "cf-ray": "Cloudflare",
    "akamai": "Akamai",
    "fortiweb": "FortiWeb",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "cloudfront": "AWS_CloudFront",
}


def _parse_nikto_line(line: str) -> dict[str, str]:
    """Inspect ``line`` of nikto stdout for resolved-field signals.

    Returns a dict with ``WebServer`` / ``CMSFramework`` / ``WAFVendor`` keys
    set when the line provides evidence. Empty dict if the line is noise.
    """

    out: dict[str, str] = {}

    server_match = _SERVER_LINE_RE.match(line)
    if server_match:
        out["WebServer"] = server_match.group(1).strip()

    lc = line.lower()
    for needle, vendor in _CMS_KEYWORDS.items():
        if needle in lc:
            out["CMSFramework"] = vendor
            break

    for needle, vendor in _WAF_KEYWORDS.items():
        if needle in lc:
            out["WAFVendor"] = vendor
            break

    return out


def _line_is_request(line: str) -> bool:
    return bool(_REQUEST_LINE_RE.search(line))


def _parse_output_json(path: Path) -> list[NiktoFinding]:
    """Parse nikto's JSON output. Tolerates partial/missing files."""

    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return []
    if not text:
        return []

    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError:
        return []

    raw_findings: list[Any] = []
    if isinstance(payload, dict):
        vulns = payload.get("vulnerabilities")
        if isinstance(vulns, list):
            raw_findings = vulns
    elif isinstance(payload, list):
        raw_findings = payload

    findings: list[NiktoFinding] = []
    for entry in raw_findings:
        if not isinstance(entry, dict):
            continue
        try:
            findings.append(
                NiktoFinding(
                    osvdb_id=_str_or_none(entry.get("OSVDB") or entry.get("osvdb_id")),
                    msg=str(entry.get("msg") or entry.get("message") or ""),
                    severity=str(entry.get("severity") or "Medium"),
                    url_path=_str_or_none(entry.get("url") or entry.get("uri")),
                )
            )
        except ValidationError:
            continue
    return findings


def _str_or_none(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


async def _start_nikto_proc(cmd: list[str]) -> asyncio.subprocess.Process:
    """Subprocess factory — patchable in tests via ``unittest.mock.patch``."""

    return await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def _terminate(proc: Any) -> None:
    """SIGTERM with a 10s grace, then SIGKILL. Tolerates already-dead procs."""

    try:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10.0)
            except TimeoutError:
                with _suppress_exc():
                    proc.kill()
                with _suppress_exc():
                    await proc.wait()
    except ProcessLookupError:
        return


from contextlib import contextmanager  # noqa: E402


@contextmanager
def _suppress_exc():  # type: ignore[no-untyped-def]
    try:
        yield
    except Exception:  # noqa: BLE001
        pass
