"""Tests for the nikto wrapper (streaming + early term + allowlist)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cdt.tools import NiktoFinding, NiktoSkipAllowlist, NiktoWrapper

FIXTURES = Path(__file__).parent.parent / "fixtures" / "nikto"


# ---------------------------------------------------------------------------
# Fake subprocess infrastructure — used by every streaming test.
# ---------------------------------------------------------------------------


class _FakeStream:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)

    async def readline(self) -> bytes:
        if self._lines:
            return self._lines.pop(0)
        return b""


class _FakeProc:
    def __init__(self, lines: list[bytes]) -> None:
        self.stdout = _FakeStream(lines)
        self.returncode: int | None = None
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode or 0


def _make_proc_factory(lines: list[bytes]) -> tuple[AsyncMock, _FakeProc]:
    """Returns ``(start_mock, proc)`` so tests can inspect the proc afterwards."""

    proc = _FakeProc(lines)

    async def factory(_cmd: list[str]) -> _FakeProc:
        return proc

    return AsyncMock(side_effect=factory), proc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def allowlist() -> NiktoSkipAllowlist:
    """Allowlist matching the canonical config/nikto_skip.yaml shape."""

    yaml_path = (
        Path(__file__).parent.parent.parent / "config" / "nikto_skip.yaml"
    )
    return NiktoSkipAllowlist.from_yaml(yaml_path)


@pytest.fixture
def journal_path(tmp_path: Path) -> Path:
    return tmp_path / "nikto_runs.jsonl"


@pytest.fixture
def wrapper(
    allowlist: NiktoSkipAllowlist, journal_path: Path
) -> NiktoWrapper:
    return NiktoWrapper(allowlist=allowlist, journal_path=journal_path)


# ---------------------------------------------------------------------------
# Tests — skip paths
# ---------------------------------------------------------------------------


async def test_nikto__skipped_when_all_fields_already_resolved(
    wrapper: NiktoWrapper, journal_path: Path
) -> None:
    state = {
        "WebServer": "nginx/1.24",
        "CMSFramework": "WordPress",
        "WAFVendor": "Cloudflare",
    }

    with patch("cdt.tools.nikto_wrapper._start_nikto_proc") as spy:
        result = await wrapper.run_tier2("https://acme.example", state)

    assert result.termination == "not_needed"
    assert result.findings == []
    spy.assert_not_called()
    assert journal_path.exists()


async def test_nikto__skipped_when_url_matches_allowlist_suffix(
    wrapper: NiktoWrapper,
) -> None:
    """``*.gob.pe`` is in the canonical allowlist."""

    with patch("cdt.tools.nikto_wrapper._start_nikto_proc") as spy:
        result = await wrapper.run_tier2(
            "https://www.minsa.gob.pe", {"WAFVendor": None,
                                         "CMSFramework": None,
                                         "WebServer": None}
        )

    assert result.termination == "skipped_allowlist"
    spy.assert_not_called()


async def test_nikto__skipped_when_url_matches_allowlist_apex(
    wrapper: NiktoWrapper,
) -> None:
    """The exact apex ``bcrp.gob.pe`` is in ``skip_apex`` (and ``.gob.pe`` suffix)."""

    with patch("cdt.tools.nikto_wrapper._start_nikto_proc") as spy:
        result = await wrapper.run_tier2(
            "https://bcrp.gob.pe", {"WAFVendor": None,
                                    "CMSFramework": None,
                                    "WebServer": None}
        )

    assert result.termination == "skipped_allowlist"
    spy.assert_not_called()


async def test_nikto__skipped_when_binary_missing(
    wrapper: NiktoWrapper,
) -> None:
    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value=None), patch(
        "cdt.tools.nikto_wrapper._start_nikto_proc"
    ) as spy:
        result = await wrapper.run_tier2(
            "https://acme.example",
            {"WAFVendor": None, "CMSFramework": None, "WebServer": None},
        )

    assert result.termination == "binary_missing"
    assert "PATH" in (result.error or "")
    spy.assert_not_called()


# ---------------------------------------------------------------------------
# Tests — streaming + early termination
# ---------------------------------------------------------------------------


async def test_nikto__tier2_early_termination_on_all_fields_resolved(
    wrapper: NiktoWrapper,
) -> None:
    """Three target fields resolved → SIGTERM + termination=resolved_all_fields."""

    lines = [
        b"+ Server: nginx/1.24.0\n",
        b"+ /xmlrpc.php WordPress XML-RPC endpoint\n",
        b"+ Cloudflare detected via header cf-ray\n",
        b"",  # readline returns empty when proc dies
    ]
    factory, proc = _make_proc_factory(lines)

    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value="/usr/bin/nikto"), \
            patch("cdt.tools.nikto_wrapper._start_nikto_proc", new=factory):
        result = await wrapper.run_tier2(
            "https://acme.example",
            {"WAFVendor": None, "CMSFramework": None, "WebServer": None},
        )

    assert result.termination == "resolved_all_fields"
    assert set(result.resolved_fields) == {"WAFVendor", "CMSFramework", "WebServer"}
    assert proc.terminated is True


async def test_nikto__tier2_termination_on_request_cap(
    wrapper: NiktoWrapper,
) -> None:
    """No fields resolved but 401 request lines → termination=request_cap."""

    lines = [b"+ /found-" + str(i).encode() + b"/: Hit\n" for i in range(401)]
    lines.append(b"")
    factory, proc = _make_proc_factory(lines)

    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value="/usr/bin/nikto"), \
            patch("cdt.tools.nikto_wrapper._start_nikto_proc", new=factory):
        result = await wrapper.run_tier2(
            "https://acme.example",
            {"WAFVendor": None, "CMSFramework": None, "WebServer": None},
        )

    assert result.termination == "request_cap"
    assert result.reqs_sent >= 400
    assert proc.terminated is True


async def test_nikto__tier2_termination_on_timeout(
    allowlist: NiktoSkipAllowlist, journal_path: Path
) -> None:
    """Wall-clock budget elapsing while readline is blocking → termination=timeout."""

    wrapper = NiktoWrapper(
        allowlist=allowlist,
        timeout_sec=0.05,
        journal_path=journal_path,
    )

    class _SlowStream:
        async def readline(self) -> bytes:
            import asyncio

            await asyncio.sleep(0.2)
            return b"+ /admin/: late line\n"

    proc = MagicMock()
    proc.stdout = _SlowStream()
    proc.returncode = None
    proc.terminate = MagicMock(side_effect=lambda: setattr(proc, "returncode", -15))
    proc.kill = MagicMock(side_effect=lambda: setattr(proc, "returncode", -9))
    proc.wait = AsyncMock(return_value=-15)

    async def factory(_cmd: list[str]) -> object:
        return proc

    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value="/usr/bin/nikto"), \
            patch("cdt.tools.nikto_wrapper._start_nikto_proc", side_effect=factory):
        result = await wrapper.run_tier2(
            "https://acme.example",
            {"WAFVendor": None, "CMSFramework": None, "WebServer": None},
        )

    assert result.termination == "timeout"


async def test_nikto__tier3_runs_with_full_tuning(
    wrapper: NiktoWrapper,
    tmp_path: Path,
) -> None:
    """Tier 3 reads JSON output without early termination."""

    lines = [
        b"+ /admin/: Admin found\n",
        b"+ /readme.html: WordPress readme\n",
        b"",
    ]
    factory, _proc = _make_proc_factory(lines)

    fixture_payload = json.loads(
        (FIXTURES / "tier3_full.json").read_text(encoding="utf-8")
    )

    captured_cmd: dict[str, list[str]] = {}

    async def factory_with_capture(cmd: list[str]) -> object:
        captured_cmd["cmd"] = cmd
        return await factory(cmd)

    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value="/usr/bin/nikto"), \
            patch("cdt.tools.nikto_wrapper._start_nikto_proc",
                  side_effect=factory_with_capture), \
            patch("cdt.tools.nikto_wrapper._parse_output_json",
                  return_value=[
                      NiktoFinding(osvdb_id=str(v["OSVDB"]),
                                   msg=v["msg"], severity=v["severity"],
                                   url_path=v["uri"])
                      for v in fixture_payload["vulnerabilities"]
                  ]):
        result = await wrapper.run_tier3("https://acme.example")

    assert result.mode == "tier3"
    assert "1,2,3,4,5,6,7,8,9,0,a,b,c,x" in captured_cmd["cmd"]
    assert "-maxtime" in captured_cmd["cmd"]
    assert len(result.findings) == 5


async def test_nikto__findings_parsed_from_json_output(tmp_path: Path) -> None:
    """``_parse_output_json`` reads the JSON the subprocess wrote."""

    from cdt.tools.nikto_wrapper import _parse_output_json

    payload = json.loads(
        (FIXTURES / "tier3_full.json").read_text(encoding="utf-8")
    )
    output = tmp_path / "nikto.json"
    output.write_text(json.dumps(payload), encoding="utf-8")

    findings = _parse_output_json(output)
    assert len(findings) == 5
    assert findings[0].osvdb_id == "3268"
    assert findings[0].url_path == "/files/"


async def test_nikto__findings_empty_when_output_missing(tmp_path: Path) -> None:
    """A missing JSON output file yields ``findings=[]`` without raising."""

    from cdt.tools.nikto_wrapper import _parse_output_json

    findings = _parse_output_json(tmp_path / "nope.json")
    assert findings == []


async def test_nikto__journal_jsonl_written_with_correct_shape(
    wrapper: NiktoWrapper, journal_path: Path
) -> None:
    """One JSONL line per run with all expected keys."""

    lines = [b"+ Server: apache/2.4.1\n", b""]
    factory, _proc = _make_proc_factory(lines)

    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value="/usr/bin/nikto"), \
            patch("cdt.tools.nikto_wrapper._start_nikto_proc", new=factory), \
            patch("cdt.tools.nikto_wrapper._parse_output_json", return_value=[]):
        await wrapper.run_tier2(
            "https://acme.example",
            {"WAFVendor": "Cloudflare", "CMSFramework": "WP", "WebServer": None},
        )

    assert journal_path.exists()
    line = journal_path.read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert entry["url"] == "https://acme.example"
    assert entry["tier"] == "tier2"
    assert entry["tuning"] == "b,a,5"
    assert "trigger_reason" in entry
    assert "termination" in entry


async def test_nikto__user_agent_passed_to_subprocess(
    wrapper: NiktoWrapper,
) -> None:
    """The configured UA appears in the spawned cmd's ``-useragent`` arg."""

    captured: dict[str, list[str]] = {}

    async def factory(cmd: list[str]) -> _FakeProc:
        captured["cmd"] = cmd
        return _FakeProc([b""])

    with patch("cdt.tools.nikto_wrapper.shutil.which", return_value="/usr/bin/nikto"), \
            patch("cdt.tools.nikto_wrapper._start_nikto_proc", side_effect=factory), \
            patch("cdt.tools.nikto_wrapper._parse_output_json", return_value=[]):
        await wrapper.run_tier2(
            "https://acme.example",
            {"WAFVendor": None, "CMSFramework": None, "WebServer": None},
        )

    assert "-useragent" in captured["cmd"]
    ua_idx = captured["cmd"].index("-useragent")
    assert "CDT-Scanner" in captured["cmd"][ua_idx + 1]


# ---------------------------------------------------------------------------
# Tests — allowlist + parser
# ---------------------------------------------------------------------------


def test_allowlist__loads_yaml_with_pydantic_validation(tmp_path: Path) -> None:
    """Pydantic validates the YAML structure; missing fields default safely."""

    yaml_path = tmp_path / "skip.yaml"
    yaml_path.write_text(
        "version: '1.0.0'\n"
        "skip_suffixes: ['.test']\n"
        "skip_apex: ['custom.test']\n",
        encoding="utf-8",
    )

    allowlist = NiktoSkipAllowlist.from_yaml(yaml_path)

    assert allowlist.matches("https://api.custom.test") is True
    assert allowlist.matches("https://other.test") is True   # suffix match
    assert allowlist.matches("https://acme.example") is False


def test_parse_nikto_line__extracts_server_cms_waf() -> None:
    from cdt.tools.nikto_wrapper import _parse_nikto_line

    assert _parse_nikto_line("+ Server: nginx/1.24.0") == {"WebServer": "nginx/1.24.0"}
    assert _parse_nikto_line("+ /xmlrpc.php WordPress XML-RPC")["CMSFramework"] == "WordPress"
    assert _parse_nikto_line("+ Cloudflare detected via cf-ray")["WAFVendor"] == "Cloudflare"
    assert _parse_nikto_line("- Nikto v2.5.0") == {}
