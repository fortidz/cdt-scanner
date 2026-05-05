"""Smoke tests for the typer CLI surface (v0.5 §2)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cdt import __version__
from cdt.cli import app

runner = CliRunner()


def test_cli__help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("scan", "validate", "dry-run", "diff", "doctor"):
        assert command in result.stdout


def test_cli__version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli__scan_help_contains_flags() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for flag in ("--in", "--out", "--tier", "--concurrency", "--cache-dir", "--dry-run"):
        assert flag in result.stdout


def test_cli__scan_stub_exits_zero(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    csv_path.write_text("Title,Country,Website\nDemo,Ecuador,demo.com\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "--in", str(csv_path)])
    assert result.exit_code == 0


def test_cli__validate_stub_exits_zero(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    csv_path.write_text("Title,Country,Website\nDemo,Ecuador,demo.com\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", "--in", str(csv_path)])
    assert result.exit_code == 0


def test_cli__doctor_stub_exits_zero() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0


def test_cli__diff_stub_exits_zero(tmp_path: Path) -> None:
    baseline = tmp_path / "a"
    current = tmp_path / "b"
    baseline.mkdir()
    current.mkdir()
    result = runner.invoke(app, ["diff", "--baseline", str(baseline), "--current", str(current)])
    assert result.exit_code == 0


def test_cli__dry_run_stub_exits_zero(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    csv_path.write_text("Title,Country,Website\nDemo,Ecuador,demo.com\n", encoding="utf-8")
    result = runner.invoke(app, ["dry-run", "--in", str(csv_path)])
    assert result.exit_code == 0
