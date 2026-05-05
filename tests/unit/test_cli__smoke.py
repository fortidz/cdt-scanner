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


def test_cli__scan_offline_exits_zero(tmp_path: Path) -> None:
    """Phase 8a: --no-network runs the orchestrator end-to-end with offline stubs."""

    csv_path = tmp_path / "in.csv"
    csv_path.write_text("Title,Country,Website\nDemo,Ecuador,demo.com\n", encoding="utf-8")
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", "--in", str(csv_path), "--out", str(out_dir), "--no-network"]
    )
    assert result.exit_code == 0
    assert (out_dir / "accounts_enriched.csv").exists()
    assert (out_dir / "validation_issues.csv").exists()


def test_cli__validate_stub_exits_zero(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    csv_path.write_text("Title,Country,Website\nDemo,Ecuador,demo.com\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", "--in", str(csv_path)])
    assert result.exit_code == 0


def test_cli__doctor_stub_exits_zero() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0


def test_cli__diff_missing_baseline_exits_3(tmp_path: Path) -> None:
    """Phase 8a: diff is real and reports E03 when baseline CSV is missing."""

    baseline = tmp_path / "a"
    current = tmp_path / "b"
    baseline.mkdir()
    current.mkdir()
    result = runner.invoke(
        app, ["diff", "--baseline", str(baseline), "--current", str(current)]
    )
    assert result.exit_code == 3


def test_cli__dry_run_stub_exits_zero(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    csv_path.write_text("Title,Country,Website\nDemo,Ecuador,demo.com\n", encoding="utf-8")
    result = runner.invoke(app, ["dry-run", "--in", str(csv_path)])
    assert result.exit_code == 0
