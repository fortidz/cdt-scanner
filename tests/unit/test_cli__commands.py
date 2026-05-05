"""CLI command integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from cdt.cli import app

runner = CliRunner()


def _write_csv(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


# ---------- scan ----------


def test_cli_scan__missing_brave_key_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real Validate-mode rows + missing BRAVE_SEARCH_API_KEY → ConfigError E04."""

    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    csv_path = tmp_path / "in.csv"
    _write_csv(csv_path, "Title,Country,Website\nAcme,Ecuador,acme.example\n")

    result = runner.invoke(app, ["scan", "--in", str(csv_path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 4


def test_cli_scan__authorized_required_for_dast(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    _write_csv(csv_path, "Title,Country,Website\nAcme,Ecuador,acme.example\n")

    result = runner.invoke(
        app, ["scan", "--in", str(csv_path), "--tier", "dast"]
    )
    assert result.exit_code == 2


def test_cli_scan__no_network_smoke_completes(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    _write_csv(
        csv_path,
        "Title,Country,Website\n"
        "Acme,Ecuador,acme.example\n"
        "Beta,Perú,beta.example.pe\n",
    )
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", "--in", str(csv_path), "--out", str(out_dir), "--no-network"]
    )
    assert result.exit_code == 0
    assert (out_dir / "accounts_enriched.csv").exists()
    assert (out_dir / "sites.csv").exists()
    assert (out_dir / "findings.csv").exists()
    assert (out_dir / "validation_issues.csv").exists()


def test_cli_scan__country_filter_skips_others(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    _write_csv(
        csv_path,
        "Title,Country,Website\n"
        "Acme,Ecuador,acme.example\n"
        "Beta,Perú,beta.example.pe\n"
        "Gamma,Chile,gamma.example.cl\n",
    )
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan", "--in", str(csv_path), "--out", str(out_dir),
            "--no-network", "--country", "Perú",
        ],
    )
    assert result.exit_code == 0
    # In --no-network mode every account with a website succeeds (no-op pipeline).
    # The country filter dropped Acme + Gamma BEFORE dispatch, so they appear in
    # NEITHER output. Beta survives the filter and lands in accounts_enriched.
    enriched = (out_dir / "accounts_enriched.csv").read_text(encoding="utf-8")
    issues = (out_dir / "validation_issues.csv").read_text(encoding="utf-8")
    sites = (out_dir / "sites.csv").read_text(encoding="utf-8")
    combined = enriched + issues + sites
    assert "Beta" in combined
    assert "Acme" not in combined
    assert "Gamma" not in combined


# ---------- validate ----------


def test_cli_validate__valid_csv_exits_0(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    _write_csv(csv_path, "Title,Country,Website\nAcme,Ecuador,acme.example\n")
    result = runner.invoke(app, ["validate", "--in", str(csv_path)])
    assert result.exit_code == 0
    assert "headers OK" in result.stdout


def test_cli_validate__duplicate_rows_exits_3(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    _write_csv(
        csv_path,
        "Title,Country,Website\n"
        "Acme,Ecuador,acme.example\n"
        "Acme,Ecuador,other.example\n",
    )
    result = runner.invoke(app, ["validate", "--in", str(csv_path)])
    assert result.exit_code == 3


# ---------- dry-run ----------


def test_cli_dry_run__prints_plan_and_exits_0(tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    _write_csv(
        csv_path,
        "Title,Country,Website\n"
        "Acme,Ecuador,acme.example\n"
        "Beta,Perú,\n",
    )
    result = runner.invoke(app, ["dry-run", "--in", str(csv_path)])
    assert result.exit_code == 0
    assert "Plan estimado" in result.stdout
    assert "Validate" in result.stdout
    assert "Discover" in result.stdout


# ---------- diff ----------


def test_cli_diff__detects_field_change(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.csv"
    current = tmp_path / "current.csv"
    header = ("Title,Country,WAF,WAFVendor,RiskScore,RecommendsFortiAppSec,"
              "RecommendsFortiWeb,RecommendsFortiCNAPP\n")
    _write_csv(baseline, header + "Acme,Ecuador,No,-,LOW (1/15),No,Yes,No\n")
    _write_csv(current, header + "Acme,Ecuador,No,-,MEDIUM (7/15),Yes,No,No\n")

    result = runner.invoke(
        app, ["diff", "--baseline", str(baseline), "--current", str(current)]
    )
    assert result.exit_code == 0
    assert "RiskScore" in result.stdout
    assert "RecommendsFortiAppSec" in result.stdout


# ---------- doctor ----------


def test_cli_doctor__missing_keys_warned(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("BRAVE_SEARCH_API_KEY", "SHODAN_API_KEY", "CENSYS_API_ID"):
        monkeypatch.delenv(key, raising=False)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "absent" in result.stdout.lower()
