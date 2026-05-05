"""CLI entry point for cdt — see spec v0.5 §2.

All five commands are declared with their full flag surface so help text is canonical
from Phase 1. Real behaviour ships in later phases; for now each command logs an
``<command>_invoked`` event and a ``not_implemented`` warning, then exits with 0.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import structlog
import typer

from cdt import __version__
from cdt.context import configure_logging

app = typer.Typer(
    name="cdt",
    help="Cloud Development Tool — Site Discovery & Exposure Scanner.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cdt {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Print version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Global flags. Per-command flags live on each subcommand."""


def _warn_not_implemented(command: str, phase: str) -> None:
    log = structlog.get_logger()
    log.warning("not_implemented", command=command, phase=phase)


@app.command()
def scan(
    in_: Annotated[Path, typer.Option("--in", help="Path to accounts_in.csv.")],
    out: Annotated[
        Path,
        typer.Option("--out", help="Output directory. Created if it does not exist."),
    ] = Path("./out/"),
    tier: Annotated[
        str, typer.Option("--tier", help="passive | browser | dast.")
    ] = "browser",
    authorized: Annotated[
        Path | None,
        typer.Option("--authorized", help="authorized.csv (required for --tier dast)."),
    ] = None,
    concurrency: Annotated[
        int, typer.Option("--concurrency", help="Asyncio workers (hard cap 50).")
    ] = 20,
    country: Annotated[
        str,
        typer.Option("--country", help="Comma-separated country filter, e.g. 'Ecuador,Perú'."),
    ] = "",
    skip_expansion: Annotated[
        bool, typer.Option("--skip-expansion", help="Disable crt.sh subdomain expansion.")
    ] = False,
    skip_validation: Annotated[
        bool, typer.Option("--skip-validation", help="Treat every row as SkipValidation=1.")
    ] = False,
    max_sites_per_account: Annotated[
        int, typer.Option("--max-sites-per-account", help="Cap on Website01..N (SP List = 5).")
    ] = 5,
    force_nikto: Annotated[
        bool, typer.Option("--force-nikto", help="Run nikto in Tier 2 regardless of heuristics.")
    ] = False,
    no_nikto: Annotated[
        bool, typer.Option("--no-nikto", help="Disable nikto entirely.")
    ] = False,
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir", help="Cache directory for IP ranges, discovery, etc.")
    ] = Path("~/.cache/cdt/"),
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run", help="Validate input + print plan + exit without scanning."
        ),
    ] = False,
    seed: Annotated[
        int | None,
        typer.Option("--seed", help="Deterministic ordering for tests."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="YAML config file (default: ./config/cdt.yaml)."),
    ] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help="debug | info | warn | error.")
    ] = "info",
    log_format: Annotated[
        str, typer.Option("--log-format", help="console | json.")
    ] = "console",
) -> None:
    """Run the full scanner pipeline (v0.5 §2.4)."""

    configure_logging(log_level, log_format)
    log = structlog.get_logger()
    log.info(
        "scan_invoked",
        in_=str(in_),
        out=str(out),
        tier=tier,
        authorized=str(authorized) if authorized else None,
        concurrency=concurrency,
        country=country,
        skip_expansion=skip_expansion,
        skip_validation=skip_validation,
        max_sites_per_account=max_sites_per_account,
        force_nikto=force_nikto,
        no_nikto=no_nikto,
        cache_dir=str(cache_dir),
        dry_run=dry_run,
        seed=seed,
        config=str(config) if config else None,
    )
    _warn_not_implemented(command="scan", phase="3+")


@app.command()
def validate(
    in_: Annotated[Path, typer.Option("--in", help="Path to accounts_in.csv.")],
    authorized: Annotated[
        Path | None,
        typer.Option("--authorized", help="Optional authorized.csv to cross-check."),
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", help="YAML config file.")
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Validate input schema and consistency without scanning (v0.5 §2.5)."""

    configure_logging(log_level, log_format)
    log = structlog.get_logger()
    log.info(
        "validate_invoked",
        in_=str(in_),
        authorized=str(authorized) if authorized else None,
        config=str(config) if config else None,
    )
    _warn_not_implemented(command="validate", phase="2")


@app.command(name="dry-run")
def dry_run(
    in_: Annotated[Path, typer.Option("--in", help="Path to accounts_in.csv.")],
    tier: Annotated[str, typer.Option("--tier")] = "browser",
    country: Annotated[str, typer.Option("--country")] = "",
    config: Annotated[Path | None, typer.Option("--config")] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Validate + print scan plan (no requests) (v0.5 §2.6)."""

    configure_logging(log_level, log_format)
    log = structlog.get_logger()
    log.info(
        "dry_run_invoked",
        in_=str(in_),
        tier=tier,
        country=country,
        config=str(config) if config else None,
    )
    _warn_not_implemented(command="dry-run", phase="2")


@app.command()
def diff(
    baseline: Annotated[
        Path, typer.Option("--baseline", help="Output dir of the previous run.")
    ],
    current: Annotated[
        Path, typer.Option("--current", help="Output dir of the new run.")
    ],
    out: Annotated[
        Path | None,
        typer.Option("--out", help="CSV destination. Default: stdout."),
    ] = None,
    by: Annotated[
        str,
        typer.Option(
            "--by",
            help="Comma-separated columns to compare.",
        ),
    ] = "WAF,WAFVendor,RiskScore,RecommendsFortiAppSec,RecommendsFortiWeb,RecommendsFortiCNAPP",
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Diff two scan output directories (v0.5 §2.7)."""

    configure_logging(log_level, log_format)
    log = structlog.get_logger()
    log.info(
        "diff_invoked",
        baseline=str(baseline),
        current=str(current),
        out=str(out) if out else None,
        by=by,
    )
    _warn_not_implemented(command="diff", phase="7")


@app.command()
def doctor(
    cse_quota: Annotated[
        bool, typer.Option("--cse-quota", help="Burn one search query to read remaining quota.")
    ] = False,
    shodan: Annotated[bool, typer.Option("--shodan", help="Test Shodan API access.")] = False,
    censys: Annotated[bool, typer.Option("--censys", help="Test Censys API access.")] = False,
    linode: Annotated[bool, typer.Option("--linode", help="Test Linode API access.")] = False,
    all_: Annotated[
        bool,
        typer.Option("--all", help="Run every check including the ones that cost quota."),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Health check: API keys, network, tool versions (v0.5 §2.8)."""

    configure_logging(log_level, log_format)
    log = structlog.get_logger()
    log.info(
        "doctor_invoked",
        cse_quota=cse_quota,
        shodan=shodan,
        censys=censys,
        linode=linode,
        all_=all_,
    )
    _warn_not_implemented(command="doctor", phase="9")
