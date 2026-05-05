"""CLI entry point for cdt — see spec v0.5 §2.

Phase 8a wiring: the five commands now perform real work. ``scan`` builds
the full dependency graph, runs the orchestrator, and writes the four
CSVs + nikto journal.
"""

from __future__ import annotations

import asyncio
import csv as _csv
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

import structlog
import typer

from cdt import __version__
from cdt.config_loader import CdtConfig, require_brave_key
from cdt.context import configure_logging
from cdt.errors import CdtError, ExitCode, InputError, UsageError

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


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(  # noqa: PLR0913 — CLI surface follows v0.5 §2.4 verbatim
    in_: Annotated[Path, typer.Option("--in", help="Path to accounts_in.csv.")],
    out: Annotated[
        Path,
        typer.Option("--out", help="Output directory."),
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
        typer.Option("--country", help="Comma-separated country filter."),
    ] = "",
    skip_expansion: Annotated[
        bool, typer.Option("--skip-expansion")
    ] = False,
    skip_validation: Annotated[
        bool, typer.Option("--skip-validation")
    ] = False,
    max_sites_per_account: Annotated[
        int, typer.Option("--max-sites-per-account")
    ] = 5,
    force_nikto: Annotated[bool, typer.Option("--force-nikto")] = False,
    no_nikto: Annotated[bool, typer.Option("--no-nikto")] = False,
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir")
    ] = Path("~/.cache/cdt/"),
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    seed: Annotated[int | None, typer.Option("--seed")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
    no_network: Annotated[
        bool,
        typer.Option(
            "--no-network",
            help="Offline smoke mode: skip Brave/crt.sh/tools, all accounts go to "
                 "validation_issues. Hidden, intended for tests/dev.",
            hidden=True,
        ),
    ] = False,
) -> None:
    """Run the full scanner pipeline (v0.5 §2.4)."""

    configure_logging(log_level, log_format)
    log = structlog.get_logger()

    try:
        _scan_impl(
            in_=in_,
            out=out,
            tier=tier,
            authorized=authorized,
            concurrency=concurrency,
            country=country,
            skip_expansion=skip_expansion,
            skip_validation=skip_validation,
            max_sites_per_account=max_sites_per_account,
            force_nikto=force_nikto,
            no_nikto=no_nikto,
            cache_dir=cache_dir,
            dry_run=dry_run,
            seed=seed,
            config_path=config,
            no_network=no_network,
            log=log,
        )
    except CdtError as exc:
        exc.emit(log_format=log_format)
        raise typer.Exit(code=int(exc.code)) from exc


def _scan_impl(  # noqa: PLR0912, PLR0913, PLR0915 — one wiring path, intentionally linear
    *,
    in_: Path,
    out: Path,
    tier: str,
    authorized: Path | None,
    concurrency: int,
    country: str,
    skip_expansion: bool,
    skip_validation: bool,
    max_sites_per_account: int,
    force_nikto: bool,
    no_nikto: bool,
    cache_dir: Path,
    dry_run: bool,
    seed: int | None,
    config_path: Path | None,
    no_network: bool,
    log: Any,
) -> None:
    from cdt.io import CsvInputReader, CsvOutputWriter, NiktoJournal
    from cdt.orchestrator import (
        Orchestrator,
        ScanOptions,
    )

    if tier == "dast" and authorized is None and not no_network:
        raise UsageError("--authorized is required when --tier dast")

    if not in_.exists():
        raise InputError(f"Input CSV not found: {in_}")

    # Load config + apply env overrides.
    config_obj = CdtConfig.load(config_path).merge_env_overrides()

    # Read accounts.
    reader = CsvInputReader(in_)
    accounts = reader.read_accounts()
    log.info("scan_invoked", in_=str(in_), tier=tier, accounts=len(accounts))

    if dry_run:
        _print_dry_run_plan(accounts, tier=tier)
        return

    # Country filter check requires accounts loaded.
    country_list = [c.strip() for c in country.split(",") if c.strip()]

    # Authorized.csv if dast.
    authorized_keys: set[tuple[str, str]] = set()
    if authorized is not None:
        authorized_keys = CsvInputReader(authorized).read_authorized()

    # Pre-flight: BRAVE_SEARCH_API_KEY required for Validate/Discover unless
    # --skip-validation or --no-network.
    if not skip_validation and not no_network:
        validate_or_discover = [
            a
            for a in accounts
            if not (a.skip_validation or skip_validation)
            and (a.website == "" or a.website is not None)
        ]
        if validate_or_discover:
            require_brave_key()  # raises ConfigError(E04) if missing

    options = ScanOptions(
        tier=tier,
        country_filter=country_list,
        skip_expansion=skip_expansion,
        skip_validation=skip_validation,
        max_sites_per_account=max_sites_per_account,
        force_nikto=force_nikto,
        no_nikto=no_nikto,
        no_network=no_network,
        seed=seed,
        authorized_keys=authorized_keys,
    )

    # Build the dependency graph.
    components = _build_components(
        config=config_obj,
        cache_dir=cache_dir,
        concurrency=concurrency,
        no_network=no_network,
    )

    orchestrator = Orchestrator(config_obj, components)
    results = asyncio.run(orchestrator.run(accounts, options))

    # Write outputs.
    writer = CsvOutputWriter(out)
    writer.write_accounts_enriched(
        results.successful_results(), results.metadata_table()
    )
    writer.write_sites(results.all_sites())
    writer.write_findings(results.all_findings())
    writer.write_validation_issues(results.all_validation_issues())

    nikto_journal = NiktoJournal(out)
    for run in results.all_nikto_runs():
        nikto_journal.append_result(run)

    typer.echo(
        f"done — {len(results.successful)} ok, {len(results.with_issues)} in "
        f"validation_issues. outputs in {out}"
    )


def _build_components(  # noqa: PLR0913, PLR0915 — wiring is one big function
    *,
    config: CdtConfig,
    cache_dir: Path,
    concurrency: int,
    no_network: bool,
) -> Any:
    """Construct the OrchestratorComponents dataclass with real implementations.

    In ``no_network`` mode we still build everything; the orchestrator simply
    doesn't call out (each account routes to validation_issues). This keeps
    the dep graph identical for tests that patch components.
    """

    from cdt.detect import (
        CdnDetector,
        CloudAttributor,
        DetectionRules,
        StackDetector,
        WafDetector,
    )
    from cdt.detect import (
        ScoringEngine as DetectScoringEngine,  # noqa: F401 — placeholder if needed
    )
    from cdt.discovery import BraveSearch, DiscoveryCache, Expander, Validator
    from cdt.orchestrator import OrchestratorComponents
    from cdt.scan import (
        BrowserScanner,
        IPRangesIndex,
        PassiveScanner,
        RateLimitedPool,
        ScanRunner,
    )
    from cdt.scoring import ScoringEngine as BizScoringEngine
    from cdt.tools import (
        BuiltWithWrapper,
        CensysWrapper,
        NiktoSkipAllowlist,
        NiktoWrapper,
        ShodanWrapper,
        WafW00fWrapper,
        WappalyzerWrapper,
        WhatWebWrapper,
    )

    cache_path = Path(os.path.expanduser(str(cache_dir)))
    cache_path.mkdir(parents=True, exist_ok=True)
    discovery_cache = DiscoveryCache(cache_path / "discovery")

    brave_key = "" if no_network else os.environ.get("BRAVE_SEARCH_API_KEY", "")
    brave = BraveSearch(api_key=brave_key, cache=discovery_cache)
    validator = Validator()
    expander = Expander(cache=discovery_cache)

    ip_ranges = IPRangesIndex(cache=discovery_cache)
    passive = PassiveScanner(ip_ranges=ip_ranges)
    browser = BrowserScanner()
    wafw00f = WafW00fWrapper()
    whatweb = WhatWebWrapper()

    nikto_allowlist_path = Path(config.detection.nikto_skip_file)
    nikto_allowlist = (
        NiktoSkipAllowlist.from_yaml(nikto_allowlist_path)
        if nikto_allowlist_path.exists()
        else NiktoSkipAllowlist.empty()
    )
    nikto = NiktoWrapper(allowlist=nikto_allowlist)
    shodan = ShodanWrapper(cache=discovery_cache)
    censys = CensysWrapper(cache=discovery_cache)
    wappalyzer = WappalyzerWrapper()
    builtwith = BuiltWithWrapper(cache=discovery_cache)

    rules_path = Path(config.detection.rules_file)
    detection_rules = DetectionRules.load(rules_path)
    waf_detector = WafDetector(detection_rules)
    cdn_detector = CdnDetector(detection_rules)
    cloud_attributor = CloudAttributor(detection_rules, ip_ranges_index=ip_ranges)
    stack_detector = StackDetector(detection_rules)

    rationale_path = Path(config.detection.rationale_templates_file)
    scoring_engine = BizScoringEngine(rationale_path=rationale_path)

    pool = RateLimitedPool(concurrency=min(concurrency, 50), per_key_rps=2.0)
    scan_runner = ScanRunner(pool=pool)

    return OrchestratorComponents(
        brave=brave,
        validator=validator,
        expander=expander,
        passive=passive,
        browser=browser,
        wafw00f=wafw00f,
        whatweb=whatweb,
        nikto=nikto,
        shodan=shodan,
        censys=censys,
        wappalyzer=wappalyzer,
        builtwith=builtwith,
        waf_detector=waf_detector,
        cdn_detector=cdn_detector,
        cloud_attributor=cloud_attributor,
        stack_detector=stack_detector,
        scoring_engine=scoring_engine,
        scan_runner=scan_runner,
        ip_ranges=ip_ranges,
    )


def _print_dry_run_plan(accounts: list[Any], *, tier: str) -> None:
    validate = sum(1 for a in accounts if a.website and not a.skip_validation)
    discover = sum(1 for a in accounts if not a.website and not a.skip_validation)
    scan_only = sum(1 for a in accounts if a.skip_validation)
    countries = Counter(a.country for a in accounts)

    typer.echo("Plan estimado:")
    typer.echo(f"  Total filas (post-filter):           {len(accounts)}")
    typer.echo("  Modos:")
    typer.echo(f"    Validate + Expand (default):       {validate}")
    typer.echo(f"    Discover + Expand (fallback):      {discover}")
    typer.echo(f"    Scan-only (SkipValidation=1):      {scan_only}")
    typer.echo(f"  Queries Brave estimadas:             {validate + 2 * discover}")
    typer.echo(f"  Sitios secundarios estimados:        ~{len(accounts) * 5}")
    typer.echo(f"  Countries: {dict(countries)}")
    typer.echo(f"  Tier: {tier}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@app.command()
def validate(
    in_: Annotated[Path, typer.Option("--in")],
    authorized: Annotated[Path | None, typer.Option("--authorized")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Validate input schema and consistency without scanning (v0.5 §2.5)."""

    configure_logging(log_level, log_format)
    from cdt.io import CsvInputReader

    try:
        if not in_.exists():
            raise InputError(f"Input CSV not found: {in_}")

        reader = CsvInputReader(in_)
        accounts = reader.read_accounts()

        # Headers OK by construction (read_accounts raises otherwise).
        typer.echo("✓ headers OK")
        typer.echo("✓ encoding UTF-8 (BOM stripped if present)")

        # Country scope warning.
        from cdt.models import _SCOPE_VALUES

        out_of_scope = sorted({a.country for a in accounts if a.country not in _SCOPE_VALUES})
        if out_of_scope:
            typer.echo(
                f"! {len(out_of_scope)} country/ies outside the documented scope "
                f"({', '.join(out_of_scope)}) — proceeding anyway"
            )

        # Website parseable when populated.
        from cdt.discovery.normalize import parse_url
        bad_websites: list[tuple[int, str]] = []
        for idx, a in enumerate(accounts, start=2):
            if not a.website:
                continue
            try:
                parse_url(a.website)
            except InputError:
                bad_websites.append((idx, a.website))
        if bad_websites:
            for row, site in bad_websites:
                typer.echo(f"✗ row {row}: cannot parse website {site!r}", err=True)
        else:
            typer.echo("✓ all websites parseable")

        # Duplicates.
        seen: dict[tuple[str, str], list[int]] = {}
        for idx, a in enumerate(accounts, start=2):
            seen.setdefault((a.title, a.country), []).append(idx)
        duplicates = {k: v for k, v in seen.items() if len(v) > 1}
        if duplicates:
            for (title, country), rows in duplicates.items():
                typer.echo(
                    f"✗ duplicate (Title, Country): {title!r} / {country!r} "
                    f"appears in rows {', '.join(map(str, rows))}",
                    err=True,
                )
            errors = len(duplicates) + len(bad_websites)
            warnings = 1 if out_of_scope else 0
            typer.echo(f"{errors} error{'s' if errors != 1 else ''}, "
                       f"{warnings} warning{'s' if warnings != 1 else ''}")
            raise typer.Exit(code=int(ExitCode.INPUT))

        if authorized is not None:
            CsvInputReader(authorized).read_authorized()
            typer.echo("✓ authorized.csv parseable")

    except CdtError as exc:
        exc.emit(log_format=log_format)
        raise typer.Exit(code=int(exc.code)) from exc


# ---------------------------------------------------------------------------
# dry-run
# ---------------------------------------------------------------------------


@app.command(name="dry-run")
def dry_run(
    in_: Annotated[Path, typer.Option("--in")],
    tier: Annotated[str, typer.Option("--tier")] = "browser",
    country: Annotated[str, typer.Option("--country")] = "",
    config: Annotated[Path | None, typer.Option("--config")] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Validate + print scan plan (no requests) (v0.5 §2.6)."""

    configure_logging(log_level, log_format)
    try:
        from cdt.io import CsvInputReader

        if not in_.exists():
            raise InputError(f"Input CSV not found: {in_}")
        accounts = CsvInputReader(in_).read_accounts()
        if country:
            country_list = [c.strip() for c in country.split(",") if c.strip()]
            accounts = [a for a in accounts if a.country in country_list]
        _print_dry_run_plan(accounts, tier=tier)
    except CdtError as exc:
        exc.emit(log_format=log_format)
        raise typer.Exit(code=int(exc.code)) from exc


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@app.command()
def diff(
    baseline: Annotated[Path, typer.Option("--baseline")],
    current: Annotated[Path, typer.Option("--current")],
    out: Annotated[Path | None, typer.Option("--out")] = None,
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
    try:
        baseline_path = baseline / "accounts_enriched.csv" if baseline.is_dir() else baseline
        current_path = current / "accounts_enriched.csv" if current.is_dir() else current

        if not baseline_path.exists():
            raise InputError(f"Baseline CSV not found: {baseline_path}")
        if not current_path.exists():
            raise InputError(f"Current CSV not found: {current_path}")

        fields = [c.strip() for c in by.split(",") if c.strip()]
        baseline_rows = _load_csv_rows(baseline_path)
        current_rows = _load_csv_rows(current_path)

        diff_rows: list[dict[str, str]] = []
        baseline_by_key = {(r["Title"], r["Country"]): r for r in baseline_rows}
        current_by_key = {(r["Title"], r["Country"]): r for r in current_rows}

        for key, base_row in baseline_by_key.items():
            cur_row = current_by_key.get(key)
            if cur_row is None:
                diff_rows.append({
                    "Title": key[0],
                    "Country": key[1],
                    "Field": "__missing_in_current__",
                    "Baseline": "",
                    "Current": "",
                })
                continue
            for field in fields:
                if base_row.get(field) != cur_row.get(field):
                    diff_rows.append({
                        "Title": key[0],
                        "Country": key[1],
                        "Field": field,
                        "Baseline": base_row.get(field, ""),
                        "Current": cur_row.get(field, ""),
                    })

        for key in current_by_key.keys() - baseline_by_key.keys():
            diff_rows.append({
                "Title": key[0],
                "Country": key[1],
                "Field": "__new_in_current__",
                "Baseline": "",
                "Current": "",
            })

        headers = ["Title", "Country", "Field", "Baseline", "Current"]
        if out is not None:
            with out.open("w", encoding="utf-8", newline="") as f:
                writer = _csv.DictWriter(
                    f, fieldnames=headers,
                    quoting=_csv.QUOTE_MINIMAL, lineterminator="\n",
                )
                writer.writeheader()
                writer.writerows(diff_rows)
            typer.echo(f"diff written to {out} ({len(diff_rows)} rows)")
        else:
            typer.echo(",".join(headers))
            for row in diff_rows:
                typer.echo(",".join(row[h] for h in headers))
    except CdtError as exc:
        exc.emit(log_format=log_format)
        raise typer.Exit(code=int(exc.code)) from exc


def _load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(_csv.DictReader(f))


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@app.command()
def doctor(
    cse_quota: Annotated[bool, typer.Option("--cse-quota")] = False,
    shodan: Annotated[bool, typer.Option("--shodan")] = False,
    censys: Annotated[bool, typer.Option("--censys")] = False,
    linode: Annotated[bool, typer.Option("--linode")] = False,
    all_: Annotated[bool, typer.Option("--all")] = False,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    log_format: Annotated[str, typer.Option("--log-format")] = "console",
) -> None:
    """Health check (v0.5 §2.8)."""

    configure_logging(log_level, log_format)
    import shutil

    typer.echo(f"✓ python {sys.version.split()[0]}")
    typer.echo(f"✓ cdt {__version__}")

    # API keys.
    for key, _desc in (
        ("BRAVE_SEARCH_API_KEY", "Brave Search"),
        ("SHODAN_API_KEY", "Shodan Host API"),
        ("CENSYS_API_ID", "Censys"),
        ("BUILTWITH_API_KEY", "BuiltWith"),
    ):
        present = "present" if os.environ.get(key) else "absent"
        marker = "✓" if os.environ.get(key) else "-"
        typer.echo(f"{marker} {key:30s} {present}")

    # Tool binaries.
    for binary in ("whatweb", "nikto"):
        path = shutil.which(binary)
        marker = "✓" if path else "-"
        typer.echo(f"{marker} {binary:30s} {'found at ' + path if path else 'not in PATH'}")

    # Cache + out writability.
    cache_dir = Path(os.path.expanduser(os.environ.get("CDT_CACHE_DIR", "~/.cache/cdt")))
    typer.echo(
        f"{'✓' if cache_dir.parent.exists() else '-'} cache_dir {cache_dir}"
    )

    typer.echo("done")


__all__ = ["app"]
