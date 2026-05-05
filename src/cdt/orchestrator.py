"""Per-account scan orchestrator.

Wires every layer (discovery → scan → detect → scoring → io) into one
async pipeline. Exception isolation per account: a single failing site
goes to ``validation_issues.csv`` with ``Issue=INTERNAL_ERROR`` and the
run continues.

The orchestrator does no IO of its own — it composes the components it
receives at construction time. The CLI builds the dependency graph for
production runs; tests construct it with mocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from pydantic import BaseModel, ConfigDict, Field

from cdt.config_loader import CdtConfig
from cdt.detect import (
    CdnDetector,
    CloudAttributor,
    DetectionInput,
    StackDetector,
    WafDetector,
)
from cdt.discovery import (
    BraveSearch,
    Expander,
    ExpansionResult,
    IssueCode,
    ValidationResult,
    Validator,
)
from cdt.discovery.normalize import apex_of, parse_url
from cdt.errors import InputError
from cdt.io import AccountInMetadata, Site, TopCandidate, ValidationIssue
from cdt.io.models import ValidationIssue as IoValidationIssue
from cdt.models import AccountIn
from cdt.scan import BrowserScanner, IPRangesIndex, PassiveScanner, ScanRunner
from cdt.scoring import (
    Finding,
    FindingCode,
    ScoringEngine,
    ScoringInput,
    ScoringResult,
    Severity,
)
from cdt.tools import (
    BuiltWithWrapper,
    CensysWrapper,
    NiktoResult,
    NiktoWrapper,
    ShodanWrapper,
    WafW00fWrapper,
    WappalyzerWrapper,
    WhatWebWrapper,
)

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Public DTOs
# ---------------------------------------------------------------------------


class ScanOptions(BaseModel):
    tier: str = "browser"
    country_filter: list[str] = Field(default_factory=list)
    skip_expansion: bool = False
    skip_validation: bool = False
    max_sites_per_account: int = 5
    force_nikto: bool = False
    no_nikto: bool = False
    no_network: bool = False
    seed: int | None = None
    authorized_keys: set[tuple[str, str]] = Field(default_factory=set)

    model_config = ConfigDict(arbitrary_types_allowed=True)


@dataclass
class AccountResult:
    title: str
    country: str
    mode: str  # validate | discover | scan_only | error
    metadata: AccountInMetadata | None = None
    scoring_result: ScoringResult | None = None
    sites: list[Site] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    validation_issue: IoValidationIssue | None = None
    nikto_runs: list[NiktoResult] = field(default_factory=list)


@dataclass
class ScanRunResults:
    accounts: list[AccountResult]

    @property
    def successful(self) -> list[AccountResult]:
        return [a for a in self.accounts if a.scoring_result is not None]

    @property
    def with_issues(self) -> list[AccountResult]:
        return [a for a in self.accounts if a.validation_issue is not None]

    def all_sites(self) -> list[Site]:
        out: list[Site] = []
        for a in self.accounts:
            out.extend(a.sites)
        return out

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for a in self.accounts:
            out.extend(a.findings)
        return out

    def all_validation_issues(self) -> list[IoValidationIssue]:
        return [a.validation_issue for a in self.accounts if a.validation_issue]

    def all_nikto_runs(self) -> list[NiktoResult]:
        out: list[NiktoResult] = []
        for a in self.accounts:
            out.extend(a.nikto_runs)
        return out

    def metadata_table(self) -> dict[str, AccountInMetadata]:
        """Composite-key dict consumed by ``CsvOutputWriter.write_accounts_enriched``."""

        out: dict[str, AccountInMetadata] = {}
        for a in self.accounts:
            if a.scoring_result is None or a.metadata is None:
                continue
            key = f"{a.title}|{a.country}"
            out[key] = a.metadata
        return out

    def successful_results(self) -> list[ScoringResult]:
        return [
            a.scoring_result for a in self.accounts if a.scoring_result is not None
        ]


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------


@dataclass
class OrchestratorComponents:
    brave: BraveSearch
    validator: Validator
    expander: Expander
    passive: PassiveScanner
    browser: BrowserScanner
    wafw00f: WafW00fWrapper
    whatweb: WhatWebWrapper
    nikto: NiktoWrapper
    shodan: ShodanWrapper
    censys: CensysWrapper
    wappalyzer: WappalyzerWrapper
    builtwith: BuiltWithWrapper
    waf_detector: WafDetector
    cdn_detector: CdnDetector
    cloud_attributor: CloudAttributor
    stack_detector: StackDetector
    scoring_engine: ScoringEngine
    scan_runner: ScanRunner
    ip_ranges: IPRangesIndex | None = None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    def __init__(self, config: CdtConfig, components: OrchestratorComponents) -> None:
        self._config = config
        self._c = components

    # ---------- public API -----------------------------------------------

    async def run(
        self, accounts: list[AccountIn], options: ScanOptions
    ) -> ScanRunResults:
        log.info(
            "scan_started",
            total=len(accounts),
            tier=options.tier,
            country_filter=options.country_filter,
        )

        filtered = _apply_country_filter(accounts, options.country_filter)
        log.info("scan_plan", total=len(accounts), after_filter=len(filtered))

        async def _worker(account: AccountIn) -> AccountResult:
            return await self._scan_account_safe(account, options)

        results = await self._c.scan_runner._pool.run(  # noqa: SLF001
            filtered,
            _worker,
            key_fn=lambda a: a.country,
        )
        log.info(
            "scan_finished",
            total=len(filtered),
            successful=sum(1 for r in results if r.scoring_result is not None),
            with_issues=sum(1 for r in results if r.validation_issue is not None),
        )
        return ScanRunResults(accounts=list(results))

    async def scan_account(
        self, account: AccountIn, options: ScanOptions
    ) -> AccountResult:
        """Single-account entry point. Public so tests can call it directly."""

        return await self._scan_account_safe(account, options)

    # ---------- core implementation --------------------------------------

    async def _scan_account_safe(
        self, account: AccountIn, options: ScanOptions
    ) -> AccountResult:
        started = datetime.now(UTC)
        log.info(
            "account_started",
            title=account.title,
            country=account.country,
            tier=options.tier,
        )
        try:
            result = await self._scan_account_inner(account, options, started)
        except Exception as exc:  # noqa: BLE001 — orchestrator is the safety net
            log.warning(
                "account_failed",
                title=account.title,
                country=account.country,
                error=f"{type(exc).__name__}: {exc}",
            )
            result = AccountResult(
                title=account.title,
                country=account.country,
                mode="error",
                validation_issue=IoValidationIssue(
                    title=account.title,
                    country=account.country,
                    provided_website=account.website,
                    issue="INTERNAL_ERROR",
                    suggestion="",
                    top_candidates=[],
                ),
            )

        duration = (datetime.now(UTC) - started).total_seconds()
        log.info(
            "account_finished",
            title=account.title,
            country=account.country,
            duration_ms=int(duration * 1000),
            mode=result.mode,
            findings=len(result.findings),
        )
        return result

    async def _scan_account_inner(
        self,
        account: AccountIn,
        options: ScanOptions,
        started: datetime,
    ) -> AccountResult:
        # 1. Mode decision + DAST authorization gate.
        mode = _decide_mode(account, options)
        effective_tier = options.tier
        findings: list[Finding] = []

        if effective_tier == "dast" and not _is_authorized(account, options):
            log.warning(
                "dast_unauthorized",
                title=account.title,
                country=account.country,
            )
            findings.append(
                Finding(
                    title=account.title,
                    country=account.country,
                    site_url=account.website or "-",
                    finding_code=FindingCode.NIKTO_SKIPPED_SENSITIVE_DOMAIN,
                    severity=Severity.LOW,
                    message="DAST tier requested but account not in authorized.csv; "
                    "degraded to browser tier.",
                )
            )
            effective_tier = "browser"

        # 2. Validate / Discover / Scan-only.
        canonical_url, validation_issue = await self._resolve_url(
            account, mode, options
        )
        if validation_issue is not None:
            return AccountResult(
                title=account.title,
                country=account.country,
                mode=mode,
                validation_issue=validation_issue,
                findings=findings,
            )

        # 3. Expand secondaries via crt.sh.
        secondaries: list[str] = []
        if not options.skip_expansion and canonical_url:
            secondaries = await self._expand(canonical_url, options)

        # 4. Per-site scanning.
        primary_data = await self._scan_site(
            canonical_url or account.website,
            tier=effective_tier,
            account=account,
            is_primary=True,
            options=options,
        )

        secondary_sites: list[Site] = []
        for sec_url in secondaries[: options.max_sites_per_account - 1]:
            secondary_data = await self._scan_site(
                sec_url,
                tier=effective_tier,
                account=account,
                is_primary=False,
                options=options,
            )
            secondary_sites.append(secondary_data["site"])

        # 5. Detection on the primary.
        detection_input = _build_detection_input(canonical_url, primary_data)
        waf = self._c.waf_detector.detect(detection_input)
        cdn = self._c.cdn_detector.detect(detection_input, waf_detection=waf)
        cloud = await self._c.cloud_attributor.attribute(detection_input)
        stack = self._c.stack_detector.detect(detection_input)

        # 6. Scoring.
        secondary_protected = [s.waf_detected for s in secondary_sites]
        scoring_input = ScoringInput(
            url=canonical_url or account.website,
            title=account.title,
            country=account.country,
            tier=effective_tier,
            is_alive=primary_data["alive"],
            waf=waf,
            cdn=cdn,
            cloud=cloud,
            stack=stack,
            headers=primary_data["headers"],
            tls=primary_data.get("tls"),
            secondary_sites_protected=secondary_protected,
            has_aws=cloud.provider == "AWS",
            has_azure=cloud.provider == "Azure",
            has_gcp=cloud.provider == "GCP",
            has_oci=cloud.provider == "OCI",
        )
        scoring_result = self._c.scoring_engine.evaluate(scoring_input)

        # 7. Build per-row metadata for the writer.
        metadata = AccountInMetadata(
            title=account.title,
            country=account.country,
            website01=canonical_url or account.website or "-",
            website02=secondaries[0] if len(secondaries) > 0 else "-",
            website03=secondaries[1] if len(secondaries) > 1 else "-",
            website04=secondaries[2] if len(secondaries) > 2 else "-",
            website05=secondaries[3] if len(secondaries) > 3 else "-",
            cms_framework=stack.cms,
            web_server=stack.web_server,
            cdn=cdn.vendor,
            scanned_at=started,
        )

        primary_site = _build_primary_site(
            account, canonical_url, primary_data, waf, cdn, cloud, stack,
            tier=effective_tier, scanned_at=started,
        )

        all_findings = findings + scoring_result.findings
        return AccountResult(
            title=account.title,
            country=account.country,
            mode=mode,
            metadata=metadata,
            scoring_result=scoring_result,
            sites=[primary_site, *secondary_sites],
            findings=all_findings,
            nikto_runs=primary_data.get("nikto_runs", []),
        )

    # ---------- per-stage helpers ----------------------------------------

    async def _resolve_url(
        self,
        account: AccountIn,
        mode: str,
        options: ScanOptions,
    ) -> tuple[str | None, IoValidationIssue | None]:
        """Returns ``(canonical_url, issue)``. One of them is None."""

        if options.no_network:
            # Offline mode: trust the input verbatim, no validation.
            if account.website:
                return account.website, None
            return None, IoValidationIssue(
                title=account.title,
                country=account.country,
                provided_website="",
                issue="NO_RESULTS",
                suggestion="",
                top_candidates=[],
            )

        if mode == "scan_only":
            return account.website or None, None

        if mode == "validate":
            try:
                http_result = await self._c.validator.validate(account)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "validator_failed",
                    title=account.title,
                    error=f"{type(exc).__name__}: {exc}",
                )
                return None, _issue_from_validation(account, "INTERNAL_ERROR", None)

            if http_result.confirmed:
                return http_result.canonical_url, None
            if http_result.issue and not http_result.needs_semantic_check:
                return None, _issue_from_validation(
                    account, http_result.issue.value, http_result
                )
            # Needs Brave semantic check.
            try:
                brave_result = await self._c.brave.validate(account)
            except Exception as exc:  # noqa: BLE001
                log.warning("brave_failed", title=account.title, error=str(exc))
                return None, _issue_from_validation(account, "INTERNAL_ERROR", None)
            if brave_result.confirmed:
                return http_result.canonical_url, None
            return None, _issue_from_validation(
                account,
                (brave_result.issue.value if brave_result.issue else "POSSIBLE_MISMATCH"),
                brave_result,
            )

        # Discover.
        try:
            brave_result = await self._c.brave.discover(account)
        except Exception as exc:  # noqa: BLE001
            log.warning("brave_failed", title=account.title, error=str(exc))
            return None, _issue_from_validation(account, "INTERNAL_ERROR", None)
        if brave_result.confirmed and brave_result.canonical_url:
            return f"https://{brave_result.canonical_url}", None
        return None, _issue_from_validation(
            account,
            (brave_result.issue.value if brave_result.issue else "LOW_CONFIDENCE"),
            brave_result,
        )

    async def _expand(self, url: str, options: ScanOptions) -> list[str]:
        try:
            apex = apex_of(url)
        except InputError:
            return []
        try:
            expansion: ExpansionResult = await self._c.expander.expand(
                apex, max_sites=options.max_sites_per_account
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("expander_failed", apex=apex, error=str(exc))
            return []
        # Skip the apex itself; we only want strict subdomains here.
        return [f"https://{w}" for w in expansion.websites if w and w != apex]

    async def _scan_site(
        self,
        url: str,
        *,
        tier: str,
        account: AccountIn,
        is_primary: bool,
        options: ScanOptions,
    ) -> dict:  # type: ignore[type-arg]
        """Run scan + tools against one site. Returns the bag the orchestrator needs."""

        out: dict = {  # type: ignore[type-arg]
            "url": url,
            "alive": False,
            "status": 0,
            "headers": {},
            "cookies": [],
            "body_snippet": "",
            "redirects": [],
            "tls": None,
            "ip_addresses": [],
            "asn": None,
            "asn_org": None,
            "rdns_hostnames": [],
            "cnames": [],
            "wafw00f_vendor": None,
            "wafw00f_generic": False,
            "whatweb_plugins": {},
            "wappalyzer_techs": {},
            "shodan_cpes": [],
            "shodan_ports": [],
            "nikto_runs": [],
            "site": None,
        }

        if options.no_network:
            log.info("scan_site_offline", url=url, primary=is_primary)
            return out

        # Passive — DNS, WHOIS, ASN, cloud attribution.
        try:
            passive_result = await self._c.passive.scan(url)
        except Exception as exc:  # noqa: BLE001
            log.warning("passive_failed", url=url, error=str(exc))
            passive_result = None

        if passive_result and passive_result.dns:
            out["ip_addresses"] = list(passive_result.dns.a_records)
            out["cnames"] = list(passive_result.dns.cname_chain)
        if passive_result and passive_result.asn:
            out["asn"] = passive_result.asn.asn
            out["asn_org"] = passive_result.asn.asn_org

        # Browser tier or above.
        if tier in {"browser", "dast"}:
            try:
                browser_result = await self._c.browser.fetch(url)
                out["status"] = browser_result.status
                out["headers"] = dict(browser_result.headers)
                out["body_snippet"] = browser_result.body_snippet
                out["redirects"] = list(browser_result.redirects)
                out["tls"] = browser_result.tls
                out["alive"] = browser_result.status not in {0} and browser_result.status < 500
            except Exception as exc:  # noqa: BLE001
                log.warning("browser_failed", url=url, error=str(exc))

            # wafw00f
            try:
                waf_detection = await self._c.wafw00f.detect(url)
                out["wafw00f_vendor"] = waf_detection.vendor
                out["wafw00f_generic"] = waf_detection.generic
            except Exception as exc:  # noqa: BLE001
                log.warning("wafw00f_failed", url=url, error=str(exc))

            # whatweb
            try:
                whatweb_result = await self._c.whatweb.detect(url)
                out["whatweb_plugins"] = dict(whatweb_result.plugins)
            except Exception as exc:  # noqa: BLE001
                log.warning("whatweb_failed", url=url, error=str(exc))

            # Wappalyzer
            try:
                wapp_result = await self._c.wappalyzer.detect(url)
                out["wappalyzer_techs"] = dict(wapp_result.technologies)
            except Exception as exc:  # noqa: BLE001
                log.warning("wappalyzer_failed", url=url, error=str(exc))

            # Shodan InternetDB
            for ip in out["ip_addresses"][:1]:
                try:
                    shodan_result = await self._c.shodan.lookup_internetdb(ip)
                    out["shodan_cpes"] = list(shodan_result.cpes)
                    out["shodan_ports"] = list(shodan_result.ports)
                except Exception as exc:  # noqa: BLE001
                    log.warning("shodan_failed", ip=ip, error=str(exc))

        # DAST (tier 3) extras would go here (full nikto, BuiltWith).
        # Phase 8b will gate them on resolved-fields heuristics.

        out["site"] = _build_secondary_site(
            account=account,
            url=url,
            is_primary=is_primary,
            scan_data=out,
            tier=tier,
            scanned_at=datetime.now(UTC),
        )
        return out


# ---------------------------------------------------------------------------
# Mode + filter helpers
# ---------------------------------------------------------------------------


def _decide_mode(account: AccountIn, options: ScanOptions) -> str:
    if options.skip_validation or account.skip_validation:
        return "scan_only"
    if account.website:
        return "validate"
    return "discover"


def _is_authorized(account: AccountIn, options: ScanOptions) -> bool:
    return (account.title, account.country) in options.authorized_keys


def _apply_country_filter(
    accounts: list[AccountIn], country_filter: list[str]
) -> list[AccountIn]:
    if not country_filter:
        return accounts
    accepted = {c.strip() for c in country_filter if c.strip()}
    return [a for a in accounts if a.country in accepted]


def _issue_from_validation(
    account: AccountIn,
    issue_code: str,
    result: ValidationResult | None,
) -> IoValidationIssue:
    candidates: list[TopCandidate] = []
    suggestion = ""
    if result is not None:
        suggestion = result.suggestion or ""
        for c in result.top_candidates[:3]:
            candidates.append(TopCandidate(url=c.url, score=c.score))

    return IoValidationIssue(
        title=account.title,
        country=account.country,
        provided_website=account.website,
        issue=issue_code or IssueCode.POSSIBLE_MISMATCH.value,
        suggestion=suggestion,
        top_candidates=candidates,
    )


# ---------------------------------------------------------------------------
# Detection input + Site builders
# ---------------------------------------------------------------------------


def _build_detection_input(canonical_url: str | None, scan: dict) -> DetectionInput:  # type: ignore[type-arg]
    url = canonical_url or scan.get("url", "")
    return DetectionInput(
        url=url,
        status=scan.get("status", 0),
        headers={k.lower(): v for k, v in scan.get("headers", {}).items()},
        cookies=list(scan.get("cookies", [])),
        body_snippet=scan.get("body_snippet", ""),
        cnames=list(scan.get("cnames", [])),
        ip_addresses=list(scan.get("ip_addresses", [])),
        asn=scan.get("asn"),
        asn_org=scan.get("asn_org"),
        rdns_hostnames=list(scan.get("rdns_hostnames", [])),
        wafw00f_vendor=scan.get("wafw00f_vendor"),
        wafw00f_generic=scan.get("wafw00f_generic", False),
        whatweb_plugins=dict(scan.get("whatweb_plugins", {})),
        wappalyzer_techs=dict(scan.get("wappalyzer_techs", {})),
        shodan_cpes=list(scan.get("shodan_cpes", [])),
        shodan_ports=list(scan.get("shodan_ports", [])),
    )


def _build_primary_site(
    account: AccountIn,
    canonical_url: str | None,
    scan: dict,  # type: ignore[type-arg]
    waf: object,
    cdn: object,
    cloud: object,
    stack: object,
    *,
    tier: str,
    scanned_at: datetime,
) -> Site:
    tls = scan.get("tls")
    return Site(
        title=account.title,
        country=account.country,
        site_url=canonical_url or account.website or "",
        is_primary=True,
        alive=scan.get("alive", False),
        status_code=scan.get("status", 0),
        ip=(scan["ip_addresses"][0] if scan.get("ip_addresses") else ""),
        asn=scan.get("asn"),
        asn_org=scan.get("asn_org") or "",
        cloud_provider=getattr(cloud, "provider", None) or "-",
        cdn=getattr(cdn, "vendor", None) or "-",
        waf_detected=bool(getattr(waf, "vendor", None)),
        waf_vendor=getattr(waf, "vendor", None) or "-",
        waf_tool="",
        cms_framework=getattr(stack, "cms", None) or "-",
        web_server=getattr(stack, "web_server", None) or "-",
        tls_version=getattr(tls, "version", None) or "-" if tls else "-",
        cert_issuer=getattr(tls, "cert_issuer", None) or "" if tls else "",
        cert_expires_at=getattr(tls, "not_after", None) if tls else None,
        hsts="strict-transport-security" in scan.get("headers", {}),
        csp=scan.get("headers", {}).get("content-security-policy", ""),
        xfo=scan.get("headers", {}).get("x-frame-options", ""),
        xcto="x-content-type-options" in scan.get("headers", {}),
        referrer_policy=scan.get("headers", {}).get("referrer-policy", ""),
        permissions_policy=scan.get("headers", {}).get("permissions-policy", ""),
        scan_tier=tier,
        scanned_at=scanned_at,
    )


def _build_secondary_site(
    *,
    account: AccountIn,
    url: str,
    is_primary: bool,
    scan_data: dict,  # type: ignore[type-arg]
    tier: str,
    scanned_at: datetime,
) -> Site:
    headers = scan_data.get("headers", {})
    tls = scan_data.get("tls")
    return Site(
        title=account.title,
        country=account.country,
        site_url=url,
        is_primary=is_primary,
        alive=scan_data.get("alive", False),
        status_code=scan_data.get("status", 0),
        ip=(
            scan_data["ip_addresses"][0] if scan_data.get("ip_addresses") else ""
        ),
        asn=scan_data.get("asn"),
        asn_org=scan_data.get("asn_org") or "",
        cloud_provider="-",
        cdn="-",
        waf_detected=bool(scan_data.get("wafw00f_vendor")),
        waf_vendor=scan_data.get("wafw00f_vendor") or "-",
        cms_framework="-",
        web_server="-",
        tls_version=getattr(tls, "version", None) or "-" if tls else "-",
        cert_issuer=getattr(tls, "cert_issuer", None) or "" if tls else "",
        cert_expires_at=getattr(tls, "not_after", None) if tls else None,
        hsts="strict-transport-security" in headers,
        csp=headers.get("content-security-policy", ""),
        xfo=headers.get("x-frame-options", ""),
        xcto="x-content-type-options" in headers,
        referrer_policy=headers.get("referrer-policy", ""),
        permissions_policy=headers.get("permissions-policy", ""),
        scan_tier=tier,
        scanned_at=scanned_at,
    )


# Re-export ValidationIssue alias for callers that don't want to chase
# the io.models package directly.
ValidationIssueRow = ValidationIssue
_ = parse_url  # silence "imported but unused" — used by typing-only callers
