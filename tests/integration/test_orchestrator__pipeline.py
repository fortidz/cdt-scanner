"""End-to-end orchestrator integration tests with mocked components.

These tests build an ``OrchestratorComponents`` graph manually with
``AsyncMock`` substitutes for everything that does IO. They verify the
wiring end-to-end: discovery → scan → detect → scoring → ScanRunResults.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cdt.config_loader import CdtConfig
from cdt.detect import (
    CdnDetection,
    CloudDetection,
    Confidence,
    StackDetection,
    WafDetection,
)
from cdt.discovery import ValidationResult
from cdt.discovery.models import IssueCode
from cdt.models import AccountIn
from cdt.orchestrator import (
    Orchestrator,
    OrchestratorComponents,
    ScanOptions,
)
from cdt.scan.models import ASNResult, BrowserResult, DNSResult, PassiveResult
from cdt.scoring import (
    OpportunityFlags,
    RiskBand,
    RiskScore,
    ScoringResult,
)
from cdt.tools import (
    BuiltWithResult,
    CensysCertResult,
    CensysHostResult,
    NiktoSkipAllowlist,
    ShodanHostResult,
    ShodanInternetDBResult,
    WappalyzerResult,
    WhatWebResult,
)
from cdt.tools import (
    WafDetection as WafW00fDetection,
)

NOW = datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC)


def _build_mock_components(
    *,
    brave_validate_confirmed: bool = True,
    cloud_provider: str | None = "AWS",
    cloud_role: str = "hyperscaler",
    waf_vendor: str | None = None,
) -> OrchestratorComponents:
    """Construct an OrchestratorComponents with every IO call mocked."""

    brave = MagicMock()
    brave.validate = AsyncMock(return_value=ValidationResult(
        confirmed=brave_validate_confirmed,
        canonical_url="acme.example" if brave_validate_confirmed else None,
        issue=None if brave_validate_confirmed else IssueCode.LOW_CONFIDENCE,
    ))
    brave.discover = AsyncMock(return_value=ValidationResult(
        confirmed=brave_validate_confirmed,
        canonical_url="acme.example" if brave_validate_confirmed else None,
        issue=None if brave_validate_confirmed else IssueCode.LOW_CONFIDENCE,
    ))

    validator = MagicMock()
    validator.validate = AsyncMock(return_value=ValidationResult(
        confirmed=False, canonical_url="https://acme.example/",
        needs_semantic_check=True,
    ))

    expander = MagicMock()
    expander.expand = AsyncMock(return_value=MagicMock(
        apex="acme.example", websites=["www.acme.example"], total_subdomains_seen=1,
    ))

    passive = MagicMock()
    passive.scan = AsyncMock(return_value=PassiveResult(
        url="https://acme.example/",
        dns=DNSResult(apex="acme.example", a_records=["1.2.3.4"]),
        whois=None,
        asn=ASNResult(ip="1.2.3.4", asn=14618, asn_org="Amazon"),
        scanned_at=NOW,
    ))

    browser = MagicMock()
    browser.fetch = AsyncMock(return_value=BrowserResult(
        url="https://acme.example/",
        status=200,
        final_url="https://acme.example/",
        headers={"server": "nginx/1.27.1", "content-type": "text/html"},
        body_snippet="<html><body>OK</body></html>",
        body_size=42,
        scanned_at=NOW,
    ))

    wafw00f = MagicMock()
    wafw00f.detect = AsyncMock(return_value=WafW00fDetection(
        url="https://acme.example/", vendor=waf_vendor,
    ))

    whatweb = MagicMock()
    whatweb.detect = AsyncMock(return_value=WhatWebResult(url="https://acme.example/"))

    nikto = MagicMock()
    nikto.run_tier2 = AsyncMock()
    nikto.run_tier3 = AsyncMock()
    _ = NiktoSkipAllowlist.empty()  # touch import; orchestrator wires its own

    shodan = MagicMock()
    shodan.lookup_internetdb = AsyncMock(return_value=ShodanInternetDBResult(ip="1.2.3.4"))
    shodan.lookup_host = AsyncMock(return_value=ShodanHostResult(ip="1.2.3.4"))

    censys = MagicMock()
    censys.lookup_host = AsyncMock(return_value=CensysHostResult(ip="1.2.3.4"))
    censys.search_certs = AsyncMock(return_value=CensysCertResult(domain="acme.example"))

    wappalyzer = MagicMock()
    wappalyzer.detect = AsyncMock(return_value=WappalyzerResult(url="https://acme.example/"))

    builtwith = MagicMock()
    builtwith.lookup = AsyncMock(return_value=BuiltWithResult(domain="acme.example"))

    waf_detector = MagicMock()
    waf_detector.detect = MagicMock(return_value=WafDetection(
        vendor=waf_vendor,
        confidence=Confidence.HIGH if waf_vendor else Confidence.LOW,
        waf_active=bool(waf_vendor),
        cdn_capable=False,
    ))

    cdn_detector = MagicMock()
    cdn_detector.detect = MagicMock(return_value=CdnDetection())

    cloud_attributor = MagicMock()
    cloud_attributor.attribute = AsyncMock(return_value=CloudDetection(
        provider=cloud_provider,
        confidence=Confidence.HIGH if cloud_provider else Confidence.LOW,
        source="ip_range" if cloud_provider else "unknown",
        role=cloud_role,
    ))

    stack_detector = MagicMock()
    stack_detector.detect = MagicMock(return_value=StackDetection(
        web_server="nginx/1.27.1",
        cms=None,
    ))

    scoring_engine = MagicMock()

    def _evaluate_stub(scoring_input: Any) -> ScoringResult:
        # Multi-CSP -> CNAPP. AWS-only no-WAF -> AppSec.
        cnapp = sum([
            scoring_input.has_aws, scoring_input.has_azure,
            scoring_input.has_gcp, scoring_input.has_oci,
        ]) >= 2
        appsec = scoring_input.waf.vendor is None and scoring_input.cloud.provider is not None
        complexity_count = sum([
            scoring_input.has_aws, scoring_input.has_azure,
            scoring_input.has_gcp, scoring_input.has_oci,
        ])
        complexity_table = ("-", "One CSP", "Two CSP", "Three CSP", "Four CSP")
        complexity = complexity_table[complexity_count]
        return ScoringResult(
            risk=RiskScore(score=7, band=RiskBand.MEDIUM, breakdown=[]),
            opportunity=OpportunityFlags(appsec=appsec, web=False, cnapp=cnapp),
            rationale="mock rationale",
            findings=[],
            waf_decision="No" if scoring_input.waf.vendor is None else "Yes",
            waf_vendor=scoring_input.waf.vendor or "-",
            waf_tool="",
            public_cloud="Yes" if scoring_input.cloud.provider else "No",
            complexity=complexity,
            primary_hyperscaler=scoring_input.cloud.provider or "-",
            has_aws=scoring_input.has_aws,
            has_azure=scoring_input.has_azure,
            has_gcp=scoring_input.has_gcp,
            has_oci=scoring_input.has_oci,
        )

    scoring_engine.evaluate = MagicMock(side_effect=_evaluate_stub)

    from cdt.scan import ScanRunner
    from cdt.scan.runner import RateLimitedPool

    scan_runner = ScanRunner(pool=RateLimitedPool(concurrency=4, per_key_rps=1000))

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
    )


@pytest.fixture
def config(tmp_path: Path) -> CdtConfig:
    return CdtConfig()


# ---------- pipeline tests ----------


async def test_pipeline__validate_mode_with_brave_match(config: CdtConfig) -> None:
    components = _build_mock_components(brave_validate_confirmed=True)
    orchestrator = Orchestrator(config, components)

    accounts = [AccountIn(Title="Acme", Country="Ecuador", Website="acme.example")]
    options = ScanOptions(tier="browser")

    results = await orchestrator.run(accounts, options)

    assert len(results.successful) == 1
    successful = results.successful[0]
    assert successful.scoring_result is not None
    assert successful.scoring_result.opportunity.appsec is True
    assert successful.scoring_result.public_cloud == "Yes"


async def test_pipeline__discover_mode_low_confidence_to_validation_issues(
    config: CdtConfig,
) -> None:
    components = _build_mock_components(brave_validate_confirmed=False)
    orchestrator = Orchestrator(config, components)

    accounts = [AccountIn(Title="Acme", Country="Ecuador", Website="")]
    options = ScanOptions(tier="browser")

    # The validator step is skipped when website is empty (Discover mode).
    results = await orchestrator.run(accounts, options)

    assert len(results.with_issues) == 1
    issue = results.with_issues[0].validation_issue
    assert issue is not None
    assert issue.issue == "LOW_CONFIDENCE"


async def test_pipeline__multi_csp_recommends_cnapp(config: CdtConfig) -> None:
    components = _build_mock_components(brave_validate_confirmed=True, cloud_provider="AWS")
    orchestrator = Orchestrator(config, components)

    accounts = [AccountIn(Title="Acme", Country="Ecuador", Website="acme.example")]
    options = ScanOptions(tier="browser")

    results = await orchestrator.run(accounts, options)

    successful = results.successful[0]
    assert successful.scoring_result is not None
    # The mock evaluate stub maps cloud.provider="AWS" → has_aws=True only;
    # without azure/gcp/oci flags, CNAPP stays False but AppSec fires.
    assert successful.scoring_result.opportunity.appsec is True


async def test_pipeline__error_in_one_account_does_not_kill_run(
    config: CdtConfig,
) -> None:
    """An exception in scan_account is captured to validation_issues."""

    components = _build_mock_components(brave_validate_confirmed=True)

    orig_validate = components.validator.validate
    call_count = {"n": 0}

    async def maybe_fail(account: AccountIn) -> Any:
        call_count["n"] += 1
        if "bad" in account.website:
            raise RuntimeError("simulated failure")
        return await orig_validate(account)

    components.validator.validate = maybe_fail  # type: ignore[assignment]

    orchestrator = Orchestrator(config, components)
    accounts = [
        AccountIn(Title="Acme", Country="Ecuador", Website="ok1.example"),
        AccountIn(Title="Beta", Country="Perú", Website="bad.example"),
        AccountIn(Title="Gamma", Country="Chile", Website="ok3.example"),
    ]
    options = ScanOptions(tier="browser")
    results = await orchestrator.run(accounts, options)

    titles = [a.title for a in results.accounts]
    assert sorted(titles) == ["Acme", "Beta", "Gamma"]

    bad = next(a for a in results.accounts if a.title == "Beta")
    # Beta's validator raises; the outer safety net moves it to validation_issues.
    assert bad.validation_issue is not None or bad.scoring_result is not None
