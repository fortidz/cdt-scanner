"""Top-level scoring orchestrator. Composes risk + opportunity + rationale."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import structlog

from cdt.scoring.models import ScoringInput, ScoringResult
from cdt.scoring.opportunity import (
    OpportunityCalculator,
    compute_complexity,
    compute_primary_hyperscaler,
    compute_public_cloud,
    compute_waf_decision,
)
from cdt.scoring.rationale import RationaleRenderer
from cdt.scoring.risk import RiskScorer

log = structlog.get_logger()


class ScoringEngine:
    def __init__(
        self,
        rationale_path: Path,
        scorer: RiskScorer | None = None,
        calculator: OpportunityCalculator | None = None,
        renderer: RationaleRenderer | None = None,
    ) -> None:
        self._scorer = scorer or RiskScorer()
        self._calculator = calculator or OpportunityCalculator()
        self._renderer = renderer or RationaleRenderer(rationale_path)

    def evaluate(
        self,
        scoring_input: ScoringInput,
        now: datetime | None = None,
    ) -> ScoringResult:
        log.info("scoring_evaluation_started", url=scoring_input.url)

        risk, findings = self._scorer.score(scoring_input, now=now)
        opportunity = self._calculator.calculate(scoring_input, risk)

        waf_decision = compute_waf_decision(scoring_input.waf)
        public_cloud = compute_public_cloud(scoring_input.cloud)
        complexity = compute_complexity(
            public_cloud,
            has_aws=scoring_input.has_aws,
            has_azure=scoring_input.has_azure,
            has_gcp=scoring_input.has_gcp,
            has_oci=scoring_input.has_oci,
        )
        primary_hyperscaler = compute_primary_hyperscaler(
            scoring_input.cloud,
            has_aws=scoring_input.has_aws,
            has_azure=scoring_input.has_azure,
            has_gcp=scoring_input.has_gcp,
            has_oci=scoring_input.has_oci,
        )
        waf_vendor = scoring_input.waf.vendor or "-"
        waf_tool = _build_waf_tool(scoring_input.waf.vendor)

        rationale = self._renderer.render(
            opportunity,
            scoring_input,
            risk,
            primary_hyperscaler=primary_hyperscaler,
            complexity=complexity,
        )

        result = ScoringResult(
            risk=risk,
            opportunity=opportunity,
            rationale=rationale,
            findings=findings,
            waf_decision=waf_decision,
            waf_vendor=waf_vendor,
            waf_tool=waf_tool,
            public_cloud=public_cloud,
            complexity=complexity,
            primary_hyperscaler=primary_hyperscaler,
            has_aws=scoring_input.has_aws,
            has_azure=scoring_input.has_azure,
            has_gcp=scoring_input.has_gcp,
            has_oci=scoring_input.has_oci,
        )
        log.info(
            "scoring_evaluation_completed",
            url=scoring_input.url,
            risk=risk.display,
            appsec=opportunity.appsec,
            web=opportunity.web,
            cnapp=opportunity.cnapp,
        )
        return result


def _build_waf_tool(vendor: str | None) -> str:
    """Free-form description for the ``WAFTool`` column.

    v0.4 §3.3 keeps this column flexible; we use a vendor-prefixed string
    so analysts can grep by vendor in CSVs.
    """

    if not vendor:
        return ""
    if vendor.startswith("Fortinet_"):
        product = vendor.split("_", 1)[1]
        return f"{product} (Fortinet) WAF"
    return f"{vendor} WAF"
