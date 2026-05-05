"""Fortinet recommendation calculator (v0.4 §7.3).

Decision tree:

  Default: AppSec=No, Web=No, CNAPP=No

  Si WAF=No OR (WAF=Yes AND vendor != Fortinet AND RiskScore >= HIGH):
      Si PublicCloud=Yes:  AppSec=Yes
      Sino:                Web=Yes

  Si Complexity ∈ {Two, Three, Four CSP}:
      CNAPP=Yes

  Excepción (overrides AppSec/Web; CNAPP queda según multi-CSP):
      Si vendor=Fortinet AND band=LOW AND complexity="One CSP":
          AppSec=No, Web=No
"""

from __future__ import annotations

import structlog

from cdt.detect.models import CloudDetection, WafDetection
from cdt.scoring.models import (
    OpportunityFlags,
    RiskBand,
    RiskScore,
    ScoringInput,
)
from cdt.scoring.risk import compute_waf_decision as _compute_waf_decision

log = structlog.get_logger()

_FORTINET_PREFIX = "Fortinet"
_HIGH_BANDS = {RiskBand.HIGH, RiskBand.CRITICAL}
_MULTI_CSP = {"Two CSP", "Three CSP", "Four CSP"}
_COMPLEXITY_TABLE = ("-", "One CSP", "Two CSP", "Three CSP", "Four CSP")


class OpportunityCalculator:
    def calculate(
        self, scoring_input: ScoringInput, risk: RiskScore
    ) -> OpportunityFlags:
        waf_decision = compute_waf_decision(scoring_input.waf)
        public_cloud = compute_public_cloud(scoring_input.cloud)
        complexity = compute_complexity(
            public_cloud,
            has_aws=scoring_input.has_aws,
            has_azure=scoring_input.has_azure,
            has_gcp=scoring_input.has_gcp,
            has_oci=scoring_input.has_oci,
        )

        appsec = False
        web = False
        cnapp = False

        # WAF missing or competitor with HIGH+ risk.
        vendor = scoring_input.waf.vendor or ""
        is_fortinet_vendor = vendor.startswith(_FORTINET_PREFIX)
        competitor_high_risk = (
            waf_decision == "Yes"
            and not is_fortinet_vendor
            and risk.band in _HIGH_BANDS
        )
        if waf_decision == "No" or competitor_high_risk:
            if public_cloud == "Yes":
                appsec = True
            else:
                web = True

        # Multi-CSP always adds CNAPP.
        if complexity in _MULTI_CSP:
            cnapp = True

        # Late-firing exception per §7.3 trailing rule.
        if (
            is_fortinet_vendor
            and risk.band == RiskBand.LOW
            and complexity == "One CSP"
        ):
            appsec = False
            web = False
            # CNAPP is independent — multi-CSP can't co-exist with One CSP, so
            # this branch never clears CNAPP in practice. Kept explicit.

        log.info(
            "opportunity_calculated",
            url=scoring_input.url,
            appsec=appsec,
            web=web,
            cnapp=cnapp,
            waf_decision=waf_decision,
            public_cloud=public_cloud,
            complexity=complexity,
        )
        return OpportunityFlags(appsec=appsec, web=web, cnapp=cnapp)


# ---------------------------------------------------------------------------
# Helpers exposed for the engine + renderer
# ---------------------------------------------------------------------------


def compute_waf_decision(waf: WafDetection) -> str:
    """Re-export from ``risk`` to keep callers in this module clean."""

    return _compute_waf_decision(waf)


def compute_public_cloud(cloud: CloudDetection) -> str:
    """v0.4 §14.2 → §3.3 public_cloud column."""

    from cdt.detect.models import Confidence  # local import: avoids cycle

    if cloud.confidence == Confidence.HIGH:
        if cloud.role == "datacenter":
            return "No"
        return "Yes"
    if cloud.confidence == Confidence.MEDIUM:
        return "Further investigation needed"
    return "Further investigation needed" if cloud.provider else "No"


def compute_complexity(
    public_cloud: str,
    *,
    has_aws: bool,
    has_azure: bool,
    has_gcp: bool,
    has_oci: bool,
) -> str:
    """v0.4 §3.3 ``Complexity`` column.

    "One CSP" .. "Four CSP" by hyperscaler count when in public cloud;
    "-" when not in public cloud or zero hyperscalers detected.
    """

    if public_cloud == "No":
        return "-"
    count = sum([has_aws, has_azure, has_gcp, has_oci])
    if count == 0:
        return "-"
    return _COMPLEXITY_TABLE[count]


def compute_primary_hyperscaler(
    cloud: CloudDetection,
    *,
    has_aws: bool,
    has_azure: bool,
    has_gcp: bool,
    has_oci: bool,
) -> str:
    """The primary site's hyperscaler when classifiable; else first present
    in ``has_*`` priority order; else ``"-"``."""

    primary = (cloud.provider or "").upper()
    if primary in {"AWS", "AZURE", "GCP", "OCI"}:
        return primary

    for label, present in (
        ("AWS", has_aws),
        ("Azure", has_azure),
        ("GCP", has_gcp),
        ("OCI", has_oci),
    ):
        if present:
            return label
    return "-"


def list_csps(
    *,
    has_aws: bool,
    has_azure: bool,
    has_gcp: bool,
    has_oci: bool,
) -> str:
    """Joined hyperscaler labels for rationale templates: ``"AWS+GCP"``."""

    parts: list[str] = []
    if has_aws:
        parts.append("AWS")
    if has_azure:
        parts.append("Azure")
    if has_gcp:
        parts.append("GCP")
    if has_oci:
        parts.append("OCI")
    return "+".join(parts) if parts else "-"
