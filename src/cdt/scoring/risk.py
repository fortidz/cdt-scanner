"""RiskScore /15 computation per v0.4 §6.

Pure function: takes a ``ScoringInput`` and a reference ``now``, walks the
10-item rubric, returns ``(RiskScore, list[Finding])``. No IO, no clock
side-effects when ``now`` is passed in.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import structlog

from cdt.scoring.models import (
    Finding,
    FindingCode,
    RiskBand,
    RiskBreakdownItem,
    RiskScore,
    ScoringInput,
    Severity,
)

log = structlog.get_logger()

_MAX_SCORE = 15

_TLS_LOW_VERSIONS = {
    "TLSv1",
    "TLSv1.0",
    "TLS 1.0",
    "TLSv1.1",
    "TLS 1.1",
    "SSLv3",
    "SSL 3.0",
    "SSLv2",
}

_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors", re.IGNORECASE)


class RiskScorer:
    """Stateless scorer. Reusable across many sites."""

    def score(
        self,
        scoring_input: ScoringInput,
        now: datetime | None = None,
    ) -> tuple[RiskScore, list[Finding]]:
        log.info(
            "risk_scoring_started",
            url=scoring_input.url,
            tier=scoring_input.tier,
            is_alive=scoring_input.is_alive,
        )

        if not scoring_input.is_alive:
            log.info("risk_scored", url=scoring_input.url, score=0, band=RiskBand.LOW.value)
            return RiskScore(score=0, band=RiskBand.LOW, breakdown=[]), []

        breakdown: list[RiskBreakdownItem] = []
        findings: list[Finding] = []
        reference = now or datetime.now(UTC)

        breakdown.append(
            RiskBreakdownItem(
                rubric_item="alive_baseline", points=1, reason="site reachable"
            )
        )

        self._score_missing_waf(scoring_input, breakdown, findings)
        self._score_tls_expiry(scoring_input, reference, breakdown, findings)
        self._score_tls_version(scoring_input, breakdown, findings)
        self._score_missing_hsts(scoring_input, breakdown, findings)
        self._score_missing_csp(scoring_input, breakdown, findings)
        self._score_missing_xfo(scoring_input, breakdown, findings)

        if scoring_input.tier == "dast":
            self._score_dast_signals(scoring_input, breakdown, findings)

        self._score_secondary_sites(scoring_input, breakdown, findings)

        total = min(_MAX_SCORE, sum(item.points for item in breakdown))
        band = _band_for(total)

        log.info(
            "risk_scored",
            url=scoring_input.url,
            score=total,
            band=band.value,
            findings=len(findings),
        )
        return RiskScore(score=total, band=band, breakdown=breakdown), findings

    # ------------------------------------------------------------------

    def _score_missing_waf(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        decision = compute_waf_decision(ctx.waf)
        if decision != "No":
            return
        breakdown.append(
            RiskBreakdownItem(
                rubric_item="missing_waf",
                points=3,
                reason="no WAF detected and CDN does not provide WAF function",
            )
        )
        findings.append(
            Finding(
                title=ctx.title,
                country=ctx.country,
                site_url=ctx.url,
                finding_code=FindingCode.MISSING_WAF,
                severity=Severity.HIGH,
                message="No WAF or WAF-capable CDN detected.",
            )
        )

    def _score_tls_expiry(
        self,
        ctx: ScoringInput,
        reference: datetime,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        tls = ctx.tls
        if tls is None or tls.not_after is None:
            return
        threshold = reference + timedelta(days=30)
        if tls.not_after <= threshold:
            breakdown.append(
                RiskBreakdownItem(
                    rubric_item="cert_expired_or_near",
                    points=2,
                    reason=f"cert not_after={tls.not_after.isoformat()}",
                )
            )
            findings.append(
                Finding(
                    title=ctx.title,
                    country=ctx.country,
                    site_url=ctx.url,
                    finding_code=FindingCode.EXPIRED_CERT,
                    severity=Severity.HIGH,
                    message="TLS certificate expired or expires within 30 days.",
                    evidence=tls.not_after.isoformat(),
                )
            )

    def _score_tls_version(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        tls = ctx.tls
        if tls is None or not tls.version:
            return
        normalized = tls.version.replace(" ", "").upper()
        if any(low.replace(" ", "").upper() == normalized for low in _TLS_LOW_VERSIONS):
            breakdown.append(
                RiskBreakdownItem(
                    rubric_item="weak_tls",
                    points=2,
                    reason=f"version={tls.version}",
                )
            )
            findings.append(
                Finding(
                    title=ctx.title,
                    country=ctx.country,
                    site_url=ctx.url,
                    finding_code=FindingCode.WEAK_TLS,
                    severity=Severity.HIGH,
                    message="TLS version below 1.2 is enabled.",
                    evidence=tls.version,
                )
            )

    def _score_missing_hsts(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        if "strict-transport-security" in ctx.headers:
            return
        breakdown.append(
            RiskBreakdownItem(rubric_item="missing_hsts", points=1)
        )
        findings.append(
            Finding(
                title=ctx.title,
                country=ctx.country,
                site_url=ctx.url,
                finding_code=FindingCode.MISSING_HSTS,
                severity=Severity.MEDIUM,
                message="Strict-Transport-Security header missing.",
            )
        )

    def _score_missing_csp(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        if "content-security-policy" in ctx.headers:
            return
        breakdown.append(
            RiskBreakdownItem(rubric_item="missing_csp", points=1)
        )
        findings.append(
            Finding(
                title=ctx.title,
                country=ctx.country,
                site_url=ctx.url,
                finding_code=FindingCode.MISSING_CSP,
                severity=Severity.MEDIUM,
                message="Content-Security-Policy header missing.",
            )
        )

    def _score_missing_xfo(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        if "x-frame-options" in ctx.headers:
            return
        csp = ctx.headers.get("content-security-policy", "")
        if csp and _FRAME_ANCESTORS_RE.search(csp):
            return
        breakdown.append(
            RiskBreakdownItem(rubric_item="missing_xfo", points=1)
        )
        findings.append(
            Finding(
                title=ctx.title,
                country=ctx.country,
                site_url=ctx.url,
                finding_code=FindingCode.MISSING_XFO,
                severity=Severity.LOW,
                message="X-Frame-Options missing and CSP frame-ancestors absent.",
            )
        )

    def _score_dast_signals(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        if ctx.server_header_cve_known:
            breakdown.append(
                RiskBreakdownItem(rubric_item="cve_known_version", points=2)
            )
            findings.append(
                Finding(
                    title=ctx.title,
                    country=ctx.country,
                    site_url=ctx.url,
                    finding_code=FindingCode.CVE_KNOWN_VERSION,
                    severity=Severity.HIGH,
                    message="Server header exposes a version with known CVEs.",
                )
            )
        if ctx.admin_panel_exposed:
            breakdown.append(
                RiskBreakdownItem(rubric_item="admin_exposed", points=1)
            )
            findings.append(
                Finding(
                    title=ctx.title,
                    country=ctx.country,
                    site_url=ctx.url,
                    finding_code=FindingCode.EXPOSED_ADMIN,
                    severity=Severity.MEDIUM,
                    message="Admin/login panel discovered without auth gating.",
                )
            )
        if ctx.cms_outdated_with_cve:
            breakdown.append(
                RiskBreakdownItem(rubric_item="cms_outdated", points=1)
            )
            findings.append(
                Finding(
                    title=ctx.title,
                    country=ctx.country,
                    site_url=ctx.url,
                    finding_code=FindingCode.OUTDATED_CMS,
                    severity=Severity.MEDIUM,
                    message="CMS version is outdated with known CVEs.",
                )
            )

    def _score_secondary_sites(
        self,
        ctx: ScoringInput,
        breakdown: list[RiskBreakdownItem],
        findings: list[Finding],
    ) -> None:
        # v0.4 §6.1: only fires when primary IS protected and secondary is not.
        primary_decision = compute_waf_decision(ctx.waf)
        primary_protected = primary_decision == "Yes"
        any_secondary_unprotected = any(
            not protected for protected in ctx.secondary_sites_protected
        )
        if not (primary_protected and any_secondary_unprotected):
            return
        breakdown.append(
            RiskBreakdownItem(
                rubric_item="secondary_unprotected",
                points=1,
                reason="primary protected, at least one secondary missing WAF",
            )
        )
        findings.append(
            Finding(
                title=ctx.title,
                country=ctx.country,
                site_url=ctx.url,
                finding_code=FindingCode.SECONDARY_SITE_EXPOSED,
                severity=Severity.MEDIUM,
                message="A secondary site lacks WAF while the primary is protected.",
            )
        )


def _band_for(score: int) -> RiskBand:
    if score >= 13:
        return RiskBand.CRITICAL
    if score >= 10:
        return RiskBand.HIGH
    if score >= 6:
        return RiskBand.MEDIUM
    return RiskBand.LOW


def compute_waf_decision(waf: object) -> str:
    """Mirrors ``opportunity.compute_waf_decision`` but kept in this module to
    avoid a circular import. Both modules use the same logic; the helper is
    re-exported from ``scoring.opportunity`` for callers there."""

    from cdt.detect.models import Confidence  # local import: avoids cycle

    confidence = getattr(waf, "confidence", None)
    waf_active = getattr(waf, "waf_active", False)
    if confidence == Confidence.HIGH and waf_active:
        return "Yes"
    if confidence == Confidence.HIGH and not waf_active:
        return "Further investigation needed"
    if confidence == Confidence.MEDIUM:
        return "Further investigation needed"
    return "No"
