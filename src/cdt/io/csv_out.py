"""CSV writers for the four output files (v0.4 §3.3-§3.6).

All outputs honour the v0.5 §3.10 contract:
  - encoding utf-8 (NO BOM)
  - newline LF (``\\n``)
  - quoting RFC 4180 minimal (``csv.QUOTE_MINIMAL``)

Column orders match v0.4 §3.3-§3.6 exactly. Mutating these tuples requires
a coordinated SharePoint List schema update per v0.4 §20.3.9.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import structlog

from cdt.io.models import AccountInMetadata, Site, ValidationIssue
from cdt.scoring import Finding, ScoringResult

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Header definitions — column order is part of the public contract.
# ---------------------------------------------------------------------------


ACCOUNTS_ENRICHED_HEADERS: tuple[str, ...] = (
    "Title",
    "Country",
    "PublicCloud",
    "Complexity",
    "HasAWS",
    "HasAzure",
    "HasGCP",
    "HasOCI",
    "PrimaryHyperScaler",
    "Website01",
    "Website02",
    "Website03",
    "Website04",
    "Website05",
    "WAF",
    "WAFVendor",
    "WAFTool",
    "CMSFramework",
    "WebServer",
    "CDN",
    "RiskScore",
    "RecommendsFortiAppSec",
    "RecommendsFortiWeb",
    "RecommendsFortiCNAPP",
    "OpportunityRationale",
    "ScannedAt",
)

SITES_HEADERS: tuple[str, ...] = (
    "Title",
    "Country",
    "SiteURL",
    "IsPrimary",
    "Alive",
    "StatusCode",
    "IP",
    "ASN",
    "ASNOrg",
    "CloudProvider",
    "CDN",
    "WAFDetected",
    "WAFVendor",
    "WAFTool",
    "CMSFramework",
    "WebServer",
    "TLSVersion",
    "CertIssuer",
    "CertExpiresAt",
    "HSTS",
    "CSP",
    "XFO",
    "XCTO",
    "ReferrerPolicy",
    "PermissionsPolicy",
    "ScanTier",
    "ScannedAt",
    # Fase 9 #1: appended at the end so the existing column 1..27 order
    # stays byte-stable for SharePoint Grid view paste; consumers that
    # ignore unknown trailing columns continue to work unchanged.
    "OriginCloudProvider",
)

FINDINGS_HEADERS: tuple[str, ...] = (
    "Title",
    "Country",
    "SiteURL",
    "FindingCode",
    "Severity",
    "Message",
    "Evidence",
)

VALIDATION_ISSUES_HEADERS: tuple[str, ...] = (
    "Title",
    "Country",
    "ProvidedWebsite",
    "Issue",
    "Suggestion",
    "TopCandidates",
)


# Operator-facing limits.
_RATIONALE_MAX = 200
_EVIDENCE_MAX = 500


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class CsvOutputWriter:
    def __init__(self, out_dir: Path) -> None:
        self._out = Path(out_dir)
        self._out.mkdir(parents=True, exist_ok=True)

    # ---------- accounts_enriched.csv ----------

    def write_accounts_enriched(
        self,
        rows: Iterable[ScoringResult],
        extra_metadata: dict[str, AccountInMetadata],
    ) -> int:
        """Write ``accounts_enriched.csv``.

        ``extra_metadata`` is keyed by the composite ``"{Title}|{Country}"``
        string; the orchestrator (Phase 8) builds the dict before calling.
        ``rows`` is consumed in iteration order and matched by composite key
        derived from ``ScoringResult`` row metadata that the orchestrator
        attaches via the metadata table.
        """

        path = self._out / "accounts_enriched.csv"
        # Iterate rows once; the orchestrator places each ScoringResult next
        # to its metadata in dict-insertion order. We zip without consuming
        # the dict's order — for single-account smoke tests, fall back to
        # the only metadata available.
        meta_iter = iter(extra_metadata.values())
        return self._write_dict_rows(
            path,
            ACCOUNTS_ENRICHED_HEADERS,
            (
                _enriched_row(_next_or_only(meta_iter, extra_metadata), result)
                for result in rows
            ),
        )

    # ---------- sites.csv ----------

    def write_sites(self, rows: Iterable[Site]) -> int:
        path = self._out / "sites.csv"
        return self._write_dict_rows(
            path,
            SITES_HEADERS,
            (_site_row(site) for site in rows),
        )

    # ---------- findings.csv ----------

    def write_findings(self, rows: Iterable[Finding]) -> int:
        path = self._out / "findings.csv"
        return self._write_dict_rows(
            path,
            FINDINGS_HEADERS,
            (_finding_row(f) for f in rows),
        )

    # ---------- validation_issues.csv ----------

    def write_validation_issues(self, rows: Iterable[ValidationIssue]) -> int:
        path = self._out / "validation_issues.csv"
        return self._write_dict_rows(
            path,
            VALIDATION_ISSUES_HEADERS,
            (_issue_row(issue) for issue in rows),
        )

    # ---------- shared writer ----------

    def _write_dict_rows(
        self,
        path: Path,
        headers: tuple[str, ...],
        rows: Iterable[dict[str, str]],
    ) -> int:
        count = 0
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=list(headers),
                quoting=csv.QUOTE_MINIMAL,
                lineterminator="\n",
                extrasaction="ignore",
            )
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                count += 1

        bytes_written = path.stat().st_size
        log.info(
            "csv_written",
            path=str(path),
            rows=count,
            bytes=bytes_written,
        )
        return count


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------


def _next_or_only(
    it: Iterator[AccountInMetadata],
    table: dict[str, AccountInMetadata],
) -> AccountInMetadata:
    """Pull the next metadata entry, or the sole entry if there is exactly one.

    The orchestrator (Phase 8) is responsible for inserting metadata into the
    dict in the same order it yields ScoringResults. For single-account
    smoke tests where ``len(table) == 1``, we tolerate any iteration order.
    """

    try:
        return next(it)
    except StopIteration:
        if len(table) == 1:
            return next(iter(table.values()))
        raise KeyError(
            "No AccountInMetadata available for ScoringResult; orchestrator "
            "must populate `extra_metadata` keyed by 'Title|Country' in row "
            "order."
        ) from None


def _enriched_row(
    meta: AccountInMetadata, result: ScoringResult
) -> dict[str, str]:
    return {
        "Title": meta.title,
        "Country": meta.country,
        "PublicCloud": result.public_cloud,
        "Complexity": result.complexity,
        "HasAWS": _yes_no(result.has_aws),
        "HasAzure": _yes_no(result.has_azure),
        "HasGCP": _yes_no(result.has_gcp),
        "HasOCI": _yes_no(result.has_oci),
        "PrimaryHyperScaler": result.primary_hyperscaler,
        "Website01": meta.website01,
        "Website02": meta.website02,
        "Website03": meta.website03,
        "Website04": meta.website04,
        "Website05": meta.website05,
        "WAF": result.waf_decision,
        "WAFVendor": result.waf_vendor,
        "WAFTool": result.waf_tool,
        "CMSFramework": _dash_if_empty(meta.cms_framework),
        "WebServer": _dash_if_empty(meta.web_server),
        "CDN": _dash_if_empty(meta.cdn),
        "RiskScore": result.risk.display,
        "RecommendsFortiAppSec": _render_recommend(result.opportunity.appsec),
        "RecommendsFortiWeb": _render_recommend(result.opportunity.web),
        "RecommendsFortiCNAPP": _render_recommend(result.opportunity.cnapp),
        "OpportunityRationale": _truncate(result.rationale, _RATIONALE_MAX),
        "ScannedAt": _iso_z(meta.scanned_at),
    }


def _site_row(site: Site) -> dict[str, str]:
    return {
        "Title": site.title,
        "Country": site.country,
        "SiteURL": site.site_url,
        "IsPrimary": _bit(site.is_primary),
        "Alive": _bit(site.alive),
        "StatusCode": str(site.status_code) if site.status_code else "",
        "IP": site.ip,
        "ASN": str(site.asn) if site.asn is not None else "",
        "ASNOrg": site.asn_org,
        "CloudProvider": _dash_if_empty(site.cloud_provider),
        "CDN": _dash_if_empty(site.cdn),
        "WAFDetected": _bit(site.waf_detected),
        "WAFVendor": _dash_if_empty(site.waf_vendor),
        "WAFTool": site.waf_tool,
        "CMSFramework": _dash_if_empty(site.cms_framework),
        "WebServer": _dash_if_empty(site.web_server),
        "TLSVersion": _dash_if_empty(site.tls_version),
        "CertIssuer": site.cert_issuer,
        "CertExpiresAt": _iso_z(site.cert_expires_at) if site.cert_expires_at else "",
        "HSTS": _bit(site.hsts),
        "CSP": site.csp if site.csp else "0",
        "XFO": site.xfo if site.xfo else "0",
        "XCTO": _bit(site.xcto),
        "ReferrerPolicy": site.referrer_policy if site.referrer_policy else "0",
        "PermissionsPolicy": (
            site.permissions_policy if site.permissions_policy else "0"
        ),
        "ScanTier": site.scan_tier,
        "ScannedAt": _iso_z(site.scanned_at),
        "OriginCloudProvider": _dash_if_empty(site.origin_cloud_provider),
    }


def _finding_row(f: Finding) -> dict[str, str]:
    return {
        "Title": f.title,
        "Country": f.country,
        "SiteURL": f.site_url,
        "FindingCode": f.finding_code.value,
        "Severity": f.severity.value,
        "Message": f.message,
        "Evidence": _truncate(f.evidence, _EVIDENCE_MAX),
    }


def _issue_row(issue: ValidationIssue) -> dict[str, str]:
    candidates = ", ".join(
        f"{c.url} ({c.score:.1f})" for c in issue.top_candidates[:3]
    )
    return {
        "Title": issue.title,
        "Country": issue.country,
        "ProvidedWebsite": issue.provided_website,
        "Issue": issue.issue,
        "Suggestion": _dash_if_empty(issue.suggestion),
        "TopCandidates": candidates,
    }


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _render_recommend(value: bool | None) -> str:
    """Tri-state rendering for RecommendsForti{AppSec,Web,CNAPP} columns.

    ``None`` is the sentinel for "insufficient data" emitted by the
    opportunity calculator when ``tier=passive`` (Fase 9 #2). Distinct
    from ``False`` ("No") so operators can tell "we looked and the
    answer is no" apart from "we didn't have enough signal to decide".
    """

    if value is None:
        return "-"
    return "Yes" if value else "No"


def _bit(value: bool) -> str:
    return "1" if value else "0"


def _dash_if_empty(value: str | None) -> str:
    if not value or value.strip() == "":
        return "-"
    return value


def _safe_str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _truncate(text: str, limit: int) -> str:
    if not text or len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _iso_z(dt: datetime) -> str:
    """ISO 8601 UTC with explicit ``Z`` suffix.

    ``datetime.isoformat()`` would emit ``+00:00``; the SharePoint List parser
    is happier with the ``Z`` form (and v0.4 §3.3 row 26 uses ``Z`` literally).
    """

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


