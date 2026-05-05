"""Hypothesis accumulator + scoring engine.

The accumulator buckets ``SignalMatch`` per candidate and resolves a single
winner per category using the threshold + gap rules from
``hypothesis_resolution`` (v0.5 §5.7):

  - top.points >= threshold AND top.points - second.points >= gap → HIGH
  - top.points >= threshold but gap insufficient                  → MEDIUM
  - top.points <  threshold                                       → LOW (no winner)
"""

from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING

from cdt.detect.models import (
    CdnDetection,
    CloudDetection,
    Confidence,
    DetectionInput,
    Hypothesis,
    SignalMatch,
    StackDetection,
    WafDetection,
)
from cdt.detect.rules import (
    DetectionRules,
    WafVendorRule,
    WebServerBannerRule,
)
from cdt.detect.signals import evaluate_rule_signals, extract_meta_generator

if TYPE_CHECKING:
    from cdt.scan.models import IPRangeMatch


class HypothesisAccumulator:
    """Per-category vendor scoring bucket."""

    def __init__(self) -> None:
        self._buckets: dict[str, Hypothesis] = {}

    def add_signal(self, hypothesis_name: str, signal: SignalMatch) -> None:
        bucket = self._buckets.setdefault(
            hypothesis_name, Hypothesis(name=hypothesis_name)
        )
        bucket.points += signal.points
        bucket.signals_matched.append(signal)

    def winner(
        self, *, threshold: int, gap_required: int
    ) -> tuple[str | None, Confidence, int, list[SignalMatch]]:
        """Pick the top hypothesis under threshold + gap rules.

        Returns ``(name|None, confidence, gap, signals_for_winner)``.
        """

        if not self._buckets:
            return None, Confidence.LOW, 0, []

        ranked = sorted(
            self._buckets.values(), key=lambda h: h.points, reverse=True
        )
        top = ranked[0]
        runner = ranked[1] if len(ranked) > 1 else None
        gap = top.points - (runner.points if runner else 0)

        if top.points < threshold:
            return None, Confidence.LOW, gap, []

        if gap >= gap_required:
            return top.name, Confidence.HIGH, gap, list(top.signals_matched)

        return top.name, Confidence.MEDIUM, gap, list(top.signals_matched)

    def runner_up(self) -> str | None:
        if len(self._buckets) < 2:
            return None
        ranked = sorted(
            self._buckets.values(), key=lambda h: h.points, reverse=True
        )
        return ranked[1].name if len(ranked) > 1 else None


# ---------------------------------------------------------------------------
# ScoringEngine
# ---------------------------------------------------------------------------


class ScoringEngine:
    """Applies the rule pack to ``DetectionInput`` and resolves winners."""

    def __init__(self, rules: DetectionRules) -> None:
        self._rules = rules
        self._scoring = rules.scoring

    # ---------- WAF -------------------------------------------------------

    def evaluate_waf(self, ctx: DetectionInput) -> WafDetection:
        accumulator = HypothesisAccumulator()
        all_matches: dict[str, list[SignalMatch]] = {}

        for vendor_rule in self._rules.waf_vendors:
            matches = evaluate_rule_signals(
                vendor_rule.signals,
                ctx,
                self._scoring,
                source=vendor_rule.vendor,
            )
            for m in matches:
                accumulator.add_signal(vendor_rule.vendor, m)
            if matches:
                all_matches[vendor_rule.vendor] = matches

        # External tool corroborations (Fase 4): boost the matching vendor.
        if ctx.wafw00f_vendor:
            corroboration = SignalMatch(
                rule_kind="external_tool",
                points=self._scoring.primary_signal_points,
                source=ctx.wafw00f_vendor,
                evidence="wafw00f vendor match",
            )
            accumulator.add_signal(ctx.wafw00f_vendor, corroboration)
            all_matches.setdefault(ctx.wafw00f_vendor, []).append(corroboration)

        winner_name, confidence, gap, winning_signals = accumulator.winner(
            threshold=self._scoring.high_confidence_threshold,
            gap_required=self._scoring.high_confidence_min_gap,
        )

        cdn_capable = False
        waf_active = False
        if winner_name:
            winner_rule: WafVendorRule | None = next(
                (v for v in self._rules.waf_vendors if v.vendor == winner_name),
                None,
            )
            if winner_rule is not None:
                cdn_capable = winner_rule.cdn_capable
                waf_active = _is_waf_active(winner_rule, ctx)
            # If wafw00f corroborated, treat it as evidence the WAF is enforcing.
            if ctx.wafw00f_vendor == winner_name and not ctx.wafw00f_generic:
                waf_active = True

        return WafDetection(
            vendor=winner_name,
            confidence=confidence,
            signals_matched=winning_signals,
            waf_active=waf_active,
            cdn_capable=cdn_capable,
            runner_up=accumulator.runner_up(),
            gap=gap,
        )

    # ---------- CDN -------------------------------------------------------

    def evaluate_cdn(
        self,
        ctx: DetectionInput,
        waf_detection: WafDetection | None = None,
    ) -> CdnDetection:
        # Reuse a CDN-capable WAF result when present.
        if waf_detection and waf_detection.cdn_capable and waf_detection.vendor:
            return CdnDetection(
                vendor=waf_detection.vendor,
                confidence=waf_detection.confidence,
                signals_matched=list(waf_detection.signals_matched),
            )

        accumulator = HypothesisAccumulator()
        for vendor_rule in self._rules.cdn_only_vendors:
            matches = evaluate_rule_signals(
                vendor_rule.signals,
                ctx,
                self._scoring,
                source=vendor_rule.vendor,
            )
            for m in matches:
                accumulator.add_signal(vendor_rule.vendor, m)

        winner_name, confidence, _gap, winning_signals = accumulator.winner(
            threshold=self._scoring.high_confidence_threshold,
            gap_required=self._scoring.high_confidence_min_gap,
        )

        return CdnDetection(
            vendor=winner_name,
            confidence=confidence,
            signals_matched=winning_signals,
        )

    # ---------- Cloud -----------------------------------------------------

    def evaluate_cloud(
        self,
        ctx: DetectionInput,
        ip_range_match: IPRangeMatch | None = None,
    ) -> CloudDetection:
        # 1. IP range trie hit short-circuits the rest.
        if ip_range_match is not None:
            evidence = f"prefix={ip_range_match.prefix}"
            return CloudDetection(
                provider=ip_range_match.provider,
                confidence=Confidence.HIGH,
                source="ip_range",
                signals_matched=[
                    SignalMatch(
                        rule_kind="ip_range",
                        points=self._scoring.ip_range_match_points,
                        source=ip_range_match.provider,
                        evidence=evidence,
                    )
                ],
                role=_role_for_provider(self._rules, ip_range_match.provider),
                asn_org=ctx.asn_org,
            )

        accumulator = HypothesisAccumulator()
        sources: dict[str, str] = {}

        for provider_rule in self._rules.cloud_providers:
            for rdns in ctx.rdns_hostnames:
                rdns_l = rdns.lower().rstrip(".")
                if any(
                    fnmatch.fnmatchcase(rdns_l, pat.lower())
                    for pat in provider_rule.rdns_patterns
                ):
                    accumulator.add_signal(
                        provider_rule.provider,
                        SignalMatch(
                            rule_kind="rdns",
                            points=self._scoring.reverse_dns_points,
                            source=provider_rule.provider,
                            evidence=f"rdns:{rdns}",
                        ),
                    )
                    sources.setdefault(provider_rule.provider, "rdns")
                    break

            for cname in ctx.cnames:
                cnl = cname.lower()
                if any(
                    cnl.endswith(s.lower()) for s in provider_rule.cname_suffixes
                ):
                    accumulator.add_signal(
                        provider_rule.provider,
                        SignalMatch(
                            rule_kind="cname",
                            points=self._scoring.cname_match_points,
                            source=provider_rule.provider,
                            evidence=f"cname:{cname}",
                        ),
                    )
                    sources.setdefault(provider_rule.provider, "cname")
                    break

            if ctx.asn is not None and ctx.asn in provider_rule.asns:
                accumulator.add_signal(
                    provider_rule.provider,
                    SignalMatch(
                        rule_kind="asn",
                        points=self._scoring.asn_match_points,
                        source=provider_rule.provider,
                        evidence=f"asn:{ctx.asn}",
                    ),
                )
                sources.setdefault(provider_rule.provider, "asn")

            server = ctx.headers.get("server", "")
            for header_rule in provider_rule.server_headers:
                if _server_match(header_rule, server):
                    points = self._scoring.server_header_points
                    if header_rule.confidence_modifier is not None:
                        points = int(round(points * header_rule.confidence_modifier))
                    accumulator.add_signal(
                        provider_rule.provider,
                        SignalMatch(
                            rule_kind="banner",
                            points=points,
                            source=provider_rule.provider,
                            evidence=f"server:{server[:60]}",
                        ),
                    )
                    sources.setdefault(provider_rule.provider, "banner")

        # Cloud uses a per-source decision tree (v0.4 §14.2) rather than the
        # uniform threshold/gap rule: each signal kind carries its own
        # baseline confidence (rdns/cname=MEDIUM, asn/banner=LOW). Multiple
        # source kinds for the same provider upgrade the result to HIGH.
        winner_name, _gap, winning_signals = _pick_cloud_winner(accumulator)

        if winner_name is None:
            # Datacenter fallback: regional ISP / telco ASN orgs.
            datacenter_match = _datacenter_match(self._rules, ctx)
            if datacenter_match:
                return CloudDetection(
                    provider="datacenter",
                    confidence=Confidence.LOW,
                    source="datacenter",
                    signals_matched=[
                        SignalMatch(
                            rule_kind="datacenter",
                            points=0,
                            source="datacenter",
                            evidence=f"asn_org:{datacenter_match}",
                        )
                    ],
                    role="datacenter",
                    asn_org=ctx.asn_org,
                )

            return CloudDetection(
                provider=None,
                confidence=Confidence.LOW,
                source="unknown",
                signals_matched=[],
                role="hyperscaler",
                asn_org=ctx.asn_org,
            )

        primary_source = _primary_source_for(winning_signals)
        confidence = _confidence_for_cloud_signals(winning_signals)
        return CloudDetection(
            provider=winner_name,
            confidence=confidence,
            source=primary_source,
            signals_matched=winning_signals,
            role=_role_for_provider(self._rules, winner_name),
            asn_org=ctx.asn_org,
        )

    # ---------- Stack -----------------------------------------------------

    def evaluate_stack(self, ctx: DetectionInput) -> StackDetection:
        web_server = self._evaluate_web_server(ctx)

        cms_accumulator = HypothesisAccumulator()
        cms_signals_per_vendor: dict[str, list[SignalMatch]] = {}
        for cms_rule in self._rules.cms:
            matches = evaluate_rule_signals(
                cms_rule.signals, ctx, self._scoring, source=cms_rule.name
            )
            if matches:
                cms_signals_per_vendor[cms_rule.name] = matches
                for m in matches:
                    cms_accumulator.add_signal(cms_rule.name, m)

        # External tool corroboration: Wappalyzer + whatweb.
        for cms_name in _external_cms_hits(ctx):
            corrob = SignalMatch(
                rule_kind="external_tool",
                points=self._scoring.secondary_signal_points,
                source=cms_name,
                evidence="wappalyzer/whatweb cms",
            )
            cms_accumulator.add_signal(cms_name, corrob)
            cms_signals_per_vendor.setdefault(cms_name, []).append(corrob)

        cms_winner, _cms_conf, _gap, cms_winning_signals = cms_accumulator.winner(
            threshold=self._scoring.high_confidence_threshold,
            gap_required=self._scoring.high_confidence_min_gap,
        )

        cms_version: str | None = None
        if cms_winner:
            cms_version = self._extract_cms_version(cms_winner, ctx)

        # Frameworks accumulate independently — no exclusivity.
        frameworks: list[str] = []
        framework_signals: list[SignalMatch] = []
        for fw_rule in self._rules.frameworks:
            matches = evaluate_rule_signals(
                fw_rule.signals, ctx, self._scoring, source=fw_rule.name
            )
            if matches:
                total = sum(m.points for m in matches)
                if total >= self._scoring.high_confidence_threshold:
                    frameworks.append(fw_rule.name)
                    framework_signals.extend(matches)

        # Combine signals for telemetry (winner-only for CMS).
        all_signals: list[SignalMatch] = []
        if cms_winner and cms_winner in cms_signals_per_vendor:
            all_signals.extend(cms_winning_signals)
        all_signals.extend(framework_signals)

        return StackDetection(
            web_server=web_server,
            cms=cms_winner,
            cms_version=cms_version,
            frameworks=frameworks,
            signals_matched=all_signals,
        )

    def _evaluate_web_server(self, ctx: DetectionInput) -> str | None:
        banner = ctx.headers.get("server")
        if not banner:
            return None

        rules = self._rules.web_servers.get("banner_map", [])
        for rule in rules:
            assigned = _apply_banner_rule(rule, banner)
            if assigned is not None:
                return assigned if assigned != "-" else None
        return None

    def _extract_cms_version(
        self, cms_name: str, ctx: DetectionInput
    ) -> str | None:
        cms_rule = next(
            (c for c in self._rules.cms if c.name == cms_name and c.version_extract),
            None,
        )
        if cms_rule is None or cms_rule.version_extract is None:
            return None

        ext = cms_rule.version_extract
        try:
            pattern = re.compile(ext.regex)
        except re.error:
            return None

        if ext.from_ == "meta_generator":
            content = extract_meta_generator(ctx.body_snippet)
            if content is None:
                return None
            match = pattern.search(content)
            return match.group(1) if match and match.groups() else None

        if ext.from_ == "header" and ext.header_name:
            header_value = ctx.headers.get(ext.header_name.lower(), "")
            match = pattern.search(header_value)
            return match.group(1) if match and match.groups() else None

        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_CLOUD_SOURCE_RANK = {
    "ip_range": 4,
    "rdns": 3,
    "cname": 3,
    "asn": 2,
    "banner": 1,
}


def _pick_cloud_winner(
    accumulator: HypothesisAccumulator,
) -> tuple[str | None, int, list[SignalMatch]]:
    """Pick the provider with the highest aggregate cloud points.

    Cloud uses per-source confidence rather than the uniform threshold/gap
    rule: a single rdns or cname match is enough to assert a provider with
    MEDIUM confidence. The threshold/gap mechanism is only used for
    disambiguating between *competing* providers (e.g. an IP that hits both
    AWS and Cloudflare ASN tables).
    """

    if not accumulator._buckets:  # noqa: SLF001 — internal helper, same module
        return None, 0, []
    ranked = sorted(
        accumulator._buckets.values(),  # noqa: SLF001
        key=lambda h: h.points,
        reverse=True,
    )
    top = ranked[0]
    if top.points == 0:
        return None, 0, []
    runner = ranked[1] if len(ranked) > 1 else None
    gap = top.points - (runner.points if runner else 0)
    return top.name, gap, list(top.signals_matched)


def _primary_source_for(signals: list[SignalMatch]) -> str:
    """Return the strongest source kind seen for the winning provider."""

    best_rank = -1
    best_source = "unknown"
    for s in signals:
        rank = _CLOUD_SOURCE_RANK.get(s.rule_kind, 0)
        if rank > best_rank:
            best_rank = rank
            best_source = s.rule_kind
    return best_source


def _confidence_for_cloud_signals(signals: list[SignalMatch]) -> Confidence:
    """v0.4 §14.2 confidence ladder, with multi-source upgrade.

    - Any ip_range hit                                      → HIGH
    - Two or more distinct source kinds                     → HIGH
    - One ``rdns`` or ``cname`` match                       → MEDIUM
    - One ``asn`` or ``banner`` match                       → LOW
    """

    if not signals:
        return Confidence.LOW

    kinds = {s.rule_kind for s in signals}
    if "ip_range" in kinds:
        return Confidence.HIGH

    distinct_real_kinds = kinds & {"rdns", "cname", "asn", "banner"}
    if len(distinct_real_kinds) >= 2:
        return Confidence.HIGH

    if "rdns" in distinct_real_kinds or "cname" in distinct_real_kinds:
        return Confidence.MEDIUM

    return Confidence.LOW


def _is_waf_active(vendor_rule: object, ctx: DetectionInput) -> bool:
    indicators = getattr(vendor_rule, "waf_active_indicators", []) or []
    body = ctx.body_snippet
    for ind in indicators:
        challenge = getattr(ind, "challenge_page", None) or {}
        if isinstance(challenge, dict) and "regex" in challenge and body:
            try:
                if re.search(challenge["regex"], body):
                    return True
            except re.error:
                continue

        header = getattr(ind, "header", None) or {}
        if isinstance(header, dict) and header.get("present"):
            name = header.get("name", "").lower()
            if name and name in ctx.headers:
                return True

    if ctx.status in (403, 429):
        return True
    return False


def _role_for_provider(rules: DetectionRules, provider_name: str) -> str:
    for p in rules.cloud_providers:
        if p.provider == provider_name:
            return p.role
    return "hyperscaler"


def _server_match(rule: object, banner: str) -> bool:
    if not banner:
        return False
    regex_ci = getattr(rule, "regex_ci", None)
    if regex_ci:
        try:
            return bool(re.search(regex_ci, banner, re.IGNORECASE))
        except re.error:
            return False
    regex = getattr(rule, "regex", None)
    if regex:
        try:
            return bool(re.search(regex, banner))
        except re.error:
            return False
    equals_ci = getattr(rule, "equals_ci", None)
    if equals_ci:
        return banner.lower() == str(equals_ci).lower()
    equals = getattr(rule, "equals", None)
    if equals:
        return bool(banner == str(equals))
    return False


def _datacenter_match(rules: DetectionRules, ctx: DetectionInput) -> str | None:
    if not ctx.asn_org:
        return None
    org = ctx.asn_org.lower()
    for needle in rules.datacenter_fallback.asn_orgs_treated_as_datacenter:
        if needle.lower() in org:
            return needle
    return None


def _apply_banner_rule(rule: WebServerBannerRule, banner: str) -> str | None:
    """Return the assignment string when the rule matches, or None."""

    if rule.regex:
        try:
            pat = re.compile(rule.regex)
        except re.error:
            return None
        match = pat.search(banner)
        if match:
            return _expand_assignment(rule.assign, match)
    if rule.equals_ci:
        if banner.lower() == rule.equals_ci.lower():
            return rule.assign
    if rule.equals:
        if banner == rule.equals:
            return rule.assign
    return None


def _expand_assignment(template: str, match: re.Match[str]) -> str:
    """Replace ``$1``, ``$2`` ... in ``template`` with regex groups."""

    def _repl(m: re.Match[str]) -> str:
        idx = int(m.group(1))
        try:
            return match.group(idx) or ""
        except IndexError:
            return ""

    return re.sub(r"\$(\d+)", _repl, template)


def _external_cms_hits(ctx: DetectionInput) -> list[str]:
    """Cross-check Wappalyzer + whatweb for CMS hints."""

    found: list[str] = []
    cms_known = {
        "WordPress",
        "Drupal",
        "Joomla",
        "Magento",
        "Shopify",
        "Wix",
        "Squarespace",
        "Ghost",
        "Strapi",
        "Sitecore",
    }

    for cat_values in ctx.wappalyzer_techs.values():
        for v in cat_values:
            if v in cms_known and v not in found:
                found.append(v)

    for plugin_name in ctx.whatweb_plugins:
        if plugin_name in cms_known and plugin_name not in found:
            found.append(plugin_name)

    return found
