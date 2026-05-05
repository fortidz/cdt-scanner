"""Predicate evaluator — pure functions over ``DetectionInput``.

Each YAML signal ``when`` is one of:

  - ``{header: {name, equals_ci?, equals?, regex?, regex_ci?, present?, name_regex?}}``
  - ``{cookie: {name?, name_in?, name_regex?}}``
  - ``{cname: {suffix?, suffix_in?}}``
  - ``{body_contains: "..."}`` / ``body_contains_any: [...]``
  - ``{body_regex: "..."}`` / ``body_regex_any: [...]``
  - ``{body_path_present: "..."}`` / ``body_path_present_any: [...]``
  - ``{meta_generator_regex: "..."}``
  - ``{status_in: [...]}``
  - ``{asn_in: [...]}``
  - ``{all: [<sub-signals>]}`` — AND combinator
  - ``{any: [<sub-signals>]}`` — OR combinator

We deliberately implement each kind with explicit branches (no ``eval`` /
``exec``) — the predicate language is small and the security cost of a code
sandbox is too high.
"""

from __future__ import annotations

import re
from typing import Any

from cdt.detect.models import DetectionInput, SignalMatch
from cdt.detect.rules import RuleSignal, ScoringConfig

_META_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def evaluate_signal(
    signal: RuleSignal, ctx: DetectionInput, *, source: str = "?"
) -> SignalMatch | None:
    """Apply the ``when`` predicate to ``ctx``. Return a match on hit, else None."""

    matched, evidence = _match(signal.when, ctx)
    if not matched:
        return None
    return SignalMatch(
        rule_kind=signal.kind or "match",
        points=0,  # caller assigns; this fn doesn't know the scoring table
        source=source,
        evidence=evidence or "matched",
    )


def evaluate_rule_signals(
    signals: list[RuleSignal],
    ctx: DetectionInput,
    scoring: ScoringConfig,
    *,
    source: str = "?",
) -> list[SignalMatch]:
    """Iterate ``signals``, apply each, return matches with point assignments."""

    out: list[SignalMatch] = []
    for sig in signals:
        result = evaluate_signal(sig, ctx, source=source)
        if result is None:
            continue
        result.points = _points_for(sig.kind, scoring)
        if sig.confidence_modifier is not None:
            result.points = int(round(result.points * sig.confidence_modifier))
        out.append(result)
    return out


def _points_for(kind: str | None, scoring: ScoringConfig) -> int:
    if kind == "primary":
        return scoring.primary_signal_points
    if kind == "secondary":
        return scoring.secondary_signal_points
    if kind == "block_page":
        return scoring.block_page_points
    # Fallback for "kindless" signals (CDN-only / framework rules) — treat them
    # as primary so they can clear the threshold on their own.
    return scoring.primary_signal_points


# ---------------------------------------------------------------------------
# Predicate dispatch
# ---------------------------------------------------------------------------


def _match(predicate: dict[str, Any], ctx: DetectionInput) -> tuple[bool, str]:
    """Return ``(matched, evidence)`` for a single predicate dict.

    A predicate can carry multiple top-level keys (e.g. ``{body_contains: ...,
    status_in: [...]}``); ALL must match. This is the implicit-AND form. Use
    ``{all: [...]}`` / ``{any: [...]}`` for explicit combinators.
    """

    if not predicate:
        return False, ""

    # Combinators short-circuit.
    if "all" in predicate:
        clauses = predicate["all"]
        if not isinstance(clauses, list):
            return False, ""
        evidences: list[str] = []
        for c in clauses:
            ok, ev = _match(c, ctx)
            if not ok:
                return False, ""
            if ev:
                evidences.append(ev)
        return True, "; ".join(evidences) or "all"

    if "any" in predicate:
        clauses = predicate["any"]
        if not isinstance(clauses, list):
            return False, ""
        for c in clauses:
            ok, ev = _match(c, ctx)
            if ok:
                return True, ev or "any"
        return False, ""

    # Single-kind predicates. Evaluate every key — implicit AND.
    matches: list[str] = []
    for kind, payload in predicate.items():
        ok, ev = _match_kind(kind, payload, ctx)
        if not ok:
            return False, ""
        if ev:
            matches.append(ev)
    return True, "; ".join(matches) or "match"


def _match_kind(kind: str, payload: Any, ctx: DetectionInput) -> tuple[bool, str]:
    if kind == "header":
        return _match_header(payload, ctx)
    if kind == "cookie":
        return _match_cookie(payload, ctx)
    if kind == "cname":
        return _match_cname(payload, ctx)
    if kind == "body_contains":
        return _body_contains(ctx, [str(payload)])
    if kind == "body_contains_any":
        return _body_contains(ctx, _as_str_list(payload))
    if kind == "body_regex":
        return _body_regex(ctx, [str(payload)])
    if kind == "body_regex_any":
        return _body_regex(ctx, _as_str_list(payload))
    if kind == "body_path_present":
        return _body_contains(ctx, [str(payload)])
    if kind == "body_path_present_any":
        return _body_contains(ctx, _as_str_list(payload))
    if kind == "meta_generator_regex":
        return _meta_generator_regex(ctx, str(payload))
    if kind == "status_in":
        codes = payload if isinstance(payload, list) else [payload]
        return (ctx.status in codes), f"status={ctx.status}"
    if kind == "asn_in":
        asns = payload if isinstance(payload, list) else [payload]
        return (ctx.asn in asns), f"asn={ctx.asn}"
    return False, ""


def _match_header(payload: Any, ctx: DetectionInput) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, ""

    name_regex = payload.get("name_regex")
    if name_regex:
        try:
            pat = re.compile(name_regex, re.IGNORECASE)
        except re.error:
            return False, ""
        for hname, hval in ctx.headers.items():
            if pat.search(hname):
                return True, f"header:{hname}={hval[:60]}"
        return False, ""

    name = payload.get("name")
    if not isinstance(name, str):
        return False, ""

    actual = ctx.headers.get(name.lower())
    if actual is None:
        return False, ""

    if payload.get("present") is True:
        return True, f"header:{name} present"
    if "equals_ci" in payload:
        target = payload["equals_ci"]
        return (actual.lower() == str(target).lower()), f"header:{name}={actual[:60]}"
    if "equals" in payload:
        target = payload["equals"]
        return (actual == target), f"header:{name}={actual[:60]}"
    if "regex_ci" in payload:
        try:
            pat = re.compile(payload["regex_ci"], re.IGNORECASE)
        except re.error:
            return False, ""
        return bool(pat.search(actual)), f"header:{name}~={actual[:60]}"
    if "regex" in payload:
        try:
            pat = re.compile(payload["regex"])
        except re.error:
            return False, ""
        return bool(pat.search(actual)), f"header:{name}~={actual[:60]}"

    # No constraint beyond "name" — treat as ``present: true``.
    return True, f"header:{name} present"


def _match_cookie(payload: Any, ctx: DetectionInput) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, ""

    cookie_names = ctx.cookie_names()

    if "name" in payload:
        target = str(payload["name"])
        for cn in cookie_names:
            if cn == target:
                return True, f"cookie:{cn}"
        return False, ""

    if "name_in" in payload:
        accepted = _as_str_list(payload["name_in"])
        for cn in cookie_names:
            if cn in accepted:
                return True, f"cookie:{cn}"
        return False, ""

    if "name_regex" in payload:
        try:
            pat = re.compile(payload["name_regex"])
        except re.error:
            return False, ""
        for cn in cookie_names:
            if pat.search(cn):
                return True, f"cookie:{cn}"
        return False, ""

    return False, ""


def _match_cname(payload: Any, ctx: DetectionInput) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, ""

    if "suffix" in payload:
        suffix = str(payload["suffix"]).lower()
        for cn in ctx.cnames:
            if cn.lower().endswith(suffix):
                return True, f"cname:{cn}"
        return False, ""

    if "suffix_in" in payload:
        suffixes = [s.lower() for s in _as_str_list(payload["suffix_in"])]
        for cn in ctx.cnames:
            cnl = cn.lower()
            if any(cnl.endswith(s) for s in suffixes):
                return True, f"cname:{cn}"
        return False, ""

    return False, ""


def _body_contains(ctx: DetectionInput, needles: list[str]) -> tuple[bool, str]:
    if not ctx.body_snippet:
        return False, ""
    for needle in needles:
        if needle and needle in ctx.body_snippet:
            return True, f"body~='{needle[:60]}'"
    return False, ""


def _body_regex(ctx: DetectionInput, patterns: list[str]) -> tuple[bool, str]:
    if not ctx.body_snippet:
        return False, ""
    for raw in patterns:
        try:
            pat = re.compile(raw)
        except re.error:
            continue
        if pat.search(ctx.body_snippet):
            return True, f"body~/{raw[:60]}/"
    return False, ""


def _meta_generator_regex(ctx: DetectionInput, pattern: str) -> tuple[bool, str]:
    if not ctx.body_snippet:
        return False, ""
    match = _META_GENERATOR_RE.search(ctx.body_snippet)
    if match is None:
        return False, ""
    content = match.group(1)
    try:
        pat = re.compile(pattern)
    except re.error:
        return False, ""
    if pat.search(content):
        return True, f"meta_generator='{content[:60]}'"
    return False, ""


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None]


def extract_meta_generator(body: str) -> str | None:
    """Return the raw ``content`` of a ``<meta name=generator>`` tag, if any."""

    if not body:
        return None
    match = _META_GENERATOR_RE.search(body)
    if match is None:
        return None
    return match.group(1)
