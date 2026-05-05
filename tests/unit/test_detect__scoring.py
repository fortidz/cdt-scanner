"""HypothesisAccumulator + ScoringEngine tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cdt.detect import (
    Confidence,
    DetectionInput,
    DetectionRules,
    HypothesisAccumulator,
    ScoringEngine,
    SignalMatch,
)

RULES_PATH = Path(__file__).parent.parent.parent / "config" / "detection_rules.yaml"
FIXTURES = Path(__file__).parent.parent / "fixtures" / "http"


def _load_fixture(rel: str) -> DetectionInput:
    payload = json.loads((FIXTURES / rel).read_text(encoding="utf-8"))
    return DetectionInput.model_validate(
        {
            "url": payload["url"],
            "status": payload["status"],
            "headers": {k.lower(): v for k, v in payload["headers"].items()},
            "cookies": payload.get("cookies", []),
            "body_snippet": payload.get("body", ""),
            "cnames": payload.get("cnames", []),
            "asn": payload.get("asn"),
            "asn_org": payload.get("asn_org"),
            "rdns_hostnames": payload.get("rdns_hostnames", []),
        }
    )


@pytest.fixture(scope="module")
def rules() -> DetectionRules:
    return DetectionRules.load(RULES_PATH)


@pytest.fixture(scope="module")
def engine(rules: DetectionRules) -> ScoringEngine:
    return ScoringEngine(rules)


# ---------- HypothesisAccumulator ----------


def test_accumulator__add_and_winner_high() -> None:
    acc = HypothesisAccumulator()
    acc.add_signal(
        "A", SignalMatch(rule_kind="primary", points=10, source="A", evidence="x")
    )
    acc.add_signal(
        "A", SignalMatch(rule_kind="secondary", points=5, source="A", evidence="y")
    )
    acc.add_signal(
        "B", SignalMatch(rule_kind="primary", points=5, source="B", evidence="z")
    )

    name, conf, gap, _signals = acc.winner(threshold=10, gap_required=5)
    assert name == "A"
    assert conf == Confidence.HIGH
    assert gap == 10  # 15 - 5


def test_accumulator__threshold_not_met_returns_low() -> None:
    acc = HypothesisAccumulator()
    acc.add_signal(
        "A", SignalMatch(rule_kind="primary", points=5, source="A", evidence="x")
    )
    name, conf, _gap, _signals = acc.winner(threshold=10, gap_required=5)
    assert name is None
    assert conf == Confidence.LOW


def test_accumulator__threshold_met_but_gap_small_returns_medium() -> None:
    acc = HypothesisAccumulator()
    acc.add_signal(
        "A", SignalMatch(rule_kind="primary", points=10, source="A", evidence="x")
    )
    acc.add_signal(
        "B", SignalMatch(rule_kind="primary", points=8, source="B", evidence="y")
    )
    name, conf, gap, _signals = acc.winner(threshold=10, gap_required=5)
    assert name == "A"
    assert conf == Confidence.MEDIUM
    assert gap == 2


def test_accumulator__empty_returns_low() -> None:
    acc = HypothesisAccumulator()
    name, conf, gap, signals = acc.winner(threshold=10, gap_required=5)
    assert name is None
    assert conf == Confidence.LOW
    assert gap == 0
    assert signals == []


def test_accumulator__runner_up_returned() -> None:
    acc = HypothesisAccumulator()
    acc.add_signal(
        "A", SignalMatch(rule_kind="primary", points=20, source="A", evidence="x")
    )
    acc.add_signal(
        "B", SignalMatch(rule_kind="secondary", points=5, source="B", evidence="y")
    )
    assert acc.runner_up() == "B"


# ---------- ScoringEngine ----------


def test_engine_waf__cloudflare_fixture_high(engine: ScoringEngine) -> None:
    ctx = _load_fixture("waf/cloudflare_pro.json")
    result = engine.evaluate_waf(ctx)
    assert result.vendor == "Cloudflare"
    assert result.confidence == Confidence.HIGH


def test_engine_waf__no_signals_returns_low(engine: ScoringEngine) -> None:
    ctx = _load_fixture("waf/no_waf_clean.json")
    result = engine.evaluate_waf(ctx)
    assert result.vendor is None
    assert result.confidence == Confidence.LOW


def test_engine_cdn__capable_waf_propagates(engine: ScoringEngine) -> None:
    ctx = _load_fixture("waf/cloudflare_pro.json")
    waf = engine.evaluate_waf(ctx)
    cdn = engine.evaluate_cdn(ctx, waf_detection=waf)
    assert cdn.vendor == "Cloudflare"


def test_engine_cloud__rdns_aws(engine: ScoringEngine) -> None:
    ctx = _load_fixture("cloud/aws_ec2_rdns.json")
    cloud = engine.evaluate_cloud(ctx)
    assert cloud.provider == "AWS"
    assert cloud.source == "rdns"


def test_engine_stack__nginx_banner(engine: ScoringEngine) -> None:
    ctx = _load_fixture("waf/no_waf_clean.json")
    stack = engine.evaluate_stack(ctx)
    assert stack.web_server == "nginx/1.24.0"


def test_engine_stack__wordpress_meta_generator(engine: ScoringEngine) -> None:
    ctx = _load_fixture("stack/wordpress_with_meta.json")
    stack = engine.evaluate_stack(ctx)
    assert stack.cms == "WordPress"
    assert stack.cms_version == "6.5.2"
    assert stack.web_server == "nginx/1.27.1"


def test_engine_stack__django_framework(engine: ScoringEngine) -> None:
    ctx = _load_fixture("stack/django.json")
    stack = engine.evaluate_stack(ctx)
    assert "Django" in stack.frameworks
