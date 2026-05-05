"""Predicate evaluator tests — one per predicate kind + combinator cases."""

from __future__ import annotations

from cdt.detect.models import DetectionInput
from cdt.detect.rules import RuleSignal
from cdt.detect.signals import evaluate_signal


def _ctx(**kwargs: object) -> DetectionInput:
    return DetectionInput.model_validate({"url": "https://x.example", **kwargs})


def _signal(when: dict[str, object]) -> RuleSignal:
    return RuleSignal(kind="primary", when=when)


def test_header__equals_ci_matches() -> None:
    ctx = _ctx(headers={"server": "Cloudflare"})
    sig = _signal({"header": {"name": "server", "equals_ci": "cloudflare"}})
    assert evaluate_signal(sig, ctx) is not None


def test_header__regex_matches() -> None:
    ctx = _ctx(headers={"cf-ray": "abc-mia"})
    sig = _signal({"header": {"name": "cf-ray", "regex": "^[a-f0-9]+-[a-z]+$"}})
    assert evaluate_signal(sig, ctx) is not None


def test_header__regex_ci_matches() -> None:
    ctx = _ctx(headers={"server": "AKAMAIGHOST"})
    sig = _signal({"header": {"name": "server", "regex_ci": "^Akamai(GHost|NetStorage)"}})
    assert evaluate_signal(sig, ctx) is not None


def test_header__present_true() -> None:
    ctx = _ctx(headers={"x-amz-cf-id": "x"})
    sig = _signal({"header": {"name": "x-amz-cf-id", "present": True}})
    assert evaluate_signal(sig, ctx) is not None


def test_header__present_false_when_missing() -> None:
    ctx = _ctx(headers={})
    sig = _signal({"header": {"name": "x-amz-cf-id", "present": True}})
    assert evaluate_signal(sig, ctx) is None


def test_header__name_regex_matches() -> None:
    ctx = _ctx(headers={"x-akamai-transformed": "yes"})
    sig = _signal({"header": {"name_regex": "^x-akamai-"}})
    assert evaluate_signal(sig, ctx) is not None


def test_cookie__name_matches() -> None:
    ctx = _ctx(cookies=["FORTIWAFSID=abc; Path=/"])
    sig = _signal({"cookie": {"name": "FORTIWAFSID"}})
    assert evaluate_signal(sig, ctx) is not None


def test_cookie__name_in_matches() -> None:
    ctx = _ctx(cookies=["__cf_bm=abc"])
    sig = _signal({"cookie": {"name_in": ["__cfduid", "__cf_bm", "cf_clearance"]}})
    assert evaluate_signal(sig, ctx) is not None


def test_cookie__name_regex_matches() -> None:
    ctx = _ctx(cookies=["incap_ses_123_456=abc"])
    sig = _signal({"cookie": {"name_regex": "^(incap_ses_|visid_incap_)"}})
    assert evaluate_signal(sig, ctx) is not None


def test_cname__suffix_matches() -> None:
    ctx = _ctx(cnames=["d12345.cloudfront.net"])
    sig = _signal({"cname": {"suffix": ".cloudfront.net"}})
    assert evaluate_signal(sig, ctx) is not None


def test_cname__suffix_in_matches() -> None:
    ctx = _ctx(cnames=["edge.cloudflare.net"])
    sig = _signal({"cname": {"suffix_in": [".cloudflare.net", ".cloudflare.com"]}})
    assert evaluate_signal(sig, ctx) is not None


def test_body_contains__matches() -> None:
    ctx = _ctx(body_snippet="Welcome to our shop. static.wixstatic.com asset")
    sig = _signal({"body_contains": "static.wixstatic.com"})
    assert evaluate_signal(sig, ctx) is not None


def test_body_contains_any__matches() -> None:
    ctx = _ctx(body_snippet="Magento_Ui/")
    sig = _signal({"body_contains_any": ["Magento_Ui/", "/skin/frontend/"]})
    assert evaluate_signal(sig, ctx) is not None


def test_body_regex__matches() -> None:
    ctx = _ctx(body_snippet="Reference #18.abcdef.1234567.deadbeef something")
    sig = _signal({"body_regex": r"Reference #\d+\.[a-f0-9]+\.\d+\.[a-f0-9]+"})
    assert evaluate_signal(sig, ctx) is not None


def test_status_in__matches() -> None:
    ctx = _ctx(status=403)
    sig = _signal({"status_in": [403, 429]})
    assert evaluate_signal(sig, ctx) is not None


def test_body_path_present__matches() -> None:
    ctx = _ctx(body_snippet='<link href="/wp-content/themes/x.css">')
    sig = _signal({"body_path_present": "/wp-content/"})
    assert evaluate_signal(sig, ctx) is not None


def test_meta_generator_regex__matches() -> None:
    ctx = _ctx(body_snippet='<meta name="generator" content="WordPress 6.5.2">')
    sig = _signal({"meta_generator_regex": r"^WordPress\s+\d+\.\d+"})
    assert evaluate_signal(sig, ctx) is not None


def test_asn_in__matches() -> None:
    ctx = _ctx(asn=15169)
    sig = _signal({"asn_in": [15169]})
    assert evaluate_signal(sig, ctx) is not None


def test_combinator_all__all_pass() -> None:
    ctx = _ctx(headers={"server": "cloudflare", "cf-ray": "abc-MIA"})
    sig = _signal(
        {
            "all": [
                {"header": {"name": "server", "equals_ci": "cloudflare"}},
                {"header": {"name": "cf-ray", "regex": "^[a-z0-9]+-[A-Z]+$"}},
            ]
        }
    )
    assert evaluate_signal(sig, ctx) is not None


def test_combinator_all__one_fails() -> None:
    ctx = _ctx(headers={"server": "cloudflare"})  # cf-ray missing
    sig = _signal(
        {
            "all": [
                {"header": {"name": "server", "equals_ci": "cloudflare"}},
                {"header": {"name": "cf-ray", "regex": "^[a-z0-9]+-[A-Z]+$"}},
            ]
        }
    )
    assert evaluate_signal(sig, ctx) is None


def test_combinator_any__one_passes() -> None:
    ctx = _ctx(cookies=["__cf_bm=abc"])
    sig = _signal(
        {
            "any": [
                {"header": {"name": "cf-ray", "present": True}},
                {"cookie": {"name_in": ["__cf_bm", "cf_clearance"]}},
            ]
        }
    )
    assert evaluate_signal(sig, ctx) is not None


def test_combinator_any__none_pass() -> None:
    ctx = _ctx(cookies=[])
    sig = _signal(
        {
            "any": [
                {"header": {"name": "cf-ray", "present": True}},
                {"cookie": {"name_in": ["__cf_bm"]}},
            ]
        }
    )
    assert evaluate_signal(sig, ctx) is None
