"""Orchestrator helper-level unit tests (decide_mode, filters, builders)."""

from __future__ import annotations

from cdt.models import AccountIn
from cdt.orchestrator import (
    ScanOptions,
    _apply_country_filter,
    _build_detection_input,
    _decide_mode,
    _is_authorized,
)


def _account(title: str = "Acme", country: str = "Ecuador",
             website: str = "acme.example", skip: bool = False) -> AccountIn:
    return AccountIn(
        Title=title, Country=country, Website=website, SkipValidation=skip
    )


# ---------- decide_mode ----------


def test_decide_mode__website_present_returns_validate() -> None:
    options = ScanOptions(tier="browser")
    assert _decide_mode(_account(), options) == "validate"


def test_decide_mode__website_empty_returns_discover() -> None:
    options = ScanOptions(tier="browser")
    assert _decide_mode(_account(website=""), options) == "discover"


def test_decide_mode__skip_validation_returns_scan_only() -> None:
    options = ScanOptions(tier="browser")
    assert _decide_mode(_account(skip=True), options) == "scan_only"


def test_decide_mode__global_skip_validation_overrides() -> None:
    options = ScanOptions(tier="browser", skip_validation=True)
    assert _decide_mode(_account(), options) == "scan_only"


# ---------- country filter ----------


def test_country_filter_applied_pre_dispatch() -> None:
    accounts = [
        _account(country="Ecuador"),
        _account(country="Perú"),
        _account(country="Chile"),
    ]
    filtered = _apply_country_filter(accounts, ["Ecuador", "Chile"])
    assert {a.country for a in filtered} == {"Ecuador", "Chile"}


def test_country_filter_empty_returns_all() -> None:
    accounts = [_account(country="Ecuador"), _account(country="Perú")]
    assert _apply_country_filter(accounts, []) == accounts


# ---------- DAST authorization ----------


def test_dast_authorized_lookup() -> None:
    options = ScanOptions(tier="dast", authorized_keys={("Acme", "Ecuador")})
    assert _is_authorized(_account("Acme", "Ecuador"), options) is True
    assert _is_authorized(_account("Beta", "Ecuador"), options) is False


# ---------- DetectionInput builder ----------


def test_build_detection_input__copies_scan_data() -> None:
    scan_data: dict = {
        "url": "https://acme.example/",
        "status": 200,
        "headers": {"Server": "nginx", "X-Test": "1"},
        "cookies": ["cf_clearance=abc"],
        "body_snippet": "<html></html>",
        "cnames": ["edge.cdn"],
        "ip_addresses": ["1.2.3.4"],
        "asn": 13335,
        "asn_org": "Cloudflare",
        "rdns_hostnames": ["1-2-3-4.cloudflare.com"],
        "wafw00f_vendor": "Cloudflare",
        "wafw00f_generic": False,
        "whatweb_plugins": {"WordPress": ["6.5"]},
        "wappalyzer_techs": {"cms": ["WordPress"]},
        "shodan_cpes": ["cpe:/a:nginx"],
        "shodan_ports": [443, 80],
    }
    di = _build_detection_input("https://acme.example/", scan_data)
    assert di.url == "https://acme.example/"
    assert di.headers == {"server": "nginx", "x-test": "1"}  # lower-cased keys
    assert di.asn == 13335
    assert di.wafw00f_vendor == "Cloudflare"
    assert "WordPress" in di.whatweb_plugins
