"""Tests for the rule pack loader (config/detection_rules.yaml)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cdt.detect import DetectionRules
from cdt.errors import InputError

REAL_RULES = Path(__file__).parent.parent.parent / "config" / "detection_rules.yaml"


@pytest.fixture
def rules() -> DetectionRules:
    return DetectionRules.load(REAL_RULES)


def test_rules__load_real_yaml_validates(rules: DetectionRules) -> None:
    assert rules.version == "1.0.0"
    assert rules.scoring.primary_signal_points == 10


def test_rules__missing_required_field_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    # ``version`` is required at the top level.
    bad.write_text("scoring: {}\n", encoding="utf-8")

    with pytest.raises(InputError):
        DetectionRules.load(bad)


def test_rules__engine_version_compatible_returns_true(
    rules: DetectionRules,
) -> None:
    assert rules.engine_version_compatible("0.5.0") is True
    assert rules.engine_version_compatible("0.5.1") is True
    assert rules.engine_version_compatible("1.0.0") is True


def test_rules__engine_version_incompatible_returns_false(
    rules: DetectionRules,
) -> None:
    assert rules.engine_version_compatible("0.4.0") is False
    assert rules.engine_version_compatible("0.0.1") is False


def test_rules__waf_vendors_count_matches_spec(rules: DetectionRules) -> None:
    """v0.5 §5.3 ships exactly 13 WAF vendors."""
    assert len(rules.waf_vendors) == 13
    names = [v.vendor for v in rules.waf_vendors]
    for expected in (
        "Cloudflare",
        "AWS_CloudFront_WAF",
        "Azure_FrontDoor_WAF",
        "Akamai",
        "Fortinet_FortiWeb",
        "Fortinet_FortiGate",
        "Imperva",
        "F5_BIGIP_ASM",
        "Sucuri",
        "Barracuda",
        "Citrix_NetScaler",
        "StackPath",
        "Wallarm",
    ):
        assert expected in names


def test_rules__cdn_vendors_count_matches_spec(rules: DetectionRules) -> None:
    assert len(rules.cdn_only_vendors) == 5
    names = [v.vendor for v in rules.cdn_only_vendors]
    assert {"Fastly", "KeyCDN", "BunnyCDN", "CDN77", "Google_Cloud_CDN"}.issubset(names)


def test_rules__cms_count_matches_spec(rules: DetectionRules) -> None:
    assert len(rules.cms) == 10


def test_rules__frameworks_count_matches_spec(rules: DetectionRules) -> None:
    assert len(rules.frameworks) == 7


def test_rules__cloud_providers_count(rules: DetectionRules) -> None:
    """9 cloud providers + datacenter fallback (separate field)."""
    assert len(rules.cloud_providers) == 9
    assert len(rules.datacenter_fallback.asn_orgs_treated_as_datacenter) >= 7


def test_rules__web_servers_banner_map_has_entries(rules: DetectionRules) -> None:
    banner_map = rules.web_servers.get("banner_map", [])
    assert len(banner_map) >= 7


def test_rules__bad_yaml_raises_input_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid yaml: !!!", encoding="utf-8")

    with pytest.raises(InputError):
        DetectionRules.load(bad)
