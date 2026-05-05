"""Tech stack detector — banner + CMS + frameworks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cdt.detect import DetectionInput, DetectionRules, StackDetector

RULES_PATH = Path(__file__).parent.parent.parent / "config" / "detection_rules.yaml"
STACK_FIXTURES = Path(__file__).parent.parent / "fixtures" / "http" / "stack"
WAF_FIXTURES = Path(__file__).parent.parent / "fixtures" / "http" / "waf"


def _load(path: Path) -> DetectionInput:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return DetectionInput.model_validate(
        {
            "url": payload["url"],
            "status": payload["status"],
            "headers": {k.lower(): v for k, v in payload["headers"].items()},
            "cookies": payload.get("cookies", []),
            "body_snippet": payload.get("body", ""),
            "cnames": payload.get("cnames", []),
        }
    )


@pytest.fixture(scope="module")
def detector() -> StackDetector:
    return StackDetector(DetectionRules.load(RULES_PATH))


def test_stack__nginx_banner_assigned(detector: StackDetector) -> None:
    ctx = _load(WAF_FIXTURES / "no_waf_clean.json")
    result = detector.detect(ctx)
    assert result.web_server == "nginx/1.24.0"


def test_stack__apache_with_version(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "drupal_x_generator.json")
    result = detector.detect(ctx)
    assert result.web_server == "Apache/2.4.57"


def test_stack__wordpress_meta_generator(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "wordpress_with_meta.json")
    result = detector.detect(ctx)
    assert result.cms == "WordPress"
    assert result.cms_version == "6.5.2"


def test_stack__drupal_x_generator_header(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "drupal_x_generator.json")
    result = detector.detect(ctx)
    assert result.cms == "Drupal"
    assert result.cms_version == "10"


def test_stack__joomla_meta_generator(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "joomla.json")
    result = detector.detect(ctx)
    assert result.cms == "Joomla"


def test_stack__django_csrftoken_cookie_framework(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "django.json")
    result = detector.detect(ctx)
    assert "Django" in result.frameworks


def test_stack__rails_session_cookie_framework(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "rails.json")
    result = detector.detect(ctx)
    assert "Rails" in result.frameworks


def test_stack__multiple_frameworks_aggregated(detector: StackDetector) -> None:
    """A site with both Express + ASP.NET-shaped headers reports both."""

    ctx = DetectionInput(
        url="https://x.example",
        status=200,
        headers={"x-powered-by": "Express"},
        cookies=["ASP.NET_SessionId=abc; Path=/"],
    )
    result = detector.detect(ctx)
    assert "Express" in result.frameworks
    assert "ASP.NET" in result.frameworks


def test_stack__no_match_returns_dash(detector: StackDetector) -> None:
    ctx = DetectionInput(url="https://x.example", status=200, headers={})
    result = detector.detect(ctx)
    assert result.web_server is None
    assert result.cms is None
    assert result.frameworks == []


def test_stack__nextjs_framework(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "nextjs.json")
    result = detector.detect(ctx)
    assert "Next.js" in result.frameworks


def test_stack__nuxt_framework(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "nuxt.json")
    result = detector.detect(ctx)
    assert "Nuxt" in result.frameworks


def test_stack__laravel_framework(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "laravel.json")
    result = detector.detect(ctx)
    assert "Laravel" in result.frameworks


def test_stack__shopify_cms(detector: StackDetector) -> None:
    ctx = _load(STACK_FIXTURES / "shopify.json")
    result = detector.detect(ctx)
    assert result.cms == "Shopify"
