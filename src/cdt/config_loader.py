"""Top-level config loader (``config/cdt.yaml``) per v0.5 §2.10.

The loader composes references to the per-domain YAMLs (discovery, scan,
detection, rationale) without inlining them — each subpackage parses its
own file independently. This keeps schema migrations local.

Env-var overrides (``CDT_LOG_LEVEL``, ``CDT_LOG_FORMAT``, ``CDT_CACHE_DIR``,
``CDT_USER_AGENT``) are applied after YAML load so the runbook's "set env
to override" pattern works.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cdt.errors import ConfigError, InputError

_DEFAULT_CONFIG_PATH = Path("./config/cdt.yaml")


class DefaultsConfig(BaseModel):
    tier: str = "browser"
    concurrency: int = 20
    cache_dir: str = "~/.cache/cdt"
    log_level: str = "info"
    log_format: str = "console"
    max_sites_per_account: int = 5
    user_agent: str = "CDT-Scanner/0.1 (+https://github.com/fortidz/cdt-scanner)"

    model_config = ConfigDict(extra="ignore")


class DiscoveryRefConfig(BaseModel):
    provider: str = "brave_search"
    api_key_env: str = "BRAVE_SEARCH_API_KEY"
    endpoint: str = "https://api.search.brave.com/res/v1/web/search"
    cache_ttl_hours: int = 168
    blacklisted_domains: list[str] = Field(default_factory=list)
    config_file: str = "config/discovery.yaml"

    model_config = ConfigDict(extra="ignore")


class DetectionRefsConfig(BaseModel):
    rules_file: str = "config/detection_rules.yaml"
    nikto_skip_file: str = "config/nikto_skip.yaml"
    rationale_templates_file: str = "config/rationale_templates.yaml"

    model_config = ConfigDict(extra="ignore")


class ScanRefConfig(BaseModel):
    config_file: str = "config/scan.yaml"

    model_config = ConfigDict(extra="ignore")


class CdtConfig(BaseModel):
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    discovery: DiscoveryRefConfig = Field(default_factory=DiscoveryRefConfig)
    detection: DetectionRefsConfig = Field(default_factory=DetectionRefsConfig)
    scan: ScanRefConfig = Field(default_factory=ScanRefConfig)

    model_config = ConfigDict(extra="ignore")

    @classmethod
    def load(cls, path: Path | None = None) -> CdtConfig:
        target = path or _DEFAULT_CONFIG_PATH
        if not target.exists():
            return cls()  # all defaults

        try:
            with target.open(encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except OSError as exc:
            raise ConfigError(f"Cannot read {target}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {target}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ConfigError(f"Top-level YAML must be a mapping in {target}")

        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"Config failed validation: {exc}") from exc

    def merge_env_overrides(self) -> CdtConfig:
        defaults = self.defaults.model_copy()

        if v := os.environ.get("CDT_LOG_LEVEL"):
            defaults.log_level = v
        if v := os.environ.get("CDT_LOG_FORMAT"):
            defaults.log_format = v
        if v := os.environ.get("CDT_CACHE_DIR"):
            defaults.cache_dir = v
        if v := os.environ.get("CDT_USER_AGENT"):
            defaults.user_agent = v

        return self.model_copy(update={"defaults": defaults})

    def cache_dir_path(self) -> Path:
        return Path(os.path.expanduser(self.defaults.cache_dir))


def require_brave_key() -> str:
    """Look up ``BRAVE_SEARCH_API_KEY`` or raise ConfigError (E04)."""

    key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
    if not key:
        raise ConfigError(
            "BRAVE_SEARCH_API_KEY is required for Validate / Discover modes. "
            "Set the env var or pass --skip-validation."
        )
    return key


# Re-export for callers that want a tidy import surface.
__all__ = [
    "CdtConfig",
    "ConfigError",
    "DefaultsConfig",
    "DetectionRefsConfig",
    "DiscoveryRefConfig",
    "InputError",
    "ScanRefConfig",
    "require_brave_key",
]
