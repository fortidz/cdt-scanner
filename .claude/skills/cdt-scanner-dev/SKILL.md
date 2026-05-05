---
name: cdt-scanner-dev
description: Templates, idioms, and conventions for the CDT (Cloud Development Tool) project. Use this skill any time you implement code, tests, Dockerfiles, Terraform resources, or GitHub Actions workflows in `cdt-scanner` or `cdt-infra`. Provides drop-in templates for pyproject.toml, Dockerfile multi-stage Kali-based, Linode Terraform resource, scan.yml workflow, pydantic models, structlog setup, asyncio rate-limited pool, subprocess streaming wrapper (nikto pattern), tenacity retry, YAML config loading with pydantic validation, and CSV writing with proper quoting. Encodes the project decisions that should not be re-debated.
---

# cdt-scanner-dev

Skill propio del proyecto CDT. Concentra los patrones idiomáticos para que Claude Code no los reinvente cada vez. Léelo siempre antes de implementar código, tests o infra en `cdt-scanner` o `cdt-infra`.

Este skill está alineado con `docs/spec/spec-cdt-v0.4.md` y `docs/spec/spec-cdt-v0.5.md`. Si hay conflicto, los specs mandan.

---

## 1. Convenciones de proyecto

### 1.1 Naming

- **Módulos Python**: `snake_case`. Plural cuando agrupan: `tools/`, `detect/`, `scoring/`, `discovery/`.
- **Tests**: `test_<module>__<behavior>.py::test_<scenario>`. Doble underscore separa módulo y comportamiento.
- **Eventos structlog**: `snake_case_underscore`. Ejemplos: `discovery_validate_ok`, `discovery_validate_fail`, `nikto_triggered`, `nikto_early_term`, `nikto_skipped`, `account_started`, `account_finished`, `scan_finished`, `csv_written`.
- **Recursos Linode (Terraform)**: `linode_instance.<purpose>` (ej. `dev_cdt`, `ephemeral_cdt`).
- **Archivos YAML de config**: minúsculas con guión bajo (`detection_rules.yaml`, `nikto_skip.yaml`).

### 1.2 Estructura de imports

```python
# stdlib primero
import asyncio
import json
from pathlib import Path

# third-party
import httpx
import structlog
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

# local
from cdt.errors import ScannerError, E_NETWORK
from cdt.models import AccountIn, AccountEnriched
```

### 1.3 Reglas duras

- **Type hints siempre.** mypy strict mode.
- **pydantic v2** para models de IO. NO dataclasses planos. NO dicts crudos como contratos.
- **typer** para CLI. NO argparse, NO click.
- **structlog** para logs. NO `print()`. NO f-strings en eventos — usar kwargs.
- **httpx** para HTTP. NO requests, NO urllib.
- **asyncio-first** donde haya I/O concurrente.
- **tenacity** para retries con backoff exponencial.
- **respx** para mockear httpx en tests.

---

## 2. Templates embebidos

### 2.1 `Dockerfile` (multi-stage, Kali base, non-root, read-only FS)

```dockerfile
# syntax=docker/dockerfile:1.7

# === Stage 1: builder ===
FROM kalilinux/kali-rolling@sha256:REPLACE_WITH_CURRENT_DIGEST AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3.12 python3.12-venv python3-pip \
        build-essential libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml .
COPY src/ ./src/

# Crea venv aislado
RUN python3.12 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir .

# === Stage 2: runtime ===
FROM kalilinux/kali-rolling@sha256:REPLACE_WITH_CURRENT_DIGEST

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3.12 \
        whatweb \
        nikto \
        ca-certificates \
        dnsutils \
        curl && \
    apt-mark hold whatweb nikto && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Non-root user
RUN useradd -m -u 1000 -s /bin/bash cdt
USER cdt
WORKDIR /home/cdt

# Copia el venv del builder
COPY --from=builder --chown=cdt:cdt /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# El usuario montará /app/in y /app/out como volumes en runtime
RUN mkdir -p /app/in /app/out /app/cache

ENTRYPOINT ["python", "-m", "cdt"]
CMD ["--help"]
```

**Notas:**
- Pin del digest del base image (no el `:latest`). Actualizar via PR explícito.
- `apt-mark hold whatweb nikto` evita actualizaciones inesperadas de los binarios — testeamos contra versiones específicas.
- Volume mounts: `/app/in` (read-only), `/app/out` (writable), `/app/cache` (writable).
- Run con `--read-only --tmpfs /tmp` en producción.

### 2.2 `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "cdt"
version = "0.1.0"
description = "Cloud Development Tool — Site Discovery & Exposure Scanner"
readme = "README.md"
requires-python = ">=3.12,<3.13"
license = { text = "Proprietary" }
authors = [{ name = "Dave", email = "eiz311@gmail.com" }]

dependencies = [
    "typer~=0.12",
    "pydantic~=2.9",
    "httpx~=0.27",
    "dnspython~=2.7",
    "pytricia~=1.0",
    "python-Wappalyzer~=0.4",
    "wafw00f==2.3.1",
    "shodan~=1.31",
    "censys~=2.2",
    "rich~=13.0",
    "structlog~=24.0",
    "PyYAML~=6.0",
    "tenacity~=9.0",
]

[project.optional-dependencies]
dev = [
    "pytest~=8.0",
    "pytest-asyncio~=0.23",
    "pytest-cov~=5.0",
    "respx~=0.21",
    "freezegun~=1.5",
    "ruff~=0.5",
    "mypy~=1.11",
]

[project.scripts]
cdt = "cdt.cli:app"

[tool.setuptools.packages.find]
where = ["src"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "S", "C4", "ASYNC"]
ignore = ["S101"]  # pytest assertions

[tool.mypy]
python_version = "3.12"
strict = true
warn_unused_ignores = true
warn_return_any = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "--strict-markers --strict-config"
```

### 2.3 Terraform — `linode_instance` para dev-persistent

```hcl
# env/dev-persistent/main.tf

terraform {
  cloud {
    organization = "fortidz"
    workspaces { name = "cdt-dev-persistent" }
  }
}

module "base" {
  source     = "../../modules/linode-base"
  env        = "dev"
  ssh_pubkey = var.ssh_pubkey
  admin_ips  = var.admin_ips
}

resource "linode_stackscript" "dev_init" {
  label       = "cdt-dev-init"
  description = "Bootstraps dev VM: Docker + GH runner + hardening"
  images      = ["linode/kali"]
  rev_note    = "v1"
  is_public   = false
  script      = file("${path.module}/../../scripts/dev-init.sh")
}

resource "linode_instance" "dev_cdt" {
  label            = "cdt-dev-persistent"
  region           = var.region
  type             = "g6-standard-1"   # 2 GB RAM
  image            = "linode/kali"
  authorized_keys  = [trimspace(var.ssh_pubkey)]
  private_ip       = false
  tags             = ["cdt", "dev"]

  stackscript_id = linode_stackscript.dev_init.id
  stackscript_data = {
    gh_runner_token = var.gh_runner_token
    gh_repo_url     = "https://github.com/fortidz/cdt-scanner"
    gh_runner_label = "cdt-dev"
  }
}

resource "linode_firewall" "dev_fw" {
  label   = "cdt-dev-fw"
  tags    = ["cdt", "dev"]
  linodes = [linode_instance.dev_cdt.id]

  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

  inbound {
    label    = "ssh-from-admin"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = var.admin_ips
  }
}
```

```hcl
# env/dev-persistent/variables.tf

variable "linode_token" {
  description = "Linode API token. Comes from variable set."
  type        = string
  sensitive   = true
}

variable "ssh_pubkey" {
  description = "Public SSH key authorized on the VM."
  type        = string
}

variable "admin_ips" {
  description = "List of CIDRs allowed to SSH the dev VM."
  type        = list(string)
}

variable "region" {
  description = "Linode region."
  type        = string
  default     = "us-east"
}

variable "gh_runner_token" {
  description = "Token for self-hosted GH Actions runner registration."
  type        = string
  sensitive   = true
}
```

```hcl
# env/dev-persistent/outputs.tf

output "public_ip" {
  description = "Public IPv4 of the dev Linode."
  value       = linode_instance.dev_cdt.ip_address
}

output "instance_id" {
  description = "Linode instance ID for the dev VM."
  value       = linode_instance.dev_cdt.id
}
```

```hcl
# env/dev-persistent/versions.tf

terraform {
  required_version = "~> 1.9"
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.0"
    }
  }
}

provider "linode" {
  token = var.linode_token
}
```

### 2.4 GitHub Actions — `scan.yml` esqueleto

```yaml
# .github/workflows/scan.yml — repo cdt-scanner

name: Run CDT Scan

on:
  workflow_dispatch:
    inputs:
      phase:
        type: choice
        options: [dev, prod]
        default: prod
      tier:
        type: choice
        options: [passive, browser, dast]
        default: browser
      csv_content:
        description: "Pega aquí accounts_in.csv (vacío = usa inputs/recurring.csv del repo)"
        type: string
        required: false
      country_filter:
        description: "Filtrar por país (opcional)"
        type: string
        required: false
  schedule:
    - cron: '0 6 * * 1'    # lunes 06:00 UTC

permissions:
  contents: write    # para commit-back de outputs (v0.5 §3.6)

concurrency:
  group: cdt-scan-${{ github.event.inputs.phase }}
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ${{ inputs.phase == 'dev' && fromJSON('["self-hosted","linode","cdt-dev"]') || 'ubuntu-latest' }}
    timeout-minutes: 90

    steps:
      - name: Checkout cdt-scanner
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Resolve input CSV
        run: |
          set -euo pipefail
          mkdir -p ./in
          if [ -n "${{ inputs.csv_content }}" ]; then
            printf '%s' "${{ inputs.csv_content }}" > ./in/accounts_in.csv
          else
            cp inputs/recurring.csv ./in/accounts_in.csv
          fi
          head -1 ./in/accounts_in.csv | grep -q "Title,Country,Website" || {
            echo "::error::CSV sin encabezados esperados"; exit 3; }

      # === FASE DEV ===
      - name: '[DEV] Run scan on persistent Linode'
        if: ${{ inputs.phase == 'dev' }}
        env:
          BRAVE_SEARCH_API_KEY: ${{ secrets.BRAVE_SEARCH_API_KEY }}
        run: |
          docker pull ghcr.io/fortidz/cdt:dev
          docker run --rm \
            -v "$PWD/in:/app/in:ro" \
            -v "$PWD/out:/app/out" \
            -v "$PWD/cache:/app/cache" \
            -e BRAVE_SEARCH_API_KEY \
            --user 1000:1000 --read-only --tmpfs /tmp \
            ghcr.io/fortidz/cdt:dev \
            scan --in /app/in/accounts_in.csv --tier ${{ inputs.tier }} \
                 --country "${{ inputs.country_filter }}" --out /app/out/

      # === FASE PROD ===
      - name: '[PROD] Checkout cdt-infra'
        if: ${{ inputs.phase == 'prod' }}
        uses: actions/checkout@v4
        with:
          repository: fortidz/cdt-infra
          token: ${{ secrets.INFRA_TOKEN }}
          path: infra

      - name: '[PROD] Setup Terraform'
        if: ${{ inputs.phase == 'prod' }}
        uses: hashicorp/setup-terraform@v3
        with:
          cli_config_credentials_token: ${{ secrets.HCP_TF_TOKEN }}

      # ... apply, scan via SSH, destroy ...
      # (detalle en v0.4 §12.4)

      - name: Upload outputs as artifact
        if: ${{ always() }}
        uses: actions/upload-artifact@v4
        with:
          name: cdt-scan-${{ github.run_id }}
          path: ./out/
          retention-days: 30

      - name: Commit outputs to repo
        if: ${{ success() }}
        env:
          RUN_ID: ${{ github.run_id }}
        run: |
          set -euo pipefail
          DATE=$(date -u +%Y-%m-%d)
          DEST="outputs/${DATE}_${RUN_ID}"

          git config user.name  "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

          git fetch origin outputs:outputs 2>/dev/null || true
          if git rev-parse --verify outputs >/dev/null 2>&1; then
            git checkout outputs
          else
            git checkout --orphan outputs
            git rm -rf . 2>/dev/null || true
            cat > README.md <<'EOF'
          # CDT scan outputs
          Cada folder = una corrida. El operador descarga
          accounts_enriched.csv del folder más reciente y lo
          sube manualmente a SharePoint (spec v0.5 §3).
          EOF
            cat > .gitattributes <<'EOF'
          outputs/**/*.csv  linguist-generated=true
          EOF
            git add README.md .gitattributes
            git commit -m "init outputs branch"
          fi

          mkdir -p "${DEST}"
          cp ./out/accounts_enriched.csv ./out/sites.csv \
             ./out/findings.csv ./out/validation_issues.csv "${DEST}/"
          cat > "${DEST}/run-meta.json" <<EOF
          {"run_id":"${RUN_ID}","tier":"${{ inputs.tier }}","completed_at":"$(date -u +%FT%TZ)"}
          EOF
          git add "${DEST}"
          git commit -m "scan results: ${DATE} run ${RUN_ID}"
          git push origin outputs
```

### 2.5 Pydantic models — `src/cdt/models.py`

```python
"""Contratos de IO. Si una columna del CSV cambia, este archivo cambia
y los golden files se regeneran (con commit explícito)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl, field_validator


class Country(str, Enum):
    PE = "Perú"
    EC = "Ecuador"
    CL = "Chile"
    BO = "Bolivia"
    PY = "Paraguay"
    UY = "Uruguay"
    VE = "Venezuela"


class TierLevel(str, Enum):
    PASSIVE = "passive"
    BROWSER = "browser"
    DAST = "dast"


class AccountIn(BaseModel):
    """Una fila de accounts_in.csv."""

    title: str = Field(..., min_length=1, alias="Title")
    country: str = Field(..., min_length=1, alias="Country")
    website: str = Field(default="", alias="Website")
    skip_validation: bool = Field(default=False, alias="SkipValidation")

    model_config = {"populate_by_name": True, "str_strip_whitespace": True}

    @field_validator("country")
    @classmethod
    def warn_if_outside_scope(cls, v: str) -> str:
        # Aviso, no error — v0.4 §12.13
        if v not in {c.value for c in Country}:
            import structlog
            structlog.get_logger().warning(
                "country_outside_scope", country=v
            )
        return v


class WAFDecision(str, Enum):
    YES = "Yes"
    NO = "No"
    FURTHER = "Further investigation needed"


class Complexity(str, Enum):
    ONE = "One CSP"
    TWO = "Two CSP"
    THREE = "Three CSP"
    FOUR = "Four CSP"
    NA = "-"


class AccountEnriched(BaseModel):
    """Una fila de accounts_enriched.csv. Orden de columnas matters
    porque alimenta SharePoint Grid view paste (v0.4 §3.3)."""

    title: str = Field(..., alias="Title")
    country: str = Field(..., alias="Country")
    public_cloud: WAFDecision = Field(..., alias="PublicCloud")
    complexity: Complexity = Field(..., alias="Complexity")
    has_aws: bool = Field(..., alias="HasAWS")
    has_azure: bool = Field(..., alias="HasAzure")
    has_gcp: bool = Field(..., alias="HasGCP")
    has_oci: bool = Field(..., alias="HasOCI")
    primary_hyperscaler: str = Field(default="-", alias="PrimaryHyperScaler")
    website01: str = Field(default="-", alias="Website01")
    website02: str = Field(default="-", alias="Website02")
    website03: str = Field(default="-", alias="Website03")
    website04: str = Field(default="-", alias="Website04")
    website05: str = Field(default="-", alias="Website05")
    waf: WAFDecision = Field(..., alias="WAF")
    waf_vendor: str = Field(default="-", alias="WAFVendor")
    waf_tool: str = Field(default="", alias="WAFTool")
    cms_framework: str = Field(default="-", alias="CMSFramework")
    web_server: str = Field(default="-", alias="WebServer")
    cdn: str = Field(default="-", alias="CDN")
    risk_score: str = Field(..., alias="RiskScore")
    recommends_fortiappsec: bool = Field(..., alias="RecommendsFortiAppSec")
    recommends_fortiweb: bool = Field(..., alias="RecommendsFortiWeb")
    recommends_forticnapp: bool = Field(..., alias="RecommendsFortiCNAPP")
    opportunity_rationale: str = Field(default="", max_length=200, alias="OpportunityRationale")
    scanned_at: datetime = Field(..., alias="ScannedAt")

    model_config = {"populate_by_name": True}
```

### 2.6 Test template con `respx`

```python
# tests/unit/test_discovery__brave_validate.py
"""Tests del modo Validate del provider Brave Search."""

import pytest
import respx
from httpx import Response

from cdt.discovery.brave_search import BraveSearch
from cdt.models import AccountIn


@pytest.fixture
def brave_client() -> BraveSearch:
    return BraveSearch(api_key="test-key")


@respx.mock
async def test_validate__match_returns_confirmed(brave_client: BraveSearch) -> None:
    """Cuando Brave devuelve resultados, el website queda confirmado."""

    account = AccountIn(Title="TIPTI", Country="Ecuador", Website="tipti.market")

    respx.get("https://api.search.brave.com/res/v1/web/search").mock(
        return_value=Response(
            200,
            json={"web": {"results": [{"url": "https://www.tipti.market/about"}]}},
            headers={"X-RateLimit-Remaining": "1, 999"},
        )
    )

    result = await brave_client.validate(account)
    assert result.confirmed is True
    assert result.canonical_url == "https://tipti.market"


@respx.mock
async def test_validate__no_results_emits_mismatch(brave_client: BraveSearch) -> None:
    """0 resultados → flag POSSIBLE_MISMATCH."""

    account = AccountIn(Title="Empresa Falsa", Country="Ecuador", Website="empresafalsa.com")

    respx.get("https://api.search.brave.com/res/v1/web/search").mock(
        return_value=Response(200, json={"web": {"results": []}})
    )

    result = await brave_client.validate(account)
    assert result.confirmed is False
    assert result.issue == "POSSIBLE_MISMATCH"
```

---

## 3. Patterns idiomáticos

### 3.1 Subprocess streaming wrapper (canónico: nikto monitor)

```python
"""Cuando un subprocess produce output largo (nikto, whatweb verbose),
NO usar subprocess.run con capture_output. Stream line-by-line."""

import asyncio
import subprocess
import time
from collections.abc import Callable
from typing import Any

import structlog

log = structlog.get_logger()


def run_streamed(
    cmd: list[str],
    on_line: Callable[[str], dict[str, Any] | None],
    hard_time_cap_sec: int = 300,
    hard_req_cap: int = 400,
) -> dict[str, Any]:
    """Ejecuta cmd y procesa cada línea con `on_line`.

    `on_line` retorna None para continuar, o un dict para terminar
    el subprocess limpiamente con ese state.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    state: dict[str, Any] = {}
    req_count = 0
    start = time.monotonic()

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            elapsed = time.monotonic() - start
            if elapsed > hard_time_cap_sec:
                log.warning("subprocess_timeout", cmd=cmd[0], elapsed=elapsed)
                state["termination"] = "timeout"
                break

            updated = on_line(line)
            if updated is not None:
                state.update(updated)
                req_count = state.get("reqs_sent", req_count)
                if state.get("done"):
                    state["termination"] = "resolved"
                    break

            if req_count >= hard_req_cap:
                state["termination"] = "request_cap"
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    state.setdefault("termination", "completed")
    state["elapsed_sec"] = time.monotonic() - start
    return state
```

### 3.2 Asyncio rate-limited task pool

```python
"""Para escanear N cuentas en paralelo con rate limit por dominio."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


class RateLimitedPool:
    """Concurrencia global N + rate limit por key (e.g. dominio)."""

    def __init__(self, concurrency: int = 20, per_key_rps: float = 2.0) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._per_key_locks: dict[str, asyncio.Lock] = {}
        self._per_key_last: dict[str, float] = {}
        self._min_interval = 1.0 / per_key_rps

    async def run(
        self,
        items: list[T],
        worker: Callable[[T], Awaitable[R]],
        key_fn: Callable[[T], str],
    ) -> list[R]:
        async def _wrap(item: T) -> R:
            async with self._sem:
                key = key_fn(item)
                lock = self._per_key_locks.setdefault(key, asyncio.Lock())
                async with lock:
                    last = self._per_key_last.get(key, 0.0)
                    wait = max(0.0, last + self._min_interval - asyncio.get_running_loop().time())
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._per_key_last[key] = asyncio.get_running_loop().time()
                return await worker(item)

        return await asyncio.gather(*(_wrap(i) for i in items))
```

### 3.3 Retry con tenacity

```python
import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)
import structlog

log = structlog.get_logger()


@retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    before_sleep=before_sleep_log(log, "warning"),  # type: ignore[arg-type]
    reraise=True,
)
async def fetch_with_retry(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """3 intentos con backoff 1s, 2s, 4s. NO retrya HTTP errors (4xx/5xx) — eso es decisión de negocio."""
    return await client.get(url, timeout=15.0)
```

### 3.4 YAML config con validación pydantic

```python
"""NUNCA hacer `yaml.safe_load` y devolver un dict crudo.
Siempre cargar a un model pydantic — falla rápido si el YAML está mal."""

from pathlib import Path
import yaml
from pydantic import BaseModel, Field


class DiscoveryConfig(BaseModel):
    provider: str = "brave_search"
    api_key_env: str = "BRAVE_SEARCH_API_KEY"
    cache_ttl_hours: int = Field(default=168, gt=0)
    blacklisted_domains: list[str] = Field(default_factory=list)


class CdtConfig(BaseModel):
    discovery: DiscoveryConfig

    @classmethod
    def load(cls, path: Path) -> "CdtConfig":
        with path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return cls.model_validate(raw)
```

### 3.5 CSV writer (UTF-8 sin BOM, LF, RFC 4180 quoting)

```python
"""El contrato del CSV (v0.5 §3.10) es estricto. Power Automate parsea
asumiendo encoding UTF-8 sin BOM y newline LF."""

import csv
from collections.abc import Iterable
from pathlib import Path

from cdt.models import AccountEnriched

# Orden EXACTO según v0.4 §3.3. NO cambiar sin actualizar SP List schema.
ACCOUNTS_ENRICHED_HEADERS = [
    "Title", "Country", "PublicCloud", "Complexity",
    "HasAWS", "HasAzure", "HasGCP", "HasOCI",
    "PrimaryHyperScaler",
    "Website01", "Website02", "Website03", "Website04", "Website05",
    "WAF", "WAFVendor", "WAFTool",
    "CMSFramework", "WebServer", "CDN",
    "RiskScore",
    "RecommendsFortiAppSec", "RecommendsFortiWeb", "RecommendsFortiCNAPP",
    "OpportunityRationale", "ScannedAt",
]


def write_accounts_enriched(rows: Iterable[AccountEnriched], path: Path) -> int:
    """Escribe el CSV. Devuelve el número de filas escritas."""
    count = 0
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=ACCOUNTS_ENRICHED_HEADERS,
            quoting=csv.QUOTE_MINIMAL,    # cita sólo si necesario
            lineterminator="\n",          # LF, no CRLF
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row.model_dump(by_alias=True, mode="json"))
            count += 1
    return count
```

### 3.6 structlog setup

```python
# src/cdt/context.py
import logging
import os
import sys

import structlog


def configure_logging(log_level: str = "info", log_format: str = "console") -> None:
    """Configurar al inicio de main()."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level)

    # CI=true fuerza JSON
    if os.environ.get("CI") == "true":
        log_format = "json"

    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
```

### 3.7 typer command template

```python
# src/cdt/cli.py
import typer
from pathlib import Path
from typing import Annotated

from cdt.context import configure_logging

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)


@app.command()
def scan(
    in_: Annotated[Path, typer.Option("--in", help="Path to accounts_in.csv")],
    out: Annotated[Path, typer.Option("--out", help="Output directory")] = Path("./out/"),
    tier: Annotated[str, typer.Option(help="passive|browser|dast")] = "browser",
    concurrency: Annotated[int, typer.Option(help="Asyncio workers")] = 20,
    country: Annotated[str, typer.Option(help="Comma-separated country filter")] = "",
    log_level: Annotated[str, typer.Option(help="debug|info|warn|error")] = "info",
    log_format: Annotated[str, typer.Option(help="console|json")] = "console",
) -> None:
    """Run the full scanner pipeline."""
    configure_logging(log_level, log_format)
    # ... real implementation here
    raise NotImplementedError("Implemented in Fase 3+")
```

---

## 4. Cómo agregar una regla nueva al catálogo de detección

Un PR que agregue una regla nueva a `config/detection_rules.yaml` **DEBE** incluir tres artefactos. CI bloquea sin ellos:

1. **Fixture HTTP** — respuesta que dispara la regla, en `tests/fixtures/http/<categoria>/<vendor>_<scenario>.json`. Formato:
   ```json
   {
     "url": "https://example.com",
     "status": 200,
     "headers": {
       "server": "FortiWeb/6.4",
       "x-fw-debug": "1"
     },
     "body": "<html>...</html>",
     "cookies": []
   }
   ```

2. **Unit test** con dos casos: hit (positivo) y no-hit (negativo con respuesta cercana pero distinta).
   ```python
   # tests/unit/test_detect__waf_fortiweb.py
   def test_fortiweb__primary_signal_hits(http_fixture_loader):
       fixture = http_fixture_loader("waf/fortiweb_basic.json")
       result = detect_waf(fixture, rules=load_rules())
       assert result.vendor == "Fortinet_FortiWeb"
       assert result.confidence == "high"

   def test_fortiweb__missing_server_no_match(http_fixture_loader):
       fixture = http_fixture_loader("waf/fortiweb_basic.json")
       fixture["headers"].pop("server")
       result = detect_waf(fixture, rules=load_rules())
       assert result.vendor is None
   ```

3. **Golden file regenerado** si el cambio afecta el output de los CSVs. Commit explícito con justificación.

---

## 5. Decisiones ya tomadas (NO re-debatir)

1. **Scope geográfico de 7 países** — documentación, no enforcement (v0.4 §12.13).
2. **Nikto condicional** con early-termination en Tier 2 (v0.4 §14.5.2).
3. **Wappalyzer primario** para tech stack, BuiltWith opcional.
4. **IP efímera en Prod**, persistente en Dev (v0.4 §12).
5. **Sin dominio propio** para el scanner.
6. **SharePoint via commit-back + upload manual** (v0.5 §3) — no Graph API por restricción de tenant corporativo.
7. **Brave Search** como provider de discovery (override sobre v0.4 §4 — Google CSE deprecó "Search the entire web").
8. **Repo privado obligatorio** — outputs contienen Title/Country reales.
9. **HCP Terraform** como backend de state — no S3, no local.
10. **Linode** como cloud provider — no AWS, no GCP.

---

## 6. Don'ts

- ❌ NO hardcodear endpoints en código — leer de `config/*.yaml`.
- ❌ NO loguear `csv_content` completo, response bodies del target, ni cookies.
- ❌ NO usar `print()` — siempre `structlog`.
- ❌ NO llamar APIs externas sin cache + rate limit.
- ❌ NO commitear keys, tokens, secretos. Usar GH Secrets + env vars.
- ❌ NO commitear outputs reales en `main`. Usar rama `outputs` (v0.5 §3.5).
- ❌ NO instalar deps fuera de `pyproject.toml`. Pin obligatorio.
- ❌ NO commitear CSVs reales con Title/Country. Usar `inputs/recurring.csv.example` con datos sintéticos.
- ❌ NO usar `subprocess.run` con `capture_output` para output > 100 KB. Usar `run_streamed` (§3.1).
- ❌ NO devolver `dict` crudos como contratos públicos. Usar pydantic models.
- ❌ NO romper el orden de columnas de los CSVs sin actualizar SP List schema en simultáneo (v0.4 §20.3.9).
- ❌ NO mockear `pydantic` validation ni `detect/scoring.py` — son SUTs (subjects under test).
