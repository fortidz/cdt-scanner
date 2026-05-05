# CLAUDE.md — cdt-scanner

Contexto permanente para sesiones de Claude Code en este repo.
Actualizar cuando cambien decisiones del spec o convenciones del código.

---

## Qué es CDT

CDT (Cloud Development Tool) es un scanner de descubrimiento y exposición de
sitios web orientado a oportunidades de Fortinet AppSec en LATAM. Toma un CSV
de cuentas (`Title, Country, Website`), valida/descubre dominios, escanea con
herramientas de Kali (whatweb, wafw00f, nikto), atribuye cloud provider, detecta
WAFs/CDNs, calcula `RiskScore /15` y emite tres booleanos de recomendación
Fortinet (`RecommendsFortiAppSec`, `RecommendsFortiWeb`, `RecommendsFortiCNAPP`).

**Scope geográfico**: 7 países (Perú, Ecuador, Chile, Bolivia, Paraguay, Uruguay,
Venezuela). El tool acepta otros países pero usar fuera del scope es
responsabilidad del operador (v0.4 §12.13).

**Dos repos**:

- `cdt-scanner` (este) — código Python, Dockerfile, config YAML, tests, catálogo de detección.
- `cdt-infra` — Terraform para los dos workspaces (dev-persistent + ephemeral).

---

## Specs autoritativos

- `docs/spec/spec-cdt-v0.4.md` — spec base consolidado.
- `docs/spec/spec-cdt-v0.5.md` — delta sobre v0.4 (cierra CLI, pipeline post-MVP, detection rule pack).

Si hay conflicto entre v0.4 y v0.5, **v0.5 manda**. Si v0.5 no menciona un tema,
v0.4 sigue vigente.

Ambos specs deben citarse explícitamente en commits/PRs cuando se implemente
algo (e.g. `Implements v0.4 §4.2 (Validate mode) + v0.5 §2.4 (CLI scan flags)`).

---

## Search provider — IMPORTANTE (override sobre v0.4 §4)

El spec v0.4 §4 usa **Google CSE** como provider de búsqueda. **Eso cambió post-spec**
porque Google deprecó la opción "Search the entire web" en Programmable Search
Engines nuevos, dejando inviables los modos Validate y Discover.

**Provider actual**: Brave Search API (free tier — $5/mes en créditos = ~1 000 req/mes).

- Endpoint: `https://api.search.brave.com/res/v1/web/search`
- Auth header: `X-Subscription-Token: <BRAVE_SEARCH_API_KEY>`
- Env var: `BRAVE_SEARCH_API_KEY`
- Rate limit: 1 req/s (free), Brave reporta `X-RateLimit-*` headers.
- La semántica del operador `site:<apex>` es idéntica a Google.

Cuando implementes `src/cdt/discovery/`, usa Brave en lugar de Google CSE. En
`config/discovery.yaml` poner `provider: brave_search`. El módulo se llama
`discovery/brave_search.py` (no `google_cse.py`).

Esto va a una nota de patch para v0.5.1 — por ahora trátalo como override sobre v0.4 §4.

---

## Stack y pinning (v0.4 §17.4)

| Componente | Versión | Pin strategy |
|---|---|---|
| Python | 3.12.x | Dockerfile base + `requires-python` |
| typer | ~0.12 | `pyproject.toml` |
| pydantic | ~2.9 | `pyproject.toml` |
| httpx | ~0.27 | `pyproject.toml` |
| dnspython | ~2.7 | `pyproject.toml` |
| pytricia | ~1.0 | `pyproject.toml` |
| python-Wappalyzer | ~0.4 | `pyproject.toml` |
| wafw00f | **==2.3.1** (exacto) | `pyproject.toml` |
| shodan | ~1.31 | `pyproject.toml` |
| censys | ~2.2 | `pyproject.toml` |
| rich | ~13 | `pyproject.toml` |
| structlog | ~24 | `pyproject.toml` |
| PyYAML | ~6.0 | `pyproject.toml` |
| tenacity | ~9 | `pyproject.toml` |
| pytest | ~8 (dev) | `[project.optional-dependencies]` |
| respx | ~0.21 (dev) | idem |
| ruff | ~0.5 (dev) | idem |
| mypy | ~1.11 (dev) | idem |
| freezegun | ~1.5 (dev) | idem |
| Base image | `kalilinux/kali-rolling@sha256:...` | Dockerfile FROM con digest |
| whatweb | apt version vigente de Kali | `apt-mark hold` en Dockerfile |
| nikto | apt version vigente de Kali | `apt-mark hold` |

Dependabot configurado en `.github/dependabot.yml` para alertas semanales agrupadas.

---

## Estructura de directorios (v0.4 §17.2)

```
cdt-scanner/
├── CLAUDE.md                    (este archivo)
├── README.md                    (disclaimer scope, quick start)
├── pyproject.toml
├── Dockerfile                   (multi-stage, Kali base pinned, non-root, read-only FS)
├── .dockerignore
├── .gitignore
├── docs/spec/                   (v0.4, v0.5)
├── docs/power-automate/         (csv-parser.md, cdt-ingest.zip — post-MVP)
├── src/cdt/
│   ├── __init__.py
│   ├── __main__.py              (entry point: python -m cdt)
│   ├── cli.py                   (typer: scan, validate, dry-run, diff, doctor)
│   ├── models.py                (pydantic v2: AccountIn, AccountEnriched, Site, Finding)
│   ├── context.py               (config global dataclass)
│   ├── errors.py                (códigos E0–E7 ↔ exit codes, v0.5 §2.11–§2.12)
│   ├── io/
│   │   ├── csv_in.py            (read accounts_in.csv, authorized.csv)
│   │   ├── csv_out.py           (write 4 CSVs, UTF-8 sin BOM, LF, quoting RFC 4180)
│   │   └── journal.py           (nikto_runs.jsonl + scan audit log)
│   ├── discovery/
│   │   ├── brave_search.py      (Validate + Discover via Brave Search API)
│   │   ├── validator.py         (HEAD + parking detection + Title match)
│   │   └── expander.py          (crt.sh subdomain expansion + ranking)
│   ├── scan/
│   │   ├── passive.py           (DNS, WHOIS, IP range lookup pytricia)
│   │   ├── browser.py           (GET /, robots, TLS handshake, headers)
│   │   └── runner.py            (asyncio Semaphore, rate-limit 2 RPS/dominio)
│   ├── tools/
│   │   ├── wafw00f_wrapper.py   (library, no subprocess)
│   │   ├── whatweb_wrapper.py   (subprocess JSON)
│   │   ├── nikto_wrapper.py     (streaming + early termination, v0.4 §14.5.2)
│   │   ├── shodan_wrapper.py    (InternetDB free + Host API opt)
│   │   ├── censys_wrapper.py
│   │   └── wappalyzer_wrapper.py
│   ├── detect/
│   │   ├── waf.py               (catálogo §14.1 cargado de YAML)
│   │   ├── cloud.py             (árbol §14.2)
│   │   ├── cdn.py               (§14.3)
│   │   ├── stack.py             (§14.4)
│   │   └── scoring.py           (sistema de confianza §14.5 + §5.7)
│   └── scoring/
│       ├── risk.py              (rúbrica /15)
│       ├── opportunity.py       (3 booleanos)
│       └── rationale.py         (templates de v0.4 §7.5)
├── config/
│   ├── cdt.yaml                 (defaults globales, v0.5 §2.10)
│   ├── discovery.yaml           (provider: brave_search)
│   ├── detection_rules.yaml     (drop-in v0.5 §5.3–§5.7)
│   ├── nikto_skip.yaml          (drop-in v0.5 §5.8)
│   └── rationale_templates.yaml (drop-in v0.5 §5.9)
├── inputs/
│   └── recurring.csv.example    (datos sintéticos, NO reales)
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│       ├── http/{waf,cdn,stack,mixed}/
│       ├── dns/
│       ├── crt_sh/
│       ├── whatweb/
│       ├── nikto/
│       ├── shodan/
│       ├── censys/
│       ├── ip_ranges/
│       └── accounts/
└── .github/
    └── workflows/
        ├── ci.yml               (ruff, mypy, pytest --cov, docker build smoke)
        ├── release.yml          (multi-arch :tag :latest a GHCR)
        └── scan.yml             (workflow_dispatch + cron, commit-back v0.5 §3.7)
```

---

## Convenciones

### Estilo Python

- **Type hints siempre.** mypy en strict mode.
- **pydantic v2** para todos los models de IO. NO dataclasses planos, NO dicts crudos como contratos.
- **typer** para CLI (no argparse, no click).
- **structlog** (no `print`, no f-string en logs — eventos nombrados con kwargs).
- **httpx** para HTTP (no requests, no urllib).
- **asyncio-first** donde haya I/O concurrente (escaneos, discovery).
- **tenacity** para retries con backoff exponencial.
- **respx** para mockear httpx en tests.
- **subprocess.Popen** + streaming line-by-line para herramientas con output largo (nikto). NO `subprocess.run` con `capture_output` para output > 100 KB.

### Naming

- Módulos: snake_case, plural cuando agrupan (`tools/`, `detect/`, `scoring/`).
- Tests: `test_<module>__<behavior>.py::test_<scenario>`.
- Eventos structlog: snake_case_underscore — `discovery_validate_ok`, `nikto_early_term`, `scan_finished`. Lista canónica en `docs/events.md` (a crear en Fase 1).

### Tests (v0.4 §19)

- Pyramid: ~200+ unit tests (coverage ≥ 80%), ~30 integration tests, 3-5 E2E manuales.
- Cada regla en `config/detection_rules.yaml` requiere fixture HTTP en
  `tests/fixtures/http/<categoria>/`. CI bloquea sin fixture.
- Golden files para los 4 CSVs de salida; actualización requiere commit explícito.
- `freezegun` para timestamps determinísticos.
- `tmp_path` para isolation en tests.

### Errores y exit codes (v0.5 §2.11)

- 0 = OK, 2 = misuse, 3 = input error, 4 = config, 5 = network, 6 = quota, 7 = SIGINT.
- Cada `Enn` ↔ exit code N. Definir en `src/cdt/errors.py`.
- Stderr formato: `cdt error: [E03] <message>`.
- Con `--log-format json` o `CI=true`, errores se emiten como JSON line.

### CSV output (v0.5 §3.10)

- Encoding UTF-8 **sin BOM**.
- Newline **LF**.
- Quoting: `"…"` sólo cuando la celda contiene `,`, `"` o newline. `"` internas escapadas como `""`.
- Las únicas columnas que típicamente requieren quoting son `OpportunityRationale`, `WAFTool`, `Message`.

---

## Decisiones ya tomadas (NO re-debatir, NO replantear en PRs)

1. **Scope geográfico de 7 países** — documentación, no enforcement (v0.4 §12.13).
2. **Nikto condicional** con early-termination en Tier 2 (v0.4 §14.5.2).
3. **Wappalyzer primario** para tech stack, BuiltWith opcional (v0.4 §14.5.2).
4. **IP efímera en Prod** (Linode efímero por run), persistente en Dev (v0.4 §12).
5. **Sin dominio propio** (sin `cdt.threathunt.cloud`).
6. **SharePoint via commit-back + upload manual** (v0.5 §3) — no Graph API por restricción de tenant corporativo.
7. **Brave Search** como provider (override sobre v0.4 §4).
8. **Repo privado obligatorio** — outputs contienen Title/Country reales.

---

## Don'ts

- ❌ NO hardcodear endpoints en código — leer de `config/*.yaml`.
- ❌ NO loguear `csv_content` completo, response bodies del target, ni cookies.
- ❌ NO usar `print()` — siempre `structlog`.
- ❌ NO llamar APIs externas sin cache + rate limit.
- ❌ NO commitear keys, tokens, secrets. Usar GH Secrets + env vars.
- ❌ NO commitear outputs reales en `main`. Usar rama `outputs` (v0.5 §3.5).
- ❌ NO instalar deps fuera de `pyproject.toml`. Pin obligatorio.
- ❌ NO commitear CSVs reales con Title/Country. Usar `inputs/recurring.csv.example` con datos sintéticos.

---

## Skills disponibles

- `init` — generar/actualizar este `CLAUDE.md` cuando cambien convenciones.
- `cdt-scanner-dev` (custom, en `.claude/skills/`) — templates e idioms del proyecto. Crearlo en Fase 0 paso 6.
- `review` — code review automatizado en PRs.
- `security-review` — barrido de seguridad. **Obligatorio en cada PR**.

Invocación: `/skill <nombre>` o como subagent.

---

## Workflow de fases (v0.4 §17.7)

Cada fase:

1. Issue en GitHub describe el alcance, refs al spec.
2. Claude Code abre rama `feat/<fase>` desde `main`.
3. Implementa + tests. CI debe estar verde antes de PR.
4. PR abre los skills `review` + `security-review`.
5. Human approval del Tech Lead.
6. Merge a main → CI publica imagen `:dev` o `:latest` a GHCR.

**Estado actual: Fase 0 (bootstrap).** Próxima: Fase 1 (scaffold Python).

---

## Estado de Fase 0 al momento

- ✅ Repos creados (`cdt-scanner`, `cdt-infra`).
- ✅ GH Secrets en cdt-scanner: `BRAVE_SEARCH_API_KEY`, `LINODE_TOKEN`, `HCP_TF_TOKEN`, `INFRA_TOKEN`.
- ✅ HCP Terraform org `fortidz`, project `CDT`, workspaces `cdt-dev-persistent` + `cdt-ephemeral`, variable set `cdt-shared-vars` aplicado.
- ✅ Specs en `docs/spec/`.
- ✅ `CLAUDE.md` (este).
- ⏳ Skill `cdt-scanner-dev`.
- ⏳ Fase 1 — scaffold Python (próxima).
