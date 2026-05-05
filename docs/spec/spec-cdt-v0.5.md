# Cloud Development Tool (CDT) — Spec v0.5 (delta sobre v0.4)

> **Estado:** Borrador delta. Cierra los ítems explícitamente diferidos por v0.4. **No reemplaza** v0.4 — se lee junto a ella.
> **Autor:** Dave (eiz311@gmail.com)
> **Fecha:** 2026-05-04
> **Alcance del delta:**
> 1. Detalle completo de la CLI (cierra §10 de v0.4).
> 2. Decisión sobre Power Automate opciones B–E (cierra §11.2 de v0.4).
> 3. Cierre formal de §13, §16 y §18 de v0.4 (placeholders / hueco de numeración).
> 4. Detection rule pack v1 — YAML concreto listo para `config/detection_rules.yaml` (cierra el "narrative-only" de §14 de v0.4).
>
> **Lo que NO cambia:** todo el resto de v0.4 sigue vigente sin enmiendas. Arquitectura bifásica, contrato de CSVs, scoring /15, tres booleanos Fortinet, pipeline GitHub Actions + Linode efímero, scope geográfico de 7 países, runbook §20. Si una sección no aparece en este delta, leer v0.4.

---

## 0. Cómo leer este documento

- Cada sección de v0.5 cita la sección de v0.4 que cierra.
- Donde v0.5 difiere de v0.4, se marca explícitamente como **(modifica v0.4 §X)**. Si no hay marca, es un complemento aditivo.
- Los bloques YAML de §5 son el contenido literal de los archivos del repo `cdt-scanner` — Claude Code los puede copiar tal cual a `config/`.

---

## 1. Resumen ejecutivo del delta

| Ítem v0.4 | Estado v0.4 | Cierre v0.5 |
|---|---|---|
| §10 CLI propuesta | Esqueleto, "detalle en v0.5" | §2 — comandos completos, flags, env vars, exit codes, formato de errores, ejemplos. |
| §11.2 opciones B–E (Power Automate) | "Evaluar post-MVP, decisión en v0.5" | §3 — **decisión: GH Actions commitea los CSVs a `outputs/` en el repo `cdt-scanner` → operador descarga y sube manualmente a una carpeta de SharePoint → Power Automate Free dispara con "When a file is created" y popula la List**. La subida a SharePoint es **manual por diseño** porque no hay acceso al tenant M365 corporativo (no admin consent posible). B, C, D, E descartadas con razones. |
| §13 reservado | Placeholder vacío | §4.1 — disuelto. La numeración salta. |
| §16 reservado | Placeholder vacío | §4.2 — disuelto. Su contenido potencial ya vive en §17.5 de v0.4 (skill `cdt-scanner-dev`). |
| §18 inexistente | Hueco de numeración (§17 → §19) | §4.3 — formalmente declarado vacío. La numeración se conserva por estabilidad de referencias cruzadas. |
| §14 detection narrative | Tablas y reglas en prosa | §5 — `detection_rules.yaml` v1 completo, drop-in. |

Sin nuevas secciones fuera de las que cierran ítems diferidos. v0.5 es disciplinada por diseño.

---

## 2. CLI — especificación completa (cierra v0.4 §10)

### 2.1 Forma general

```
cdt <comando> [flags-globales] [flags-comando] [args]
```

Todos los comandos respetan los flags globales de §2.3. Los específicos de cada comando aparecen en sus subsecciones.

### 2.2 Comandos

| Comando | Propósito | Side effects |
|---|---|---|
| `cdt scan` | Ejecuta el pipeline completo descrito en §8 de v0.4. | Escribe los 4 CSVs + `nikto_runs.jsonl` en `--out`. |
| `cdt validate` | Valida sólo el schema y la consistencia del input, sin escanear. | Imprime errores. Exit ≠ 0 si hay problemas. |
| `cdt dry-run` | Como `validate` pero además imprime el plan: cuántas filas en cada modo (Validate / Discover / Scan-only), cuántas queries CSE estimadas, cuántos sitios secundarios esperados. | Sólo lectura. |
| `cdt diff` | Compara dos directorios de output (corridas distintas) y reporta deltas por cuenta. | Escribe `diff.csv` en stdout o en `--out`. |
| `cdt doctor` | Health check: API keys presentes, conectividad, quotas, versiones de tools. | Sólo lectura. |

### 2.3 Flags globales (aplican a todos los comandos)

| Flag | Tipo | Default | Notas |
|---|---|---|---|
| `--config <path>` | path | `./config/cdt.yaml` si existe, sino built-in | Archivo YAML con overrides de cualquier valor de configuración. Ver §2.10 (precedencia). |
| `--log-level` | enum | `info` | `debug` / `info` / `warn` / `error`. |
| `--log-format` | enum | `console` | `console` (rich, color) / `json` (structlog JSON line por evento, para parsing). |
| `--no-color` | bool | false | Fuerza salida sin ANSI. CI lo activa por default cuando `CI=true`. |
| `--quiet` / `-q` | bool | false | Suprime logs salvo `error`. Equivalente a `--log-level error`. |
| `--verbose` / `-v` | bool | false | Equivalente a `--log-level debug`. |
| `--version` | bool | — | Imprime versión y exit 0. Formato: `cdt <semver> (commit <sha7>)`. |
| `--help` / `-h` | bool | — | Imprime help y exit 0. Help contextual por comando. |

### 2.4 `cdt scan`

```
cdt scan --in <csv> [--out <dir>] [--tier <t>] [--authorized <csv>]
         [--concurrency N] [--country "<lista>"] [--skip-expansion]
         [--skip-validation] [--max-sites-per-account N] [--force-nikto]
         [--no-nikto] [--cache-dir <path>] [--dry-run] [--seed N]
```

| Flag | Tipo | Default | Notas |
|---|---|---|---|
| `--in` | path | (requerido) | `accounts_in.csv` con headers `Title,Country,Website[,SkipValidation]`. |
| `--out` | path | `./out/` | Directorio de salida. Se crea si no existe. Sobrescribe archivos previos. |
| `--tier` | enum | `browser` | `passive` / `browser` / `dast`. |
| `--authorized` | path | (vacío) | Requerido si `--tier dast`. Match por `(Title, Country)` exacto. Sin él, el tool aborta antes de escanear. |
| `--concurrency` | int | 20 | Workers asyncio. Rate limit por dominio (2 RPS) es independiente. Hard cap: 50. |
| `--country` | string | (vacío) | Lista separada por comas. Filtra antes de escanear. Ejemplo: `--country "Ecuador,Perú"`. |
| `--skip-expansion` | bool | false | No expande con `crt.sh`. Sólo `Website01`. |
| `--skip-validation` | bool | false | Equivalente global a `SkipValidation=1` en cada fila. |
| `--max-sites-per-account` | int | 5 | Límite de `Website01..N`. Cualquier extra va sólo a `sites.csv`. Acotado por la SP List a 5. |
| `--force-nikto` | bool | false | Ejecuta nikto en Tier 2 sin chequear las condiciones de §14.5.2. Útil para debug. |
| `--no-nikto` | bool | false | Deshabilita nikto incluso si las condiciones disparan. Equivalente programático de `CDT_NIKTO_ENABLED=false`. |
| `--cache-dir` | path | `~/.cache/cdt/` | Cache de IP ranges, discovery, crt.sh, Shodan/Censys. |
| `--dry-run` | bool | false | Valida input + imprime plan + sale **sin escanear**. Sin escribir output. (Alias práctico al subcomando `cdt dry-run` para uso embebido en pipelines.) |
| `--seed` | int | (vacío) | Determinismo en orden de procesamiento. Útil en tests. |

**Validaciones de pre-flight (antes del primer scan):**

1. Headers del CSV son `Title,Country,Website` (en cualquier orden, opcional `SkipValidation`).
2. `--tier dast` exige `--authorized`. Si la `(Title, Country)` de una fila no aparece en `authorized.csv`, esa fila degrada a `tier=browser` con un finding `DAST_NOT_AUTHORIZED` y un warning en stderr.
3. Las API keys requeridas para el tier están presentes (ver §2.9). Si falta `GOOGLE_CSE_API_KEY` y hay filas en modo Validate/Discover, falla con exit 4.
4. Espacio libre en `--out` ≥ 100 MB.

**Output al stdout durante la ejecución:**

```
[14:31:02] INFO  validating input — 487 accounts, 7 countries
[14:31:02] INFO  plan: 412 validate, 51 discover, 24 scan-only
[14:31:02] INFO  estimated CSE queries: 102 / 100 daily quota — WARN
[14:31:03] INFO  scanning [tier=browser] concurrency=20
[14:32:18] INFO  scanned 50/487 (10%) eta=12m
...
[14:54:11] INFO  done — 472 ok, 15 in validation_issues
[14:54:11] INFO  outputs written to ./out/
```

Con `--log-format json` cada línea es un evento estructurado con campos `event`, `ts`, `level`, `account`, `country`, `tier`, `duration_ms`, etc. (ver §2.13).

### 2.5 `cdt validate`

```
cdt validate --in <csv> [--authorized <csv>]
```

Verifica:

- Headers correctos.
- Encoding UTF-8 (si BOM presente, advertencia, no error).
- `Country` dentro del scope declarado (warning si no, no error — coherente con §12.13 de v0.4).
- `Website` parseable cuando no está vacío (sin TLDs imposibles, sin caracteres ilegales, sin puerto explícito).
- Duplicados `(Title, Country)` exactos → error.
- Si `--authorized` se pasa: verifica que cada fila exista también en el input.

Exit codes: ver §2.11.

Output:

```
$ cdt validate --in accounts_in.csv
✓ headers OK
✓ encoding UTF-8 (no BOM)
! 3 rows have Country outside the documented scope (Argentina) — proceeding anyway
✓ all websites parseable
✗ duplicate (Title, Country): "Banco Ejemplo S.A. / Perú" appears in rows 14 and 287
1 error, 1 warning
```

### 2.6 `cdt dry-run`

```
cdt dry-run --in <csv> [--tier <t>] [--country "<lista>"]
```

Igual que `validate` + plan estimado:

```
Plan estimado:
  Total filas (post-filter):           487
  Modos:
    Validate + Expand (default):       412
    Discover + Expand (fallback):       51
    Scan-only (SkipValidation=1):       24
  Queries CSE estimadas:               102
  Quota CSE diaria:                    100 (custom search free)  ⚠ excede
  Sitios secundarios estimados (crt.sh): ~2400
  Cuentas potencialmente niktables:    ~80–120 (basado en heurística histórica)
  Duración estimada (tier=browser, conc=20): 48–72 min
```

Sale exit 0 si validate pasa. No escanea.

### 2.7 `cdt diff`

```
cdt diff --baseline <dir> --current <dir> [--out <path>] [--by <campo>]
```

| Flag | Tipo | Default | Notas |
|---|---|---|---|
| `--baseline` | path | (requerido) | Directorio output de la corrida anterior. Lee `accounts_enriched.csv`. |
| `--current` | path | (requerido) | Directorio output de la corrida nueva. |
| `--out` | path | stdout | CSV con las diferencias. |
| `--by` | string | `WAF,WAFVendor,RiskScore,RecommendsFortiAppSec,RecommendsFortiWeb,RecommendsFortiCNAPP` | Lista de columnas a comparar. |

Match por `(Title, Country)`. Para cada cuenta presente en ambos, compara los campos en `--by` y reporta sólo las diferencias.

Output ejemplo:

```
Title,Country,Field,Baseline,Current
TIPTI - GRUPO LA FAVORITA,Ecuador,WAFVendor,Cloudflare,Fortinet
Banco X,Perú,RiskScore,MEDIUM (7/15),HIGH (10/15)
Retail Y,Chile,RecommendsFortiAppSec,No,Yes
```

Cuentas sólo en baseline → fila con `Field=__missing_in_current__`.
Cuentas sólo en current → fila con `Field=__new_in_current__`.

Útil para tracking semanal: `cdt diff --baseline week-of-2026-04-20 --current week-of-2026-04-27 --out churn.csv`.

### 2.8 `cdt doctor`

```
cdt doctor [--cse-quota] [--shodan] [--censys] [--linode] [--all]
```

Sin flags, corre los checks "free" (sin gastar quota): presencia de API keys, conectividad básica, versiones de binarios.

| Check | Qué verifica |
|---|---|
| `api_keys_present` | `GOOGLE_CSE_API_KEY`, `GOOGLE_CSE_ENGINE_ID`, opcionalmente `SHODAN_API_KEY`, `CENSYS_API_ID/SECRET`, `BUILTWITH_API_KEY`. |
| `network_egress` | DNS resolution + HEAD a `https://internetdb.shodan.io/8.8.8.8` (200), `https://crt.sh/?q=acme.com&output=json` (200), `https://www.gstatic.com/ipranges/cloud.json` (200). |
| `tools_versions` | `wafw00f --version`, `whatweb --version`, `nikto -Version`. Compara contra el pin del Dockerfile. |
| `cache_dir_writable` | `~/.cache/cdt/` existe y es escribible. |
| `disk_space` | ≥ 200 MB libres en `--out` y en `--cache-dir`. |

Con `--cse-quota`: hace **una** query CSE real para leer el header `X-RateLimit-Remaining` (si la API lo devuelve) o estima por contador local en `~/.cache/cdt/cse_quota.json`.

Con `--all`: corre todos los checks incluyendo los que cuestan quota.

Output:

```
$ cdt doctor
✓ python 3.12.4
✓ cdt 0.5.0 (commit abc1234)
✓ wafw00f 2.3.1                    (pinned: 2.3.1)
✓ whatweb 0.5.5                    (pinned: 0.5.5)
✓ nikto 2.5.0                      (pinned: 2.5.0)
✓ GOOGLE_CSE_API_KEY               present
✓ GOOGLE_CSE_ENGINE_ID             present
- SHODAN_API_KEY                   absent (Host API disabled, InternetDB still works)
- CENSYS_API_ID/SECRET             absent (Censys disabled)
- BUILTWITH_API_KEY                absent (BuiltWith disabled — fine, optional)
✓ DNS resolution (8.8.8.8)         3ms
✓ crt.sh reachable                 78ms
✓ shodan internetdb reachable      112ms
✓ ip-ranges cache fresh            (last refresh 2h ago)
✓ ~/.cache/cdt writable            420 MB free
✓ ./out writable                   12 GB free
all green.
```

### 2.9 Variables de entorno

| Variable | Requerida si | Notas |
|---|---|---|
| `GOOGLE_CSE_API_KEY` | hay filas Validate/Discover | API key de Google Custom Search. |
| `GOOGLE_CSE_ENGINE_ID` | igual | ID del Programmable Search Engine. |
| `SHODAN_API_KEY` | nunca | Si presente, habilita Shodan Host API. Sin ella, sólo InternetDB (gratis). |
| `CENSYS_API_ID`, `CENSYS_API_SECRET` | nunca | Si presentes, habilita Censys. |
| `BUILTWITH_API_KEY` | nunca | Si presente, habilita BuiltWith. |
| `CDT_NIKTO_ENABLED` | nunca | `false` deshabilita nikto globalmente. Equivalente a `--no-nikto`. |
| `CDT_LOG_LEVEL` | nunca | Override del default. |
| `CDT_LOG_FORMAT` | nunca | Override del default. |
| `CDT_CACHE_DIR` | nunca | Override de `--cache-dir`. |
| `CDT_USER_AGENT` | nunca | Override del User-Agent (default `CDT-Scanner/0.5`). En Prod no hay dominio propio (v0.4 §12.6), el UA es identificable pero neutral. |
| `CI` | (lee Github sets it) | Si `=true`, fuerza `--no-color` y `--log-format=json` por default. |

### 2.10 Precedencia de configuración

De mayor a menor prioridad:

```
1. flags CLI (--tier, --concurrency, ...)
2. variables de entorno (CDT_*, GOOGLE_CSE_API_KEY, ...)
3. archivo --config (./config/cdt.yaml o el que se pase)
4. archivo built-in (defaults compilados)
```

Ejemplo: si `cdt.yaml` dice `concurrency: 30`, pero el flag pasa `--concurrency 10`, gana 10. Si nadie lo pasa, gana 30. Si `cdt.yaml` no existe, gana el default 20.

Estructura mínima de `cdt.yaml`:

```yaml
defaults:
  tier: browser
  concurrency: 20
  cache_dir: ~/.cache/cdt
  log_format: console

discovery:           # ver v0.4 §4.5
  cache_ttl_hours: 168
  # (resto del bloque idéntico a v0.4 §4.5)

detection:           # apunta al pack v1
  rules_file: config/detection_rules.yaml
  nikto_skip_file: config/nikto_skip.yaml
  rationale_templates_file: config/rationale_templates.yaml
```

### 2.11 Códigos de salida

| Exit | Significado |
|---|---|
| 0 | Éxito completo. |
| 1 | Error genérico no clasificado. |
| 2 | Error de uso (flag inválido, argumento faltante). Equivalente al estándar de typer. |
| 3 | Error de input: CSV mal formado, headers faltantes, duplicados. |
| 4 | Error de configuración: API key faltante para el tier seleccionado, archivo `cdt.yaml` inválido, `--authorized` requerido y ausente. |
| 5 | Error de red persistente: ningún check de `cdt doctor` pasa. |
| 6 | Quota agotada de Google CSE en pre-flight. Para arrancar de todas formas, `--skip-validation`. |
| 7 | Cancelado por el operador (SIGINT). |
| 64–78 | (reservados, sysexits.h convencionales por si los necesitamos). |

`cdt scan` siempre intenta cerrar `nikto_runs.jsonl` y los CSVs parciales antes de salir, incluso en exit 7 (handler de SIGINT).

### 2.12 Formato de errores en stderr

Todos los errores se escriben a stderr con prefijo `cdt error:` seguido del código y el contexto. Formato `console`:

```
cdt error: [E03] CSV header missing required column 'Country' in file ./in/accounts_in.csv
cdt error: [E04] GOOGLE_CSE_API_KEY is required because 412 rows are in Validate mode and 51 in Discover mode. Set the env var or pass --skip-validation.
```

Formato `json` (con `--log-format json` o `CI=true`):

```json
{"ts":"2026-05-04T14:31:02Z","level":"error","code":"E03","event":"input_validation_failed","file":"./in/accounts_in.csv","missing_columns":["Country"]}
```

Cada código `Enn` corresponde 1:1 a un exit code (`E03 → exit 3`, `E04 → exit 4`, …). Los códigos están enumerados en `src/cdt/errors.py` y son parte del contrato público — cambios que rompen códigos requieren bump de minor version.

### 2.13 Logging y verbosity

- Engine: `structlog` con renderer dual (`console` Rich vs `json` line).
- Eventos canónicos (lista no exhaustiva, todos en `events.md` del repo):
  - `scan_started`, `scan_finished`
  - `account_started`, `account_finished` (con `duration_ms`, `tier`, `findings_count`)
  - `discovery_validate_ok`, `discovery_validate_fail`, `discovery_used_cache`
  - `detection_waf_high_confidence`, `detection_waf_low_confidence`
  - `nikto_triggered`, `nikto_early_term`, `nikto_skipped`
  - `csv_written` (con `path`, `rows`, `bytes`)
- Nunca se loguea: el `csv_content` completo de input, response bodies de targets, payloads de wafw00f, contenido de cookies. Sólo metadatos (status, headers seleccionados, hash si hace falta correlación).

### 2.14 Ejemplos canónicos

```bash
# Corrida típica semanal
cdt scan --in inputs/recurring.csv --tier browser --out ./out/$(date +%Y-%m-%d)/

# Sólo Ecuador, modo passive (cero requests al target)
cdt scan --in accounts.csv --tier passive --country Ecuador --out ./out/passive-ec/

# Tier 3 contra una lista autorizada
cdt scan --in accounts.csv --authorized authorized.csv --tier dast --out ./out/dast/

# Verificar que el CSV está sano antes de mandar al pipeline
cdt validate --in accounts.csv

# Ver qué pasaría sin gastar quota
cdt dry-run --in accounts.csv --tier browser --country Perú

# Diff semanal
cdt diff --baseline ./out/2026-04-27/ --current ./out/2026-05-04/ --out churn-week-19.csv

# Health check antes de empezar el día
cdt doctor --all
```

---

## 3. Pipeline post-MVP — commit-back al repo + upload manual a SharePoint (cierra v0.4 §11.2 opciones B–E)

### 3.1 Decisión

> **Restricción dura del entorno:** no tenemos acceso al tenant corporativo M365. No es posible registrar una app en Entra ID, ni obtener admin consent para Graph, ni adquirir licencias Premium de Power Automate, ni desplegar Azure infra. Sólo tenemos acceso de **usuario final** a las aplicaciones que el tenant ya provisiona (SharePoint web, Power Automate Free, Power BI Service, Excel Online).
>
> **MVP**: se mantiene el camino manual de v0.4 §11.2 (descargar artifact → Edit in grid view → paste fila por fila). Sin cambios.
>
> **Post-MVP**, una vez el flujo MVP haya producido ≥ 4 corridas exitosas:
> 1. **GitHub Actions** termina la corrida y **commitea los CSVs de salida** a `outputs/<YYYY-MM-DD>_<run_id>/` en el repo `cdt-scanner` (rama `outputs`, ver §3.5). Sigue subiendo el artifact como red de seguridad.
> 2. **El operador** (humano) recibe la notificación → descarga `accounts_enriched.csv` desde la web de GitHub → **lo sube manualmente** a `/sites/<site>/Documents/CDT/inbox/` en SharePoint usando su propia cuenta corporativa (drag-and-drop en el navegador).
> 3. **Power Automate Free** detecta el archivo recién creado en `/CDT/inbox/`, parsea el CSV, crea un item por fila en la List `Cloud Accounts SOLA FY2026 v2`, y mueve el archivo a `/CDT/processed/`.
>
> El humano-en-el-medio es **el límite de confianza por diseño**: la única identidad que toca el tenant M365 es la del propio operador, con sus permisos normales de usuario. Cero infra dentro del tenant. Cero negociación con IT corporativo.
>
> **Opciones B, C, D, E** de v0.4 §11.2 quedan todas descartadas con razones específicas en §3.3.

> **Nota de revisión interna (trazabilidad):** §3 ha tenido **dos revisiones previas** durante la edición de v0.5:
> - Revisión 1 proponía la Opción B (email → Power Automate). Reemplazada porque el operador prefiere mantener el dato dentro del tenant M365.
> - Revisión 2 proponía drop directo a SharePoint vía Graph API con app registration `Sites.Selected`. **Descartada** al confirmar que el tenant es corporativo y no hay admin consent disponible.
>
> Esta versión actual (revisión 3) es la que respeta esa restricción. Se conservan estas notas para que el contexto futuro (si el operador alguna vez gana acceso de admin al tenant, o si CDT migra a un tenant propio) tenga el camino de upgrade ya pensado: revisión 2 sigue siendo la arquitectura objetivo a largo plazo.

### 3.2 Por qué este diseño es el correcto bajo la restricción

| Criterio | **Commit-back + upload manual** | B (Email → PA) | C (PA Premium HTTP) | D (Graph + app reg) | E (Azure Blob) |
|---|---|---|---|---|---|
| Requiere admin del tenant M365 | **No** | No (pero sí mailbox interno) | Sí (license) | Sí (admin consent) | Sí (subscription) |
| Requiere license Premium | No | No | Sí ($15/usr/mes) | No | No |
| Identidad que toca el tenant | Operador (su user normal) | Mailbox del operador | Endpoint expuesto | Service principal | Storage SAS |
| Plano de datos | GitHub repo (privado) → operador → SP | M365 + SMTP externo | M365 + endpoint público | Sólo M365 | M365 + Azure |
| Paso humano semanal | **~30 s** (1 download + 1 drag-and-drop) | 0 | 0 | 0 | 0 |
| Auditabilidad de qué corrida produjo qué CSV | **Doble**: git history + SP version history | Email | Logs HTTP | SP version history | SP version history |
| Resilience si tenant cambia política | Cero impacto (la restricción no aplica a usuario final) | Frágil (filtros corp pueden romper SMTP) | Frágil | Frágil (admin puede revocar) | Frágil |
| Coste recurrente | **$0** | $0 | $15/usr/mes | $0 | $0–$5/mes |
| Tiempo a primera corrida automatizada | **~1 día** (setup del flow + folder en SP) | ~2 h | ~1 h tras license | bloqueado | bloqueado |

Esta opción gana porque:

1. **Respeta la restricción dura del entorno** (no admin del tenant, no licenses Premium, no Azure subscription). Las opciones C, D, E quedan fuera por construcción — no son ejecutables sin escalación a IT corporativo.
2. **Saca del operador el trabajo tedioso** (paste fila por fila, ~3 min por corrida) y deja sólo el trabajo de validación humana (subir un archivo, ~30 s). El humano sigue en el loop pero sólo para autorizar la entrada al tenant.
3. **El upload manual ES el control de seguridad.** El operador es la única identidad que toca el tenant, con sus permisos normales de usuario corporativo. No hay credenciales de servicio almacenadas en GH Secrets que apunten al tenant. Cero superficie de ataque persistente del lado M365.
4. **Doble auditoría**: cada CSV producido queda en git (commit hash, autor `github-actions[bot]`, timestamp) **y** en SP (version history del archivo, autor=operador). Permite reconstruir cualquier corrida histórica.
5. **Degradación elegante**: si el flow se rompe, el camino del paste manual de v0.4 §11.2 sigue funcionando con los mismos archivos. Si el commit-back se rompe, el artifact de GitHub Actions sigue existiendo. Tres caminos redundantes, ninguno depende del otro.

### 3.3 Por qué B, C, D, E se descartan formalmente

**B — Email → Power Automate.** Aunque no requiere admin del tenant, depende de que el tenant corporativo no filtre attachments .csv (muchos lo hacen como prevención de exfiltración) y de que exista un mailbox interno disponible para recibir. Suma una dependencia externa (SMTP en GH Actions con un proveedor extra-tenant) sin valor compensatorio. Reabrir sólo si el operador prefiere recibir notificaciones por email también, pero en ese caso vivirían en paralelo, no como camino de ingestión.

**C — Power Automate Premium HTTP trigger.** Requiere license Premium ($15/usr/mes), que sólo un admin del tenant puede asignar. **No ejecutable** bajo la restricción.

**D — Microsoft Graph + app registration `Sites.Selected`.** Aunque técnicamente más limpia, requiere:
- Crear un app registration en Entra ID (sólo admin del tenant).
- Conceder admin consent al permiso `Sites.Selected` (sólo admin).
- Que un admin con `Sites.FullControl.All` corra el `POST /sites/{id}/permissions` de provisioning inicial (sólo admin, una vez).

**No ejecutable** bajo la restricción. Queda como **arquitectura objetivo si alguna vez** se gana acceso de admin (ver "Nota de revisión interna" en §3.1 — la revisión 2 del spec describe esa variante en detalle).

**E — Azure Blob como buffer.** Requiere subscription Azure (admin) + storage account (admin) + de todas formas un flow para mover Blob → SP. **No ejecutable** y suma componentes sin resolver el problema central.

### 3.4 Arquitectura

```
┌──────────────────────────────────────────────────────────────┐
│ GitHub Actions (scan.yml)                                     │
│                                                               │
│   ... (terraform apply, scan, terraform destroy) ...         │
│                                                               │
│   Step "Upload outputs as artifact" (sin cambios)            │
│       └── retención 30 días — red de seguridad última        │
│                                                               │
│   Step "Commit outputs to repo" (NUEVO):                      │
│       1. Configura git como github-actions[bot]              │
│       2. Copia ./out/*.csv a outputs/<YYYY-MM-DD>_<run_id>/  │
│       3. git add, commit, push HEAD:outputs                  │
│       (ver §3.7 para el YAML)                                │
└────────────────────┬─────────────────────────────────────────┘
                     │ git push
                     ▼
┌──────────────────────────────────────────────────────────────┐
│ Repo PRIVADO cdt-scanner — rama `outputs`                    │
│                                                               │
│   outputs/                                                    │
│     2026-05-04_8123456789/                                   │
│       accounts_enriched.csv                                  │
│       sites.csv                                              │
│       findings.csv                                           │
│       validation_issues.csv                                  │
│       run-meta.json                                          │
│     2026-04-27_8001234567/   (corrida anterior)              │
│     ...                                                       │
└────────────────────┬─────────────────────────────────────────┘
                     │ Operador navega a github.com/<org>/cdt-scanner
                     │ → branch=outputs → último folder
                     │ → click en accounts_enriched.csv → "Download raw"
                     ▼
┌──────────────────────────────────────────────────────────────┐
│ Máquina del operador (browser)                                │
│                                                               │
│   accounts_enriched.csv en Downloads/                        │
└────────────────────┬─────────────────────────────────────────┘
                     │ Operador navega a SharePoint en su browser
                     │ → /sites/<site>/Documents/CDT/inbox/
                     │ → drag-and-drop del archivo
                     │ (~30 s, autenticado con su user corporativo)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│ SharePoint Online — tenant corporativo                        │
│                                                               │
│   Site: /sites/<site>                                         │
│   Library: Documents                                          │
│   Folder structure:                                           │
│     /CDT/                                                     │
│       /inbox/                ← OPERADOR sube aquí             │
│         accounts_enriched.csv                                │
│       /processed/<YYYY-MM-DD>_<run_id>/   (flow mueve)       │
│       /failed/<YYYY-MM-DD>_<run_id>/      (flow mueve)       │
└────────────────────┬─────────────────────────────────────────┘
                     │ "When a file is created in folder" trigger
                     ▼
┌──────────────────────────────────────────────────────────────┐
│ Power Automate flow (Free tier — owned por el operador)       │
│                                                               │
│   Trigger:  SharePoint → "When a file is created             │
│             (properties only)"                                │
│             Site = ese site, Library = Documents,             │
│             Folder = /CDT/inbox                               │
│   Filter:   endsWith(name, 'accounts_enriched.csv')          │
│                                                               │
│   1. Get file content                                         │
│   2. Parse CSV (compose + split, ver §3.10)                  │
│   3. For each row → Create item en SP List                    │
│      "Cloud Accounts SOLA FY2026 v2"                          │
│   4. Si todas las filas OK → Move file a                      │
│      /CDT/processed/<YYYY-MM-DD>_<run_id>/                   │
│      Si alguna falló → Move file a /CDT/failed/<...>/        │
│      + Post Teams notification al operador con el conteo      │
└──────────────────────────────────────────────────────────────┘
```

### 3.5 Folder en el repo: estrategia de rama `outputs`

**Decisión:** los CSVs se commitean a una **rama dedicada `outputs`** del repo `cdt-scanner`, no a `main`.

**Por qué rama separada:**

- `main` mantiene historia de **código** limpia. Code review, blame, bisect, y el grafo de PRs no se contaminan con commits automáticos semanales.
- `outputs` tiene su propia historia, donde un commit = un scan. `git log outputs` es la lista cronológica de corridas.
- Evita conflictos entre PRs de feature y commits de scan: no comparten archivos.
- Más fácil purgar (si llegamos a tener años de scans, podemos rebase + squash o crear un nuevo orphan branch sin tocar `main`).

**Estructura de la rama `outputs`:**

```
outputs/
└── 2026-05-04_8123456789/
    ├── accounts_enriched.csv
    ├── sites.csv
    ├── findings.csv
    ├── validation_issues.csv
    └── run-meta.json     # {run_id, tier, country_filter, completed_at, actions_run_url}
```

`run-meta.json` permite reconstruir contexto sin abrir GH Actions UI. Útil cuando se mira una corrida vieja.

**Constraints obligatorios:**

1. **El repo `cdt-scanner` DEBE ser privado.** Las salidas contienen `Title` (razón social), `Country`, y datos de scan que no son públicos. Si por alguna razón el repo necesita ser público en el futuro, los outputs migran a un repo privado separado (`cdt-scanner-outputs`).
2. `.gitattributes` en la rama `outputs` marca los CSVs como `linguist-generated=true` para que GitHub no los cuente en estadísticas de lenguaje ni los muestre por default en diffs de PRs.
3. Se versiona en `main` un `outputs/.gitkeep` y un `outputs/README.md` explicando que el contenido vive en la rama `outputs`, para evitar confusión a quien navegue `main`.

**Tamaño esperado:** ~100 KB por corrida × 1 corrida/semana × 52 semanas/año ≈ 5 MB/año. Negligible para git. No requiere LFS.

### 3.6 Permisos en GitHub Actions

El job que hace push a `outputs` necesita:

```yaml
permissions:
  contents: write   # para git push
```

GitHub provee automáticamente un `GITHUB_TOKEN` con esos permisos cuando se declaran. **No requiere PAT separado**, no requiere secret nuevo, no requiere coordinación con admin alguno. Esta es una diferencia importante con la revisión 2 del spec (que sí requería secrets dedicados al tenant M365 inalcanzables bajo la restricción actual).

### 3.7 GitHub Actions — paso de commit-back

Se agrega como último paso del job `scan` en `scan.yml`, **siempre activo** (no opt-in — el commit-back es seguro y barato):

```yaml
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

    # Switch a la rama outputs (orphan en el primer push)
    git fetch origin outputs:outputs 2>/dev/null || true
    if git rev-parse --verify outputs >/dev/null 2>&1; then
      git checkout outputs
    else
      git checkout --orphan outputs
      git rm -rf . 2>/dev/null || true
      cat > README.md <<'EOF'
    # CDT scan outputs

    Esta rama contiene un folder por cada corrida del scanner. Cada folder
    tiene los 4 CSVs (`accounts_enriched`, `sites`, `findings`,
    `validation_issues`) y un `run-meta.json` con el contexto de la corrida.

    El operador descarga `accounts_enriched.csv` del folder más reciente y
    lo sube manualmente a SharePoint para disparar la ingesta a la List.
    Detalle en spec-cdt-v0.5.md §3.
    EOF
      cat > .gitattributes <<'EOF'
    outputs/**/*.csv  linguist-generated=true
    EOF
      git add README.md .gitattributes
      git commit -m "init outputs branch"
    fi

    mkdir -p "${DEST}"
    cp ./out/accounts_enriched.csv ./out/sites.csv ./out/findings.csv ./out/validation_issues.csv "${DEST}/"
    cat > "${DEST}/run-meta.json" <<EOF
    {
      "run_id": "${RUN_ID}",
      "tier": "${{ inputs.tier }}",
      "country_filter": "${{ inputs.country_filter }}",
      "completed_at": "$(date -u +%FT%TZ)",
      "actions_run_url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
    }
    EOF

    git add "${DEST}"
    git commit -m "scan results: ${DATE} run ${RUN_ID} (tier=${{ inputs.tier }})"
    git push origin outputs
```

**Notas operativas:**

- El job declara `permissions: contents: write` a nivel job (o workflow); el `GITHUB_TOKEN` default ya alcanza.
- `concurrency: cdt-scan-${{ inputs.phase }}` (ya declarado en v0.4 §12.4) evita pushes simultáneos. Si llegaran a colisionar de todas formas, el `git push` falla y el step se marca rojo. El operador re-corre el workflow y la siguiente corrida hace push limpio.
- Se commitea **incluso si el operador no piensa subir el archivo a SP ese día**. Las salidas en la rama `outputs` son útiles por sí mismas: audit trail, diffing semanal con `cdt diff`, archivo histórico.

### 3.8 Workflow del operador (lado humano)

Frecuencia: 1 vez por corrida (típicamente semanal). Tiempo total: ~1 minuto.

```
1. Notificación de corrida lista
   - MVP: el operador chequea la rama `outputs` cuando le toca (calendar
     reminder los lunes, por ejemplo).
   - Post-MVP opcional (§3.12): un step de GH Actions postea a Teams via
     webhook. No requiere admin del tenant — el webhook lo crea el propio
     operador en su flow de Power Automate.

2. Descarga del CSV
   - Navega a github.com/<org>/cdt-scanner/tree/outputs
   - Click en el folder más reciente (sorting alfa = cronológico porque
     empieza con YYYY-MM-DD)
   - Click en accounts_enriched.csv → botón "Download raw file"
   - El archivo cae en ~/Downloads/accounts_enriched.csv

3. Upload a SharePoint
   - Navega a https://<tenant>.sharepoint.com/sites/<site>/Documents/CDT/inbox/
   - Drag-and-drop del accounts_enriched.csv del Downloads a la ventana
     del browser
   - SharePoint sube el archivo (usando la sesión auth del operador)
   - El operador puede cerrar la pestaña — el upload está hecho

4. Confirmación automática
   - Power Automate dispara en segundos
   - Procesa las filas (~10–60 s para 500 filas)
   - El flow postea en Teams al operador: "CDT ingest done — 487 created,
     0 failed, file: accounts_enriched.csv from 2026-05-04"
   - Si hubo fallas: el mensaje incluye los Titles que no se crearon y el
     archivo se mueve a /CDT/failed/ — el operador investiga (ver §3.11)

5. (opcional) Si el operador necesita los demás CSVs (sites, findings,
   validation_issues) en SP también, los sube a /CDT/inbox/ — pero NO
   disparan el flow porque el filter de §3.9 sólo matchea
   accounts_enriched.csv. Listas hermanas son v0.7+ (ver §3.12).
```

### 3.9 Power Automate flow

El flow vive en la cuenta personal del operador en `make.powerautomate.com`. Se exporta como `.zip` y se versiona en `cdt-scanner/docs/power-automate/cdt-ingest.zip` para poder re-importarlo si se borra o si lo construye otro operador.

**Trigger:** SharePoint → "When a file is created (properties only)" — connector estándar Free.

| Campo | Valor |
|---|---|
| Site Address | `https://<tenant>.sharepoint.com/sites/<site>` |
| Library Name | Documents (o el nombre interno de la library del site) |
| Folder | `/CDT/inbox` |
| Include Nested Items | No (los archivos llegan directo a `/inbox`, no a subfolders) |

**Trigger condition (filtra para sólo `accounts_enriched.csv`):**

```
@endsWith(triggerOutputs()?['body/{Name}'], 'accounts_enriched.csv')
```

**Steps:**

1. **Get file content** — referenciando el file ID del trigger.
2. **Compose: lines** → `split(replace(body('Get_file_content'), decodeUriComponent('%0D'), ''), decodeUriComponent('%0A'))`. Limpia CR antes de split por LF (CDT escribe LF; algunos browsers/OS pueden alterar al pasar por copiar/pegar manual).
3. **Compose: header_line** → `first(outputs('lines'))`.
4. **Compose: data_lines** → `skip(outputs('lines'), 1)`.
5. **Initialize variable: `failures`** (Array, vacío).
6. **Apply to each (data line):**
    - Skip si la línea está vacía (líneas finales).
    - **Compose: cells** → ver §3.10 (parser de CSV con quoting).
    - **Create item** en list `Cloud Accounts SOLA FY2026 v2`. Mapeo 1:1 por índice de columna (orden del CSV es exactamente el de v0.4 §3.3).
    - **Configure run after**: aún si "Create item" falla (`has failed`, `is skipped`), el flow continúa. Un step posterior captura `actions('Create_item')?['outputs']?['statusCode']`; si no es 201 hace `append to array variable failures`.
7. **Condition: `length(variables('failures')) == 0`?**
    - **Sí** → "Move file" → destination `/CDT/processed/<YYYY-MM-DD>_<run_id>/`. Folder de destino calculable de `triggerOutputs()?['body/{LastModified}']` o de la fecha actual.
    - **No** → "Move file" → `/CDT/failed/<YYYY-MM-DD>_<run_id>/` + "Post message in a chat or channel" (Teams) al operador con el conteo y los Titles que fallaron.

**Cero steps Premium en el flow.** Connectors SharePoint y Teams ambos en el plan Free.

### 3.10 Parser de CSV en el flow

El CSV de CDT respeta una convención que el flow puede asumir sin parser sofisticado:

- Encoding UTF-8 sin BOM.
- Newline LF.
- Quoting: sólo cuando una celda contiene `,`, `"` o newline. Citado con `"…"` y `"` internas escapadas como `""`.
- Las únicas columnas que pueden tener comas embebidas son `OpportunityRationale`, `WAFTool` y `Message`.

Power Automate Free no tiene step nativo de "Parse CSV". Patrón conocido (válido para el subset de quoting de CDT):

1. Reemplazar literales `","` por un placeholder único — así `","` deja de ser un separador.
2. Reemplazar las comas restantes por otro placeholder — todas las comas que aún están son separadores válidos.
3. Hacer split por placeholder, luego revertir cada placeholder a su carácter original dentro de cada celda.

Detalle completo (corner cases, trim de quotes externos, escape de `""`, manejo de líneas con newlines embebidas si llegaran a aparecer) en `cdt-scanner/docs/power-automate/csv-parser.md`. El detalle vive fuera del spec porque cambia con cada iteración del flow; el spec garantiza el **contrato del CSV** (encoding, quoting, orden de columnas) y el flow se adapta a él.

**Test del parser:** se commitea `tests/fixtures/sharepoint/sample_with_quoted_commas.csv` con casos canónicos:

- Fila sin comas internas.
- Fila con coma en `OpportunityRationale`.
- Fila con `"` interna que requiere escape `""`.
- Fila con celda vacía.

Antes de mergear cambios al flow, el operador lo dispara manualmente sobre ese fixture (subiéndolo a `/CDT/inbox/` apuntando a una List de prueba) y verifica que las filas aparecen correctamente.

### 3.11 Manejo de fallas

| Falla | Detección | Acción del flow | Acción del operador |
|---|---|---|---|
| Commit-back falla en GH Actions (push rechazado, merge conflict) | Step rojo | n/a | Re-correr el workflow. Si persiste: revisar la rama `outputs` por commits inesperados (no debería haberlos — sólo el bot escribe ahí). El artifact sigue disponible como red de seguridad. |
| Operador olvida hacer la subida | n/a | El flow nunca dispara | El operador chequea la rama `outputs` cuando se acuerda. La data no se pierde — vive en git indefinidamente. |
| Operador sube el archivo equivocado (e.g. `sites.csv` en vez de `accounts_enriched.csv`) | Trigger condition de §3.9 no matchea | Espera silenciosa | El operador borra el archivo de `/inbox/` y sube el correcto. |
| Trigger no dispara (latencia de SP) | El operador no ve el flow run en `make.powerautomate.com` dentro de ~2 min | n/a | Disparar el flow manualmente desde la UI de Power Automate apuntando al archivo. |
| Una fila falla `Create item` | Step en `Apply to each` captura `statusCode != 201`, append a `failures` | Continúa con el resto. Si quedan failures al final → archivo a `/failed/`. | Revisa Teams notification con los Titles. Causa típica: schema drift en la SP List (§20.3.9 de v0.4). |
| Todas las filas fallan | `length(failures) == length(rows)` | Mueve a `/failed/`. Teams: "0 created, N failed". | Investigar schema, corregir, mover el archivo de `/failed/` de vuelta a `/inbox/` para re-disparar. |
| El operador sube el mismo archivo dos veces | El flow corre dos veces. La List recibe duplicados (Title+Country aparecen dos veces). | n/a | El operador borra los items duplicados manualmente desde la UI de SP. **Mitigación post-MVP (v0.6):** agregar step "Get items" + "Update item if exists, Create otherwise" (upsert) — documentado en §3.12. |

**Triple redundancia preservada:**

1. **GitHub Actions artifact** (retención 30 días) — sobrevive aunque la rama `outputs` se corrompa.
2. **Rama `outputs` del repo** — sobrevive aunque artifacts expiren.
3. **SP List poblada** — el sistema de registro final.

### 3.12 Mejoras conocidas, deferidas a v0.6+

Documentadas para no perderlas; **no se implementan en v0.5**.

| Mejora | Por qué no ahora | Versión target |
|---|---|---|
| Notificación a Teams cuando el commit-back termina | Power Automate Free puede crear un webhook recibido por GH Actions, pero requiere setup adicional en el flow. El operador puede vivir con un calendar reminder por ahora. | v0.6 |
| Upsert (idempotencia) en el flow para tolerar re-uploads | "Get items by Title+Country" duplica la complejidad del flow. La mitigación manual (borrar dups en SP UI) es aceptable a 1 evento ocasional. | v0.6 |
| Subida automática de `sites.csv` y `findings.csv` a SP (lista hermana) | Requiere segunda List + segundo flow + segundo trigger filter. La data ya está accesible en git. | v0.7+ |
| Migración a la arquitectura de la "revisión 2" del spec (Graph + `Sites.Selected`) | Bloqueada por la restricción dura del entorno. Reabre **sólo si** el operador gana acceso de admin al tenant o el proyecto migra a un tenant propio. | (sin fecha — depende de contexto externo) |

### 3.13 Migración del MVP al post-MVP

Cutover lo dispara el operador cuando:

1. ≥ 4 corridas exitosas con paste manual de v0.4 §11.2.
2. Schema de la SP List estable (sin cambios en últimas 2 corridas — chequeo del runbook §20.3.9 de v0.4).
3. El operador tiene confirmado acceso de Edit a la library `Documents` del site SP destino.

Plan:

| Día | Acción |
|---|---|
| D-2 | Operador crea los folders `/CDT/inbox`, `/CDT/processed`, `/CDT/failed` en SharePoint vía web. Confirma que puede subir un CSV de prueba a `/CDT/inbox/` y que la version history del file aparece. |
| D-1 | Operador crea el flow en `make.powerautomate.com` siguiendo §3.9. Lo prueba subiendo manualmente un CSV de 2-3 filas a `/CDT/inbox/` y ve que las filas aparecen en una **List de prueba** (no la real todavía). Una vez verificado, repunta el flow a la List real. Exporta el flow como zip y lo commitea a `cdt-scanner/docs/power-automate/cdt-ingest.zip`. |
| D-1 | Mergear PR a `cdt-scanner` que agrega el step "Commit outputs to repo" del §3.7 a `scan.yml`, con los `permissions: contents: write` correspondientes. |
| D | Correr scan normal. Verificar que la rama `outputs` se popula con un nuevo folder. Operador hace download + upload manual. Verificar que el flow procesa, las filas aparecen en la List real, y el archivo se mueve a `/processed/`. |
| D+7 | Si dos corridas seguidas (D y D+7) procesaron sin issues, documentar como camino canónico post-MVP. Agregar al runbook (§20 de v0.4) una nueva subsección §20.6 "Post-MVP: descarga + upload manual + flow PA" con los pasos del §3.8. El paste manual de v0.4 §11.2 queda formalmente como **fallback**, no canónico. |

### 3.14 Plan de fallback

Si algo del camino post-MVP falla, el operador degrada graciosamente:

| Punto de falla | Fallback |
|---|---|
| Commit-back step de GH Actions | Operador descarga el **artifact** del run de GH Actions (camino MVP). |
| Rama `outputs` corrompida o inaccesible | Operador descarga el **artifact** del run de GH Actions. |
| Operador no quiere hacer upload manual ese día | Operador hace **paste manual en grid view** (camino MVP de v0.4 §11.2) usando el archivo de la rama `outputs` o del artifact. |
| Flow de Power Automate no dispara o procesa con errores | Operador cae a **paste manual en grid view** sobre la SP List, mismo archivo. |
| El operador pierde acceso al tenant M365 | n/a — es un cambio organizacional, no técnico. La data sigue en git intacta, esperando a que se restablezca el acceso o se identifique un nuevo operador. |

Tres caminos de salida (artifact, rama `outputs`, paste manual) y dos caminos de ingestión (upload + flow, paste manual). Cualquier combinación funciona.

---

## 4. Cierre de secciones reservadas / hueco de numeración

### 4.1 §13 (v0.4) — disuelto

§13 de v0.4 era "(reservado) — placeholder para futuras extensiones de pipeline operativo". El runbook (§20) cubrió todas las extensiones operativas previstas en el momento. **§13 queda formalmente cerrado como vacío**. La numeración no se reutiliza por estabilidad de referencias cruzadas (otros documentos pueden citar "v0.4 §13" sin riesgo).

### 4.2 §16 (v0.4) — disuelto

§16 de v0.4 era "Reservado". El contenido potencialmente destinado allí (detalle de la skill `cdt-scanner-dev`) ya fue absorbido por §17.5 en la propia v0.4. **§16 queda cerrado como vacío** con la misma justificación que §13.

### 4.3 §18 (v0.4) — gap de numeración

v0.4 salta de §17 a §19. Esto fue un error editorial detectado en v0.5 review. **No se renumera**: §19, §20 mantienen su número porque ya están citados desde otras secciones (§17.7, §19.7→CI, §20→runbook). La regla a futuro: huecos de numeración se conservan; sólo se renumera con bump de major version (`v1.0`).

### 4.4 Convención de numeración estable

A partir de v0.5, las reglas de numeración son:

1. Los números de sección son **estables**. Una sección puede vaciarse pero no renumerarse.
2. Una sección vacía se marca explícitamente como `## §N. (cerrada en vM.m)` para que las búsquedas en spec antiguas sigan funcionando.
3. Las nuevas secciones añadidas en delta versions usan números > el último de v0.4 (próximo libre: §21) — pero v0.5 no agrega ninguna por decisión del §1.

---

## 5. Detection rule pack v1 (cierra v0.4 §14)

Esta sección cierra el "narrative-only" de §14 de v0.4 con YAML literal listo para `config/detection_rules.yaml` y los archivos auxiliares. Lo que sigue son artefactos del repo `cdt-scanner`, no más prosa.

### 5.1 Estructura del archivo

```
cdt-scanner/
└── config/
    ├── detection_rules.yaml         ← §5.3–§5.7
    ├── nikto_skip.yaml              ← §5.8
    ├── rationale_templates.yaml     ← passthrough de v0.4 §7.5
    └── cdt.yaml                     ← passthrough de §2.10
```

`detection_rules.yaml` tiene un `version` semántico interno. La carga falla si el `engine_version` mínimo declarado en el YAML es mayor que el del runtime.

### 5.2 Versionado y validación

- Cada PR a `detection_rules.yaml` debe bumpar el campo `version` (semver). CI bloquea sin bump.
- `pydantic` modela el archivo en `src/cdt/detect/rule_models.py`. Carga con validación estricta — un `vendor` no listado en el enum o un `confidence` fuera de `{low, medium, high}` falla.
- Para cada regla con `signals[].when` referenciando un campo nuevo (header, cookie, body pattern), tiene que existir una fixture HTTP correspondiente en `tests/fixtures/http/<categoria>/`. Política de §19.8 de v0.4.

### 5.3 `detection_rules.yaml` — sección WAF

```yaml
# config/detection_rules.yaml
version: "1.0.0"
engine_version_min: "0.5.0"

scoring:
  primary_signal_points: 10
  secondary_signal_points: 5
  block_page_points: 7
  ip_range_match_points: 10
  reverse_dns_points: 7
  asn_match_points: 5
  cname_match_points: 6
  server_header_points: 2
  high_confidence_threshold: 10
  high_confidence_min_gap: 5

waf_vendors:

  - vendor: Cloudflare
    cdn_capable: true
    signals:
      - kind: primary
        when:
          all:
            - header: { name: "server", equals_ci: "cloudflare" }
            - header: { name: "cf-ray", regex: "^[a-f0-9]+-[a-z0-9]{3,4}$" }
      - kind: secondary
        when:
          any:
            - cookie: { name_in: ["__cfduid", "__cf_bm", "cf_clearance"] }
            - header: { name: "cf-cache-status", present: true }
            - cname: { suffix_in: [".cloudflare.net", ".cloudflare.com"] }
      - kind: block_page
        when:
          all:
            - status_in: [403, 429]
            - body_regex_any:
                - "Attention Required! \\| Cloudflare"
                - "Ray ID: <strong>[a-f0-9]+"
                - "cf-error-details"
    waf_active_indicators:
      - challenge_page: { regex: "cf_chl_cd|__cf_chl_jschl_tk__" }
      - header: { name: "cf-mitigated", present: true }
      - probe_403_on_dotenv: true   # GET /.env returns 403 with Cloudflare body

  - vendor: AWS_CloudFront_WAF
    cdn_capable: true
    signals:
      - kind: primary
        when:
          all:
            - header: { name: "via", regex: "[0-9.]+ [a-zA-Z0-9]+\\.cloudfront\\.net" }
            - header: { name: "x-amz-cf-id", present: true }
      - kind: secondary
        when:
          any:
            - header: { name: "x-cache", present: true }
            - header: { name: "x-amz-cf-pop", present: true }
            - cname: { suffix: ".cloudfront.net" }
      - kind: block_page
        when:
          all:
            - status_in: [403]
            - body_contains_any:
                - "Request blocked"
                - "<title>403 ERROR | CloudFront</title>"

  - vendor: Azure_FrontDoor_WAF
    cdn_capable: true
    signals:
      - kind: primary
        when:
          header: { name: "x-azure-ref", present: true }
      - kind: secondary
        when:
          any:
            - header: { name: "x-msedge-ref", present: true }
            - cname: { suffix_in: [".azurefd.net", ".azureedge.net"] }
      - kind: block_page
        when:
          all:
            - status_in: [403]
            - body_contains_any:
                - "Microsoft-Azure-Application-Gateway/"
                - "The request is blocked"

  - vendor: Akamai
    cdn_capable: true
    signals:
      - kind: primary
        when:
          any:
            - header: { name: "server", regex_ci: "^Akamai(GHost|NetStorage)" }
      - kind: secondary
        when:
          any:
            - header: { name_regex: "^x-akamai-" }
            - cookie: { name_in: ["ak_bmsc", "bm_sz", "_abck"] }
            - cname: { suffix_in: [".akamaized.net", ".edgekey.net", ".edgesuite.net"] }
      - kind: block_page
        when:
          any:
            - body_regex: "Reference #\\d+\\.[a-f0-9]+\\.\\d+\\.[a-f0-9]+"
            - body_contains: "Access Denied"
            - body_contains: "You don't have permission to access"

  - vendor: Fortinet_FortiWeb
    cdn_capable: false
    signals:
      - kind: primary
        when:
          header: { name: "server", regex_ci: "^FortiWeb" }
      - kind: secondary
        when:
          any:
            - cookie: { name: "FORTIWAFSID" }
            - header: { name: "x-fw-debug", present: true }
      - kind: block_page
        when:
          any:
            - body_contains: "<title>FortiWeb</title>"
            - body_contains: "Block Rule ID:"
            - body_contains: "/error_pages/"

  - vendor: Fortinet_FortiGate
    cdn_capable: false
    signals:
      - kind: primary
        when:
          header: { name: "server", regex_ci: "^FortiGate" }
      - kind: secondary
        when:
          cookie: { name: "FGTServer" }
      - kind: block_page
        when:
          any:
            - body_contains: "Blocked because of IPS sensor"
            - body_contains: "FortiGate Web Filter"

  - vendor: Imperva
    cdn_capable: true
    signals:
      - kind: primary
        when:
          any:
            - header: { name: "x-iinfo", present: true }
            - header: { name: "x-cdn", equals_ci: "incapsula" }
      - kind: secondary
        when:
          any:
            - cookie: { name_regex: "^(incap_ses_|visid_incap_)" }
            - cname: { suffix: ".incapdns.net" }
      - kind: block_page
        when:
          body_regex: "Request unsuccessful\\. Incapsula incident ID:"

  - vendor: F5_BIGIP_ASM
    cdn_capable: false
    signals:
      - kind: primary
        when:
          header: { name: "server", regex_ci: "^BigIP" }
      - kind: secondary
        when:
          cookie: { name_regex: "^(TS[0-9a-f]{7,8}=|BIGipServer)" }
      - kind: block_page
        when:
          any:
            - body_contains: "The requested URL was rejected"
            - body_regex: "Support ID: \\d+"

  - vendor: Sucuri
    cdn_capable: true
    signals:
      - kind: primary
        when:
          any:
            - header: { name: "x-sucuri-id", present: true }
            - header: { name: "x-sucuri-cache", present: true }
      - kind: secondary
        when:
          header: { name: "server", regex_ci: "^Sucuri/Cloudproxy" }
      - kind: block_page
        when:
          body_contains: "Access Denied - Sucuri Website Firewall"

  - vendor: Barracuda
    cdn_capable: false
    signals:
      - kind: primary
        when:
          header: { name: "server", regex_ci: "^Barracuda" }
      - kind: secondary
        when:
          cookie: { name: "barra_counter_session" }
      - kind: block_page
        when:
          body_contains: "You've been blocked"

  - vendor: Citrix_NetScaler
    cdn_capable: false
    signals:
      - kind: primary
        when:
          header: { name: "via", regex: "NS-CACHE" }
      - kind: secondary
        when:
          cookie: { name_regex: "^(citrix_ns_id|NSC_)" }

  - vendor: StackPath
    cdn_capable: true
    signals:
      - kind: primary
        when:
          header: { name: "x-sp-request-id", present: true }
      - kind: secondary
        when:
          cname: { suffix: ".stackpathdns.com" }

  - vendor: Wallarm
    cdn_capable: false
    signals:
      - kind: primary
        when:
          header: { name: "nemesida", present: true }
```

### 5.4 `detection_rules.yaml` — sección CDN

CDN se reporta independientemente del WAF. Si un vendor de §5.3 también es CDN (`cdn_capable: true`) y dispara, el campo `CDN` se setea con su nombre. Esta sección agrega CDNs que NO son WAFs (puro edge/cache).

```yaml
cdn_only_vendors:

  - vendor: Fastly
    signals:
      - any:
          - header: { name: "x-served-by", regex: "^cache-[a-z0-9]+" }
          - header: { name: "x-cache", regex: "^(HIT|MISS)" }
          - header: { name_regex: "^fastly-debug-" }
          - cname: { suffix_in: [".fastly.net", ".fastlylb.net"] }

  - vendor: KeyCDN
    signals:
      - header: { name: "server", regex_ci: "^keycdn-engine" }

  - vendor: BunnyCDN
    signals:
      - header: { name: "server", regex_ci: "^BunnyCDN" }

  - vendor: CDN77
    signals:
      - header: { name_regex: "^x-cdn77-" }

  - vendor: Google_Cloud_CDN
    signals:
      - all:
          - header: { name: "via", regex: "google" }
          - asn_in: [15169]
```

### 5.5 `detection_rules.yaml` — sección Cloud providers

Usado por `detect/cloud.py` siguiendo el árbol de §14.2 de v0.4.

```yaml
cloud_providers:

  - provider: AWS
    ip_ranges_url: "https://ip-ranges.amazonaws.com/ip-ranges.json"
    ip_ranges_format: aws_json
    rdns_patterns:
      - "*.compute.amazonaws.com"
      - "*.compute-1.amazonaws.com"
      - "*.cloudfront.net"
      - "*.amazonaws.com"
    asns: [14618, 16509, 14061]
    cname_suffixes:
      - ".amazonaws.com"
      - ".cloudfront.net"
    server_headers:
      - regex_ci: "^AmazonS3$"

  - provider: Azure
    ip_ranges_url: "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
    ip_ranges_format: azure_servicetags_json
    ip_ranges_refresh_strategy: monthly_manual_pin   # MS rota la URL cada mes
    rdns_patterns:
      - "*.cloudapp.net"
      - "*.cloudapp.azure.com"
      - "*.azurewebsites.net"
      - "*.azureedge.net"
      - "*.azurefd.net"
    asns: [8075, 8068]
    cname_suffixes:
      - ".azurewebsites.net"
      - ".azureedge.net"
      - ".azurefd.net"
    server_headers:
      - regex_ci: "^Microsoft-IIS/"
        confidence_modifier: 0.5    # IIS solo no es señal fuerte; combina con Azure headers

  - provider: GCP
    ip_ranges_url: "https://www.gstatic.com/ipranges/cloud.json"
    ip_ranges_format: gcp_json
    rdns_patterns:
      - "*.googleusercontent.com"
      - "*.1e100.net"
      - "*.bc.googleusercontent.com"
    asns: [15169]
    cname_suffixes:
      - ".googleapis.com"
      - ".appspot.com"
    server_headers:
      - regex_ci: "^(Google Frontend|gws)$"

  - provider: OCI
    ip_ranges_url: "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"
    ip_ranges_format: oci_json
    rdns_patterns:
      - "*.oraclecloud.com"
      - "*.oraclevcn.com"
    asns: [31898, 63775]
    cname_suffixes:
      - ".oraclecloud.com"

  - provider: Cloudflare
    role: edge_only        # no se cuenta como hyperscaler para Complexity
    ip_ranges_urls:
      - "https://www.cloudflare.com/ips-v4"
      - "https://www.cloudflare.com/ips-v6"
    ip_ranges_format: text_cidrs
    rdns_patterns:
      - "*.cloudflare.com"
      - "*.cloudflaressl.com"
    asns: [13335]
    cname_suffixes:
      - ".cloudflare.com"
      - ".cloudflare.net"

  - provider: Fastly
    role: edge_only
    ip_ranges_url: "https://api.fastly.com/public-ip-list"
    ip_ranges_format: fastly_json
    rdns_patterns:
      - "*.fastly.net"
      - "*.fastlylb.net"
    asns: [54113]

  - provider: Akamai
    role: edge_only
    ip_ranges_url: null    # Akamai no publica
    rdns_patterns:
      - "*.akamaiedge.net"
      - "*.edgekey.net"
      - "*.edgesuite.net"
      - "*.akamaized.net"
    asns: [20940, 16625, 16702]
    cname_suffixes:
      - ".akamaiedge.net"
      - ".edgekey.net"
      - ".edgesuite.net"
      - ".akamaized.net"

  - provider: Alibaba
    asns: [45102]

  - provider: IBM
    asns: [58779, 36351]

datacenter_fallback:
  description: |
    Si ningún provider matchea pero la IP pertenece a un ISP/telco regional
    (Telefónica, Claro, Movistar, CANTV, CNT, etc.), se asigna
    CloudProvider="datacenter" con anotación del ASN org en sites.csv.
  asn_orgs_treated_as_datacenter:
    - "Telefonica"
    - "Claro"
    - "Movistar"
    - "CANTV"
    - "CNT"
    - "Entel"
    - "Telmex"
    - "GTD"
```

### 5.6 `detection_rules.yaml` — sección CMS / framework

```yaml
cms:

  - name: WordPress
    signals:
      - any:
          - meta_generator_regex: "^WordPress\\s+(\\d+\\.\\d+(\\.\\d+)?)"
          - body_path_present_any: ["/wp-content/", "/wp-includes/", "/wp-json/"]
          - cookie: { name_regex: "^wordpress_logged_in_" }
    version_extract:
      from: meta_generator
      regex: "WordPress\\s+(\\d+\\.\\d+(?:\\.\\d+)?)"

  - name: Drupal
    signals:
      - any:
          - header: { name: "x-generator", regex_ci: "^Drupal" }
          - body_path_present: "/sites/default/files/"
          - body_contains: "misc/drupal.js"
    version_extract:
      from: header
      header_name: "x-generator"
      regex: "Drupal\\s+(\\d+)"

  - name: Joomla
    signals:
      - any:
          - meta_generator_regex: "^Joomla!"
          - body_path_present: "/media/jui/"

  - name: Magento
    signals:
      - any:
          - cookie: { name: "X-Magento-Vary" }
          - body_path_present: "/skin/frontend/"
          - body_contains: "Magento_Ui/"

  - name: Shopify
    signals:
      - any:
          - header: { name_regex: "^x-shop(id|ify-)" }
          - cname: { suffix: ".myshopify.com" }

  - name: Wix
    signals:
      - any:
          - meta_generator_regex: "^Wix\\.com Website Builder"
          - body_contains: "static.wixstatic.com"

  - name: Squarespace
    signals:
      - header: { name: "x-served-by", regex_ci: "squarespace-edge" }

  - name: Ghost
    signals:
      - any:
          - meta_generator_regex: "^Ghost\\s"
          - body_path_present: "/ghost/"
    version_extract:
      from: meta_generator
      regex: "Ghost\\s+(\\d+\\.\\d+(?:\\.\\d+)?)"

  - name: Strapi
    signals:
      - header: { name: "x-powered-by", equals_ci: "Strapi" }

  - name: Sitecore
    signals:
      - any:
          - cookie: { name: "SC_ANALYTICS_GLOBAL_COOKIE" }
          - body_path_present: "/sitecore/"

frameworks:

  - name: Django
    signals:
      - all:
          - cookie: { name_in: ["csrftoken", "sessionid"] }
          - any:
              - header: { name: "x-frame-options", equals_ci: "DENY" }
              - body_contains: "csrfmiddlewaretoken"

  - name: Rails
    signals:
      - any:
          - cookie: { name_regex: "^_.*_session$" }
          - header: { name: "x-powered-by", regex_ci: "Phusion Passenger" }

  - name: Laravel
    signals:
      - cookie: { name_in: ["laravel_session", "XSRF-TOKEN"] }

  - name: Express
    signals:
      - header: { name: "x-powered-by", equals_ci: "Express" }

  - name: ASP.NET
    signals:
      - any:
          - header: { name: "x-powered-by", regex_ci: "^ASP\\.NET" }
          - cookie: { name: "ASP.NET_SessionId" }

  - name: Next.js
    signals:
      - any:
          - header: { name_regex: "^x-nextjs-" }
          - body_path_present: "/_next/"

  - name: Nuxt
    signals:
      - body_contains: "__NUXT__"

web_servers:
  # Banner mapping. La presencia del banner es señal +2 (server_header_points).
  # La ausencia (oculta) cae al fallback de TLS fingerprint, fuera de este YAML.
  banner_map:
    - regex: "^nginx/(\\d+\\.\\d+\\.\\d+)"
      assign: "nginx/$1"
    - regex: "^Apache/(\\d+\\.\\d+\\.\\d+)"
      assign: "Apache/$1"
    - regex: "^Microsoft-IIS/(\\d+\\.\\d+)"
      assign: "IIS/$1"
    - regex: "^openresty/(\\d+\\.\\d+\\.\\d+(?:\\.\\d+)?)"
      assign: "openresty/$1"
    - equals: "LiteSpeed"
      assign: "LiteSpeed"
    - equals_ci: "Caddy"
      assign: "Caddy"
    - equals_ci: "cloudflare"
      assign: "-"     # CDN oculta el origen
```

### 5.7 `detection_rules.yaml` — sistema de puntaje cross-cutting

Ya declarado en `scoring:` al inicio de §5.3. Reglas operativas que el engine aplica:

```yaml
hypothesis_resolution:
  description: |
    Para cada categoría (waf_vendor, cloud_provider, cdn, cms, web_server),
    se acumulan puntos por hipótesis (un vendor candidato).
    Gana la hipótesis que cumpla AMBAS condiciones:
      total_points >= scoring.high_confidence_threshold
      total_points - second_best_points >= scoring.high_confidence_min_gap
    Si gana con esas dos: confidence = high.
    Si supera el threshold pero no la brecha: confidence = medium.
    Si no supera el threshold: confidence = low → campo = '-' o 'Further investigation needed'.

low_confidence_handling:
  field_default_when_low_confidence:
    WAF: "Further investigation needed"
    WAFVendor: "-"
    CMSFramework: "-"
    WebServer: "-"
    CDN: "-"
    CloudProvider: "-"
  emit_finding:
    code: "LOW_CONFIDENCE_<FIELD>"
    severity: "Low"
    message: "Hypothesis score below threshold or gap too small."
```

### 5.8 `nikto_skip.yaml`

```yaml
# config/nikto_skip.yaml
version: "1.0.0"

# Allowlist de dominios donde nikto NO se ejecuta (ni Tier 2 condicional, ni Tier 3),
# por sensibilidad legal/operacional. Acorde con v0.4 §14.5.2 y §12.13.

skip_suffixes:
  - ".gob.ec"
  - ".gob.pe"
  - ".gob.cl"
  - ".gov.py"
  - ".gub.uy"
  - ".gob.bo"
  - ".gob.ve"
  - ".mil.ec"
  - ".mil.pe"
  - ".mil.cl"
  - ".mil.py"
  - ".mil.uy"
  - ".mil.bo"
  - ".mil.ve"

skip_apex:
  # Bancos centrales de los 7 países (sólo apex; subdominios públicos siguen
  # escaneables con Tier 1/2 sin nikto, los financieros suelen tener WAF sólido).
  - "bce.fin.ec"          # Banco Central del Ecuador
  - "bcrp.gob.pe"         # Banco Central de Reserva del Perú
  - "bcentral.cl"         # Banco Central de Chile
  - "bcb.gob.bo"          # Banco Central de Bolivia
  - "bcp.gov.py"          # Banco Central del Paraguay
  - "bcu.gub.uy"          # Banco Central del Uruguay
  - "bcv.org.ve"          # Banco Central de Venezuela

# El operador puede agregar dominios ad-hoc por scan vía CLI:
#   cdt scan ... --no-nikto-for "cliente-sensible.com"
# (CLI flag a documentar en §2.4 si se decide agregar.)

on_skip:
  emit_finding: true
  finding_code: "NIKTO_SKIPPED_SENSITIVE_DOMAIN"
  severity: "Low"
  message: "Nikto skipped due to nikto_skip.yaml rule."
```

### 5.9 `rationale_templates.yaml`

Sin cambios respecto a v0.4 §7.5. Se cita aquí sólo para confirmar ubicación y contrato:

```yaml
# config/rationale_templates.yaml
templates:
  appsec_no_waf_cloud:
    condition: "RecommendsFortiAppSec=Yes AND WAF=No AND PublicCloud=Yes"
    template: "Sitio vivo sin WAF + infra en {PrimaryHyperScaler} → FortiAppSec Cloud WAF."
  appsec_displacement:
    condition: "RecommendsFortiAppSec=Yes AND WAF=Yes"
    template: "WAF {WAFVendor} detectado con riesgo {RiskScoreBand} → displacement con FortiAppSec."
  cnapp_multicsp:
    condition: "RecommendsFortiCNAPP=Yes"
    template: "{Complexity} ({ListCSPs}) → FortiCNAPP para posture cloud-native."
  fortiweb_onprem:
    condition: "RecommendsFortiWeb=Yes"
    template: "Infra fuera de cloud público sin WAF → FortiWeb VM/Appliance."
```

---

## 6. Ítems que NO cierra v0.5

Por disciplina del §1, v0.5 cierra **sólo** los ítems explícitamente diferidos por v0.4. Los siguientes siguen abiertos y se tratan en versiones futuras:

| Ítem | Estado | Versión objetivo |
|---|---|---|
| `cdt-operator` MCP server (v0.4 §15.4) | Pendiente | v0.6 |
| Reportes automáticos DOCX/PDF por cuenta (v0.4 §17.8) | Pendiente | v0.6+ |
| Deck comercial PPTX por cuenta de alto valor (v0.4 §17.8) | Pendiente | v0.6+ |
| Scheduling inteligente (v0.4 §17.8) | Pendiente | v0.6+ |
| Performance / load tests (v0.4 §19.9) | "opcional v0.5+" | v0.6 si la operación lo justifica |
| TLS / JA3 fingerprinting cuando server header está oculto (v0.4 §14.4.1) | "v0.5 detalla" — **NO entregado en v0.5** porque no estaba en la lista priorizada del usuario | v0.6 |

> **Nota sobre TLS fingerprinting:** v0.4 §14.4.1 prometió detalle "en v0.5". El usuario priorizó otros 4 ítems (CLI, Power Automate, gaps de numeración, detection rule pack) como "todos los diferidos". TLS fingerprinting queda explícitamente diferido a v0.6 con esta nota para no perderlo de vista.

---

## 7. Próximos pasos operativos

1. Mergear v0.5 al repo `cdt-spec` (o donde viva el spec).
2. Cuando arranque Fase 0 (v0.4 §17.7), Claude Code copia los YAML del §5 directo a `config/` del repo `cdt-scanner`.
3. La CLI de §2 sirve como contrato para los stubs de Fase 1.
4. La decisión de §3 entra al runbook (v0.4 §20) en una nueva subsección §20.6 **post-MVP**, una vez completadas 4 corridas exitosas con paste manual.

---

*Fin de v0.5.*
