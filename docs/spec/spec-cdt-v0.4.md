# Cloud Development Tool (CDT) — Spec v0.4

> **Estado:** Borrador consolidado. Reemplaza v0.3 tras cerrar preguntas abiertas e incorporar el cambio a `Title + Country + Website` y la nueva guía downstream (SharePoint + Power BI).
> **Autor:** Dave (eiz311@gmail.com)
> **Fecha:** 2026-04-23
> **Feature en scope:** F1 — Site Discovery & Exposure Scanner (Fortinet AppSec-oriented)

---

## 0. Cambios vs v0.3

| Área | v0.3 | v0.4 |
|---|---|---|
| Input | `Title, Country` (Website opcional) | **`Title, Country, Website`** obligatorios. Website vacío dispara modo Discover como fallback. |
| Google CSE | Discovery ciego | **Validate + Expand**. Valida que el Website corresponde a la entidad y busca dominios hermanos. Queries bajan de ~2/cuenta a 0-1. |
| Opportunity | Multi-valor pipe-separated | **Tres columnas booleanas**: `RecommendsFortiAppSec`, `RecommendsFortiWeb`, `RecommendsFortiCNAPP`. |
| Industry | Heurística propuesta | **Fuera de scope** (confirmado). |
| Guía SharePoint + Power BI | Mencionada como pipeline downstream | **Nueva §11** con fases de construcción post-tool. |
| `not_found.csv` | Cuentas sin website | **`validation_issues.csv`** (cuentas con URL sospechosa o muerta, volumen menor). |
| Arquitectura de ejecución | Linode 8 GB co-ubicado con AppSec Assessment | **Bifásica: Fase Dev persistente (2 GB Kali) + Fase Prod efímera (2 GB Ubuntu host + container Kali, Terraform apply/destroy por run)**. |
| Pipeline | Self-hosted runner fijo, rclone-OneDrive para input | **GitHub Actions hosted runner para Prod, CSV como parámetro del workflow_dispatch, output como artifact de GitHub Actions (operador descarga + paste a SharePoint Grid view)**. Sin rclone, sin dependencia OAuth M365 en el pipeline. |
| Tools de scan | Reglas propias + wafw00f library | **+ whatweb `-a 3`, nikto condicional con early termination (se activa solo si faltan CMS/WebServer/WAFVendor), python-Wappalyzer como primary tech stack**. |
| Nikto | En Tier 2 contra todos | **Condicional** en Tier 2 (solo si Tier 2 base no resolvió), con **early termination** al resolver campos objetivo o 5 min max. Completo solo en Tier 3. |
| Scope geográfico | No documentado | **7 países documentados** (Perú, Ecuador, Chile, Bolivia, Paraguay, Uruguay, Venezuela). El tool acepta otros países; uso fuera del scope es responsabilidad del operador. |
| Dominio / abuse-contact | `cdt.threathunt.cloud` propuesto | **Sin dominio propio**. User-Agent neutral. En Prod el abuse-contact es irrelevante (IP efímera). |
| Risk register | Ausente | **§12.12** con 14 riesgos catalogados y mitigaciones. |

---

## 1. Visión (resumen)

CDT automatiza el enriquecimiento manual que hoy haces con `whatweb`, `wafw00f`, `nikto`, Shodan y BuiltWith, para poblar una SharePoint List que luego alimenta un dashboard de Power BI. Entrega un reporte por corrida en CSV listo para copy-paste, con atribución de cloud, detección de WAF, postura de seguridad visible y recomendación de producto Fortinet.

```
accounts_in.csv (Title, Country, Website)
          │
          ▼
┌─────────────────────────────────────┐
│  CDT scan                           │
│                                     │
│  1. Validar Website (Google CSE)    │   ← confirma que URL corresponde a la entidad
│  2. Expandir dominios (crt.sh)      │   ← encuentra Website02..N subdominios vivos
│  3. Resolución DNS / IP             │
│  4. Atribución cloud                │   ← IP ranges AWS/Azure/GCP/OCI
│  5. Scan Tier 1/2 (/3 opt.)         │   ← wafw00f + headers + TLS
│  6. Scoring /15                     │
│  7. Mapeo a producto Fortinet       │   ← 3 booleanos
└─────────────────────────────────────┘
          │
          ▼
accounts_enriched.csv  (+ sites.csv + findings.csv + validation_issues.csv)
          │
          ▼
SharePoint List → Power BI
```

---

## 2. Alcance de F1 — Tiers de escaneo

| Tier | Qué hace | Footprint esperado | Requiere autorización |
|---|---|---|:---:|
| **Passive** | DNS, WHOIS, `crt.sh`, Shodan InternetDB, Censys, cloud IP ranges, ASN lookup. No toca al objetivo. | 0 requests al target | No |
| **Browser-like** (default) | `GET /` por esquema + `robots.txt` + TLS handshake + `wafw00f` (1–5 reqs) + `whatweb -a 3` (5–15 reqs). Si tras esto quedan campos sin resolver (`CMSFramework`, `WebServer`, o `WAFVendor` incierto): **nikto condicional** (`-Tuning b,a,5 -Pause 2`) con **early termination** al resolverlos. | **Caso default (campos resueltos sin nikto): ~10–20 reqs por sitio.** Caso fallback (nikto dispara): ~100–200 reqs con early termination, hasta ~400 en worst case (5 min max). | No |
| **DAST activo** | Todo lo anterior + `nikto` completo (`-Tuning 1,2,3,4,5,6,7,8,9,0,a,b,c,x` + `-maxtime 900`), crawling limitado, endpoints comunes, fingerprint profundo. | ~6 000–8 000 reqs por sitio | Sí (cuenta en `authorized.csv`) |

**Nikto condicional (§14.5.2 detalla):** en Tier 2, nikto **no se ejecuta por default**. Solo se activa si tras passive + browser-like + wafw00f + whatweb + Wappalyzer quedan uno o más de estos campos sin resolver con confianza ≥ medium: `WAFVendor`, `CMSFramework`, `WebServer`, `PublicCloud`. Cuando dispara, corre con `-Tuning b,a,5` (software ID + auth bypass + remote files) y un monitor streaming que corta apenas los campos objetivo se resuelven. Hard caps: `-maxtime 300` (5 min) y 400 requests. Resultado práctico: en la mayoría de cuentas nikto no corre; en ~20–30% que lo requieren, promedia 100–200 reqs en lugar de 6 000. Trade-off asumido explícitamente por el operador en §12.12.

---

## 3. Contrato de CSVs

### 3.1 Input — `accounts_in.csv`

| Columna | Requerido | Notas |
|---|:---:|---|
| `Title` | ✅ | Razón social. |
| `Country` | ✅ | Scope oficial de diseño: **Perú, Ecuador, Chile, Bolivia, Paraguay, Uruguay, Venezuela** (ver §12.13). El tool **acepta cualquier valor** — usar países fuera del scope es responsabilidad del operador. |
| `Website` | ✅ | Dominio o URL principal. Si viene vacío, el tool cae al modo Discover. |
| `SkipValidation` | opcional | `1` = saltar validación CSE. Útil cuando la lista ya fue curada. |

Ejemplo:

```csv
Title,Country,Website
(EC) Almacenes El Hierro,Ecuador,megahierro.com
TIPTI - GRUPO LA FAVORITA,Ecuador,https://www.tipti.market
AEROLANE LÍNEAS AÉREAS NACIONALES DEL ECUADOR S.A.,Ecuador,latamairlines.com/ec
```

**Cómo llega el CSV al pipeline:** en Fase Prod, como parámetro del `workflow_dispatch` en GitHub Actions (pegado en el textarea de la UI o vía `gh workflow run -f csv_content="$(cat accounts.csv)"`). En Fase Dev, SSH al Linode + bind-mount local. Ver §12.2 y §12.4.

### 3.2 Input auxiliar — `authorized.csv`

Cuentas que autorizan Tier 3 DAST. Sin este archivo, el Tier 3 no corre. Match por `(Title, Country)` exacto.

```csv
Title,Country
Banco Ejemplo S.A.,Perú
Retail XYZ,Chile
```

### 3.3 Output primario — `accounts_enriched.csv`

Una fila por cuenta. Columnas ordenadas para copy-paste directo a la SharePoint List.

| # | Columna | Tipo / valores | Ejemplo |
|--:|---|---|---|
| 1 | `Title` | Text (passthrough) | `(EC) Almacenes El Hierro` |
| 2 | `Country` | Choice | `Ecuador` |
| 3 | `PublicCloud` | Choice (`Yes` / `No` / `Further investigation needed`) | `Yes` |
| 4 | `Complexity` | Choice (`One CSP` / `Two CSP` / `Three CSP` / `Four CSP` / `-`) | `Two CSP` |
| 5 | `HasAWS` | Yes/No | `Yes` |
| 6 | `HasAzure` | Yes/No | `No` |
| 7 | `HasGCP` | Yes/No | `Yes` |
| 8 | `HasOCI` | Yes/No | `No` |
| 9 | `PrimaryHyperScaler` | Choice (`AWS` / `Azure` / `GCP` / `OCI` / `-`) | `AWS` |
| 10 | `Website01` | URL canónica primaria | `https://www.tipti.market` |
| 11 | `Website02` | URL secundaria | `https://app.tipti.market` |
| 12 | `Website03` | URL secundaria | `-` |
| 13 | `Website04` | URL secundaria | `-` |
| 14 | `Website05` | URL secundaria | `-` |
| 15 | `WAF` | Choice (`Yes` / `No` / `Further investigation needed`) | `Yes` |
| 16 | `WAFVendor` | Choice (`Cloudflare` / `AWS` / `Azure` / `Akamai` / `Fortinet` / `Imperva` / `F5` / `Sucuri` / `Other` / `-`) | `Fortinet` |
| 17 | `WAFTool` | Text | `FortiWeb (Fortinet) WAF` |
| 18 | `CMSFramework` | Text (`WordPress`, `Drupal`, …, `-`) | `WordPress` |
| 19 | `WebServer` | Text | `openresty/1.27.1.1` |
| 20 | `CDN` | Text | `Cloudflare` |
| 21 | `RiskScore` | Text | `MEDIUM (7/15)` |
| 22 | `RecommendsFortiAppSec` | Yes/No | `Yes` |
| 23 | `RecommendsFortiWeb` | Yes/No | `No` |
| 24 | `RecommendsFortiCNAPP` | Yes/No | `Yes` |
| 25 | `OpportunityRationale` | Text (≤ 160 chars) | `Multi-CSP sin WAF propio — FortiAppSec + FortiCNAPP.` |
| 26 | `ScannedAt` | ISO 8601 | `2026-04-23T14:32:11Z` |

**Nota:** los scan-attrs (columnas 15–21) describen `Website01`. El detalle por sitio vive en `sites.csv`.

### 3.4 Output secundario — `sites.csv`

Una fila por sitio descubierto. Join con `accounts_enriched.csv` por `(Title, Country)`.

| Columna | Tipo |
|---|---|
| `Title`, `Country` | FKs |
| `SiteURL` | Text |
| `IsPrimary` | 0/1 |
| `Alive` | 0/1 |
| `StatusCode` | Int |
| `IP` | Text |
| `ASN` | Int |
| `ASNOrg` | Text |
| `CloudProvider` | Text |
| `CDN` | Text |
| `WAFDetected` | 0/1 |
| `WAFVendor` | Text |
| `WAFTool` | Text |
| `CMSFramework` | Text |
| `WebServer` | Text |
| `TLSVersion` | Text |
| `CertIssuer` | Text |
| `CertExpiresAt` | Date ISO |
| `HSTS`, `CSP`, `XFO`, `XCTO`, `ReferrerPolicy`, `PermissionsPolicy` | 0/1 o valor |
| `ScanTier` | `passive` / `browser` / `dast` |
| `ScannedAt` | Datetime ISO |

### 3.5 Output de auditoría — `findings.csv`

| Columna | Notas |
|---|---|
| `Title`, `Country`, `SiteURL` | Identificadores |
| `FindingCode` | `MISSING_WAF`, `EXPIRED_CERT`, `WEAK_TLS`, `MISSING_HSTS`, `MISSING_CSP`, `EXPOSED_ADMIN`, `OUTDATED_CMS`, `FORTIAPPSEC_FIT`, … |
| `Severity` | `Low` / `Medium` / `High` / `Critical` |
| `Message` | Humano-legible |
| `Evidence` | Snippet — nunca payloads ni credenciales |

### 3.6 Output de problemas — `validation_issues.csv`

Cuentas cuyo Website es sospechoso o el discovery falló.

| Columna | Notas |
|---|---|
| `Title`, `Country` | Passthrough |
| `ProvidedWebsite` | Lo que vino en el input (o vacío si modo Discover) |
| `Issue` | `DEAD_DOMAIN` / `POSSIBLE_MISMATCH` / `PARKED_DOMAIN` / `INVALID_URL` / `NO_RESULTS` / `LOW_CONFIDENCE` / `QUOTA_EXCEEDED` |
| `Suggestion` | URL alternativa sugerida si la hay |
| `TopCandidates` | Top 3 candidatos con score (para modo Discover) |

El operador revisa este CSV, corrige en `accounts_in.csv` y re-ejecuta.

---

## 4. Validación y expansión de Website

### 4.1 Tres modos de operación

El tool decide por fila según qué venga en el input:

| Modo | Entrada | Acciones | Queries CSE |
|---|---|---|---|
| **Validate + Expand** (default) | `Website` poblado | Validación ligera → scan primario → expansión via `crt.sh` → scan secundarios | 0-1 |
| **Discover + Expand** (fallback) | `Website` vacío | Discovery via CSE → scan primario → expansión via `crt.sh` → scan secundarios | 2-3 |
| **Scan-only** | `Website` poblado + `SkipValidation=1` | Va directo a scan. Para listas ya curadas. | 0 |

Un mismo CSV puede mezclar filas de los tres modos.

### 4.2 Validación del Website provisto

Pipeline corto, barato:

1. **Parse y normalización**: acepta `acme.com`, `https://acme.com`, `https://www.acme.com/ruta`. Normaliza a `{scheme, apex, subdomain, path}`. Si no parsea, emite `INVALID_URL` a `validation_issues.csv`.
2. **Resolución DNS**: si no resuelve, emite `DEAD_DOMAIN`.
3. **HEAD request** (Tier 2): si timeout o 5xx en todos los reintentos, emite `DEAD_DOMAIN`. Si responde pero landing page es genérica de parking (Sedo, GoDaddy Parked, Namecheap parking), emite `PARKED_DOMAIN`.
4. **Validación semántica CSE** (solo si la página viva no contiene el `Title` en `<title>`, `<meta og:site_name>` o `<h1>`):
   - Query: `"<Title>" site:<apex>`
   - Si 0 resultados → emite `POSSIBLE_MISMATCH` con sugerencia del CSE sobre qué dominio sí matchea el Title.
   - Si ≥ 1 resultado → **confirmado**, scan procede.
5. **Si todo OK**: scan primario y se pasa a expansión.

### 4.3 Expansión a `Website02..05` via `crt.sh`

Sin costo CSE. `crt.sh` es un servicio público que devuelve todos los certificados TLS históricos emitidos para un dominio.

1. Query a `https://crt.sh/?q=<apex>&output=json`
2. Extraer todos los `common_name` y `name_value` únicos.
3. **Filtrar**:
   - Solo subdominios del apex (descartar wildcards crudos `*.acme.com`, descartar cross-domain).
   - Descartar mailservers: `mx*`, `mail*`, `smtp*`, `imap*`, `pop*`.
   - Descartar assets: `cdn*`, `static*`, `assets*`, `media*`, `img*`.
   - Descartar env no productivos: `*.dev.*`, `*.staging.*`, `*.test.*`, `*.uat.*`, `*.qa.*`.
4. **Probar vida** (Tier 2 GET) a los sobrevivientes, con paralelismo acotado (ver §9).
5. **Rankear** los vivos: `www` > `app` > `portal` > `tienda` > `shop` > `api` > `admin` > `secure` > resto alfabético.
6. **Asignar** a `Website02..05`. Resto solo a `sites.csv`.

### 4.4 Modo Discover (fallback)

Cuando `Website` llega vacío. Query CSE con filtro ccTLD, puntaje heurístico (ver §4.3 del v0.3). Si confianza alta → continúa como Validate mode. Si baja → `validation_issues.csv` con `LOW_CONFIDENCE` y top 3 candidatos.

### 4.5 Configuración (`config/discovery.yaml`)

```yaml
discovery:
  provider: google_cse
  api_key_env: GOOGLE_CSE_API_KEY
  engine_id_env: GOOGLE_CSE_ENGINE_ID
  cache_ttl_hours: 168            # 7 días
  validate_mode:
    max_queries_per_account: 1
    skip_if_title_in_landing: true
  discover_mode:
    queries_per_account: 2
    min_confidence_score: 6
    min_confidence_gap: 3
  blacklisted_domains:
    - linkedin.com
    - facebook.com
    - paginasamarillas.com
    - crunchbase.com
    - bloomberg.com
    - emis.com
    - zoominfo.com
    - dnb.com
```

---

## 5. Arquitectura efímera (sin cambios)

- SharePoint es el system of record. CDT no persiste datos de scan.
- Al final de la corrida solo quedan: CSV de salida + logs rotables (`~/.cdt/logs/<date>.jsonl`, 30 días) + cache pública de IP ranges y discovery (regenerable).
- `--dry-run` valida el input sin ejecutar scans.

---

## 6. Rúbrica de `RiskScore` /15 (sin cambios vs v0.3)

| Señal | Puntos |
|---|:---:|
| Sitio vivo y expuesto | +1 (baseline) |
| No WAF ni CDN con función de WAF | +3 |
| Cert TLS expirado o <30 días | +2 |
| TLS <1.2 habilitado | +2 |
| Falta HSTS | +1 |
| Falta CSP | +1 |
| Falta XFO (o equivalente en CSP) | +1 |
| Server header con versión CVE-conocida (Tier 3) | +2 |
| Panel admin/login expuesto sin protección (Tier 3) | +1 |
| CMS outdated con CVE (Tier 3) | +1 |
| **Total máximo** | **15** |

**Bandas:** `LOW` 1–5 • `MEDIUM` 6–9 • `HIGH` 10–12 • `CRITICAL` 13–15. Formato CSV: `"MEDIUM (7/15)"`.

### 6.1 Modificador por sitios secundarios

Si cualquiera de `Website02..05` presenta `MISSING_WAF` y el primario está protegido, el score de la cuenta sube en `+1` (bloqueado al máximo de 15). Se refleja en `findings.csv` con código `SECONDARY_SITE_EXPOSED`.

---

## 7. Recomendación de productos Fortinet (columnas booleanas)

### 7.1 Portafolio

| Producto | Rol |
|---|---|
| **FortiAppSec** | Cloud WAF SaaS. Para clientes en cloud público. |
| **FortiWeb** | WAF como VM o Appliance. Para on-prem o cloud privada. |
| **FortiCNAPP** | Cloud-Native App Protection. Para cuentas con 2+ hyperscalers. |

### 7.2 Columnas de salida

| Columna | Tipo | Valores |
|---|---|---|
| `RecommendsFortiAppSec` | Yes/No | |
| `RecommendsFortiWeb` | Yes/No | |
| `RecommendsFortiCNAPP` | Yes/No | |
| `OpportunityRationale` | Text | Explicación breve |

### 7.3 Reglas de decisión

```
Default:
  RecommendsFortiAppSec = No
  RecommendsFortiWeb    = No
  RecommendsFortiCNAPP  = No

# WAF missing o competidor con HIGH+ risk
Si WAF = No  OR  (WAF=Yes AND WAFVendor != Fortinet AND RiskScore >= HIGH):
    Si PublicCloud = Yes:
        RecommendsFortiAppSec = Yes
    Sino (PublicCloud = No o Further investigation):
        RecommendsFortiWeb = Yes

# Multi-CSP siempre agrega FortiCNAPP
Si Complexity in {Two CSP, Three CSP, Four CSP}:
    RecommendsFortiCNAPP = Yes

# Excepción: WAF Fortinet ya en place + RiskScore LOW => no recomendación
Si WAFVendor = Fortinet AND RiskScore banda = LOW AND Complexity = One CSP:
    Todos = No
```

### 7.4 Ejemplos aplicados

| Cuenta | `WAF` | `WAFVendor` | `Cloud` | `Complexity` | Risk | `FortiAppSec` | `FortiWeb` | `FortiCNAPP` |
|---|---|---|---|---|---|:---:|:---:|:---:|
| Almacenes El Hierro | No | - | FIM | One | LOW | **Yes** | No | No |
| TIPTI (Fortinet WAF, multi-CSP) | Yes | Fortinet | Yes | Two | - | No | No | **Yes** |
| Banco on-prem sin WAF | No | - | No | - | MED | No | **Yes** | No |
| Retail multi-CSP con Akamai | Yes | Akamai | Yes | Three | HIGH | **Yes** | No | **Yes** |
| Cliente 100% Fortinet single-CSP | Yes | Fortinet | Yes | One | LOW | No | No | No |

### 7.5 Plantillas de `OpportunityRationale`

En `config/rationale_templates.yaml`:

```yaml
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

Cuando aplican varios, se concatenan separados por `; `.

---

## 8. Pipeline de scan (resumen)

```
for account in accounts_in.csv:
    mode = pick_mode(account)                          # validate / discover / scan-only
    site = validate_or_discover(account, mode)
    if site is None: write_validation_issues(); continue

    ip, asn, asn_org = resolve(site)
    aws, azure, gcp, oci, primary = attribute_cloud(ip, asn_org, cdn_signals)
    waf_detected, waf_vendor, waf_tool = detect_waf(site, tier)
    stack = fingerprint(site, tier)
    tls = check_tls(site)
    headers = inspect_headers(site)

    secondary_sites = expand_via_crt_sh(apex_of(site))
    scan_secondaries(secondary_sites)                  # tier 2

    score = score_risk(primary + secondaries)
    recs = map_products(public_cloud, complexity, waf, waf_vendor, score)
    rationale = render_rationale(recs, attrs)

    write_row(account, ..., recs, rationale)
    for s in [primary] + secondary_sites:
        write_site_row(s)
```

Concurrencia asyncio (default 20 en paralelo), rate-limit 2 RPS por dominio, timeout 15s, 3 reintentos exponenciales.

---

## 9. Pipeline downstream — AppSec Maturity Assessment

CDT emite opcionalmente `assessment_invites.csv` con cuentas priorizadas para invitar al quiz de `appsec.threathunt.cloud`. Columnas:

| Columna | Notas |
|---|---|
| `Title`, `Country` | Passthrough |
| `InviteLink` | URL con `#s=<base64>` pre-cargado con contexto |
| `RecommendsFortiAppSec`, `RecommendsFortiWeb`, `RecommendsFortiCNAPP` | Passthrough |
| `Priority` | `P0` / `P1` / `P2` según (RiskScore banda, número de productos recomendados) |

---

## 10. CLI propuesta (detalle en v0.5)

```bash
# Corrida típica
cdt scan --in accounts_in.csv --tier browser --out ./out/

# Flags globales
--tier {passive|browser|dast}    # default: browser
--authorized authorized.csv       # requerido para tier dast
--concurrency N                   # default: 20
--country "Ecuador,Chile"         # filtra por país
--skip-expansion                  # salta crt.sh (solo Website01)
--max-sites-per-account N         # default: 5
--dry-run                         # valida input sin escanear
--out DIR                         # carpeta de salida

# Utilidades
cdt validate --in accounts_in.csv             # valida schema del input
cdt diff --baseline run1/ --current run2/    # diffs entre corridas
cdt doctor                                    # chequea API keys, cachés, conectividad
```

---

## 11. Guía de construcción downstream — SharePoint List Online + Power BI Service (100% SaaS)

**Fase 2.** Se ejecuta una vez el tool esté funcional y hayas validado una primera corrida. Toda esta fase ocurre **exclusivamente en el navegador dentro de Microsoft 365**: sin Power BI Desktop, sin servidores, sin instalaciones locales. Stack de la fase:

- SharePoint List Online (M365)
- Power BI Service Pro (`app.powerbi.com`)
- Power Automate (M365) para automatización opcional
- Excel Online para *staging* del paste del CSV cuando haga falta

### 11.1 Crear la SharePoint List Online

**Ruta:** `https://<tenant>.sharepoint.com/sites/<site>` → **+ New** → **List** → **Blank list**.

Nombre sugerido: `Cloud Accounts SOLA FY2026 v2`.

**Columnas**, en el orden del §3.3 (se agregan desde **+ Add column** en la vista de la lista):

| Columna CDT | Tipo en SharePoint Online | Notas |
|---|---|---|
| `Title` | Single line of text | Ya viene default como la primera columna. |
| `Country` | Choice | Valores: Ecuador, Perú, Chile, Paraguay, Uruguay, Bolivia, Venezuela. Activa *Display choices using: Dropdown*. |
| `PublicCloud` | Choice | Yes, No, Further investigation needed |
| `Complexity` | Choice | One CSP, Two CSP, Three CSP, Four CSP, - |
| `HasAWS`, `HasAzure`, `HasGCP`, `HasOCI` | Yes/No | |
| `PrimaryHyperScaler` | Choice | AWS, Azure, GCP, OCI, - |
| `Website01`…`Website05` | Hyperlink | SharePoint Online admite "Hyperlink" como tipo nativo. |
| `WAF` | Choice | Yes, No, Further investigation needed |
| `WAFVendor` | Choice | Lista del §3.3 #16 |
| `WAFTool` | Single line of text | |
| `CMSFramework`, `WebServer`, `CDN` | Single line of text | |
| `RiskScore` | Single line of text | Formato `"MEDIUM (7/15)"` |
| `RecommendsFortiAppSec`, `RecommendsFortiWeb`, `RecommendsFortiCNAPP` | Yes/No | |
| `OpportunityRationale` | Multiple lines of text (plain) | |
| `ScannedAt` | Date and time | |

**Indexar** `Title` y `Country` desde **Settings → List settings → Indexed columns**. Sin esto, las listas grandes se vuelven lentas para filtros de Power BI.

**Lista hermana** `Cloud Sites SOLA FY2026` con el schema del §3.4 si se quiere drill-down por sitio.

### 11.2 Importar el CSV a la lista (decisión MVP: artifact + Grid view paste)

**Camino primario (MVP) — Manual desde el artifact de GitHub Actions:**

1. El operador entra a `github.com/<org>/cdt-scanner/actions` → click en la run terminada.
2. En la sección **Artifacts** (parte inferior de la página del run), descarga `cdt-scan-<run_id>.zip`.
3. Descomprime y abre `accounts_enriched.csv` con Excel Online (subiendo a OneDrive personal o usando el visor inline) o Excel Desktop si lo tiene local.
4. Selecciona todas las filas (sin la cabecera) → Copy.
5. Abre la SharePoint List `Cloud Accounts SOLA FY2026 v2` en navegador → botón **Edit in grid view**.
6. Click en la primera celda vacía debajo de la última fila → Paste. SharePoint Online acepta tab-separated nativamente; las celdas se llenan en orden de columnas (por eso el orden del CSV es importante, ver §3.3).
7. **Exit grid view** para commit.
8. Si se usa la lista hermana `Cloud Sites SOLA FY2026`, repetir con `sites.csv`.

Tiempo estimado por corrida: **2-3 minutos**. Aceptable para cadencia semanal.

**Por qué este camino y no rclone/Power Automate automático:** los tenants M365 corporativos típicamente bloquean OAuth de clientes "unmanaged" como rclone vía Conditional Access policies, app consent gating y restricciones de device compliance. El path artifact-manual no requiere aprobaciones de IT corporativo, OAuth tokens, ni client registrations en Azure AD. Funciona en cualquier tenant.

**Caminos alternativos (post-MVP, si la política del tenant lo permite):**

| Opción | Requisito | Status |
|---|---|---|
| **B — Email → Power Automate → SP** | Casilla operacional + flow con trigger "When a new email arrives" (tier free) + GitHub envía email con CSV adjunto via SendGrid/Gmail SMTP | Evaluar post-MVP |
| **C — Power Automate HTTP trigger** | License Power Automate Premium ($15/user/mes) | Solo si la org ya tiene Premium |
| **D — Microsoft Graph API directo desde GH Actions** | App registration en Azure AD con `Sites.ReadWrite.All` + admin consent | Si IT corporativo aprueba |
| **E — Azure Blob Storage como buffer** | Subscription Azure separada o storage en tenant | Solo si hay overlap con Azure infra existente |

Cualquiera de B–E reemplazaría el paso manual del operador. Decidible después de validar MVP. Documentación de cada opción detallada irá en v0.5 cuando se tome la decisión.

### 11.3 Construir el dashboard en Power BI Service (sin Desktop)

**Ruta corta recomendada** aprovechando la integración nativa SP ↔ PBI:

1. Abre la SharePoint List en el navegador.
2. Botón **Integrate → Power BI → Visualize the list**. Esto crea automáticamente un dataset en Power BI Service conectado a la List y abre un report base con visuales sugeridos.
3. En el report abierto en `app.powerbi.com`, click **Edit** → entras al editor web de Power BI (capacidades acotadas vs. Desktop, pero suficientes para lo que necesitas).
4. Reemplaza los visuales autogenerados por los que te propongo en §11.4.
5. **Save** como `Cloud Accounts SOLA FY2026 Dashboard` en un Workspace Pro.

**Si necesitas data del sites CSV también:** desde el editor web haz **Get data → SharePoint Online List** → agrega la lista hermana `Cloud Sites SOLA FY2026`. Define la relación en el **Model view**: `Accounts[Title] + Accounts[Country] → Sites[Title] + Sites[Country]` (clave compuesta).

> **Limitación conocida:** el editor web no soporta **Calculated Columns** ni **Calculated Tables** tan flexibles como Desktop, pero **Measures** sí. Las medidas DAX del §11.4 funcionan en el editor web.

### 11.4 Medidas DAX (todas válidas en Power BI web editor)

```DAX
Total Accounts = COUNTROWS(Accounts)

Accounts with AWS   = CALCULATE([Total Accounts], Accounts[HasAWS] = "Yes")
Accounts with Azure = CALCULATE([Total Accounts], Accounts[HasAzure] = "Yes")
Accounts with GCP   = CALCULATE([Total Accounts], Accounts[HasGCP] = "Yes")
Accounts with OCI   = CALCULATE([Total Accounts], Accounts[HasOCI] = "Yes")

Multi-CSP Accounts = CALCULATE(
    [Total Accounts],
    Accounts[Complexity] IN {"Two CSP", "Three CSP", "Four CSP"}
)

Accounts without WAF = CALCULATE([Total Accounts], Accounts[WAF] = "No")

FortiAppSec Pipeline = CALCULATE([Total Accounts], Accounts[RecommendsFortiAppSec] = "Yes")
FortiWeb Pipeline    = CALCULATE([Total Accounts], Accounts[RecommendsFortiWeb]    = "Yes")
FortiCNAPP Pipeline  = CALCULATE([Total Accounts], Accounts[RecommendsFortiCNAPP]  = "Yes")

High Risk Accounts = CALCULATE(
    [Total Accounts],
    CONTAINSSTRING(Accounts[RiskScore], "HIGH") || CONTAINSSTRING(Accounts[RiskScore], "CRITICAL")
)
```

### 11.5 Páginas sugeridas del dashboard

1. **Overview** — tarjetas (Total Accounts, Multi-CSP, Sin WAF, High/Critical Risk), mapa de LATAM por país, donut de Complexity.
2. **Hyperscaler footprint** — barras horizontales de [AWS/Azure/GCP/OCI], matriz país × CSP, cuentas multi-CSP listadas.
3. **Protection posture** — pie de WAF (Yes/No/Further), barras por WAFVendor, heatmap de RiskScore por país.
4. **Fortinet Opportunity** — tarjetas de pipeline por producto, tabla filtrable con `Title, Country, Opportunity{Yes/No}*3, Rationale`, slicers por país y por RiskScore band.
5. **Drill-down por sitio** (si hay `Cloud Sites` list) — tabla de sitios secundarios expuestos, cert expirations próximos, headers faltantes.

### 11.6 Cadencia y refresh (en la nube)

- El dataset en Power BI Service tiene **refresh automático** desde SharePoint List cada ~1 hora por default (ajustable en los settings del dataset).
- Con licencia **Pro** tienes hasta 8 refreshes diarios programados. Suficiente.
- La primera vez que publiques, confirma credenciales de SharePoint en **Data source credentials** del dataset.

### 11.7 Sharing

Publicar el report en un **Workspace** (no "My Workspace") para que otros usuarios Pro puedan verlo y filtrarlo. Crear una **App** si quieres un empaquetado más consumible para el equipo comercial.

### 11.8 Qué hacemos juntos cuando toque

Sesión 1 (30 min): creo contigo la List paso a paso, cargamos el primer CSV, validamos que el grid acepte los tipos.

Sesión 2 (45 min): conectamos la List con Power BI Service vía "Visualize the list", agregamos las medidas DAX, armamos las 4-5 páginas.

Sesión 3 (opcional, post-MVP): evaluamos opciones B–E del §11.2 contra las políticas de tu tenant M365 y, si alguna pasa, montamos automatización (Email → Power Automate, Graph API, etc.).

Todo en navegador. Ningún paso requiere nada instalado.

---

## 12. Pipeline de ejecución — arquitectura bifásica

La operación vive bajo tres principios duros:

1. **Todo se dispara desde GitHub Actions.** Builds, tests, despliegues, corridas programadas, rollback. Nada manual en consola de Linode salvo emergencia.
2. **Cualquier modificación de infra se hace con Terraform.** Sin clicks en portales.
3. **La infra es desechable por diseño.** En régimen de producción, nada persiste entre runs salvo los artifacts de GitHub Actions (retención 30 días) y los items que el operador haya importado a SharePoint.

La arquitectura es **bifásica** para respetar la realidad del desarrollo:

| Fase | Propósito | Infra | Duración | Costo/mes |
|---|---|---|---|---|
| **Dev** | Iterar sobre el código, debug SSH, validar reglas contra sitios reales | Linode 2 GB persistente (Kali Rolling) | Semanas/meses | ~$14.50 |
| **Prod** | Operación estable post-MVP | Linode 2 GB efímero por run (Ubuntu host + container Kali) | ~60-75 min por run | ~$0.08-0.40 |

El cutover Dev → Prod se realiza cuando los criterios de §12.10 se cumplen.

### 12.1 Fase Dev — Linode persistente para iteración

Andamiaje para construir el tool. No es la arquitectura objetivo.

```
GitHub (cdt-scanner, cdt-infra)
     │  push main → CI build + test + image a GHCR (:dev)
     │  push main en cdt-infra → apply.yml → terraform apply (workspace cdt-dev-persistent)
     ▼
┌──────────────────────────────────────────────────┐
│ Linode 2 GB persistente (dev-cdt, Kali Rolling)  │
│                                                  │
│  ┌─────────────────────────────────────┐         │
│  │ Docker daemon                        │         │
│  │   └── CDT container (Kali-based)    │         │
│  │       whatweb, wafw00f, nikto       │         │
│  │       Python 3.12 + CDT codebase    │         │
│  └─────────────────────────────────────┘         │
│                                                  │
│  GH Actions self-hosted runner (systemd)         │
│  labels: [self-hosted, linode, cdt-dev]          │
│                                                  │
│  SSH abierto para debug manual (key-only)        │
│  IP pública estable (rotable con `terraform taint`) │
└──────────────────────────────────────────────────┘
```

**Uso típico:**
- Cambio de código: `git push` → CI build → imagen `:dev` en GHCR.
- Scan manual: `ssh dev-cdt → docker run ... cdt:dev scan ...` para investigar casos raros.
- Scan automático: `workflow_dispatch` scan.yml con `phase=dev` → el self-hosted runner en la VM ejecuta directamente sin provisionar nada nuevo.

**Limitaciones conscientes:**
- IP estable acumula reputación. OK para pruebas, no para operación continua.
- Si se quema: `terraform taint linode_instance.dev_cdt && terraform apply` rota en ~3 min.
- Acceso SSH abierto → hardening estándar (key-only, fail2ban, port custom, UFW allowlist).

### 12.2 Fase Prod — Linodes efímeros por run

Operación post-MVP. Cada run provisiona, escanea y destruye. Sin estado persistente.

```
┌─────────────────────────────────────────────────────────────┐
│ Operador (navegador o CLI)                                   │
│                                                              │
│  Opción A (UI):  github.com/<org>/cdt-scanner/actions        │
│                  → "Run workflow scan.yml"                   │
│                  → Pega contenido CSV en el textarea         │
│                  → Selecciona tier, click Run                │
│                                                              │
│  Opción B (CLI): gh workflow run scan.yml \                  │
│                    -f tier=browser \                         │
│                    -f csv_content="$(cat accounts.csv)"      │
│                                                              │
│  Opción C (cron): CSV versionado en inputs/recurring.csv    │
│                   del repo, workflow scheduled lo consume    │
└────────────────────────────┬────────────────────────────────┘
                             │ workflow_dispatch / schedule
                             ▼
┌─────────────────────────────────────────────────────────────┐
│ GitHub Actions hosted runner (ubuntu-latest, free tier)     │
│ Workflow: scan.yml (phase=prod)                              │
│                                                              │
│  1. Decodificar csv_content input → /tmp/accounts_in.csv    │
│     (o leer inputs/<file>.csv del repo si modo cron)        │
│  2. Restore cache (IP ranges, discovery) via actions/cache  │
│  3. terraform apply → provisiona Linode efímero              │
│  4. Espera SSH ready (~60-90s)                               │
│  5. SCP inputs + cache al VM                                 │
│  6. docker run cdt:latest en el VM (stream de logs)          │
│  7. SCP outputs de vuelta al runner                          │
│  8. Upload outputs como GitHub Actions artifact              │
│  9. Save cache (actions/cache)                               │
│  10. terraform destroy (always, incluso si pasos previos fallan) │
│                                                              │
│ Duración: ~60-75 min  Costo: ~$0.04-0.08 por run            │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│ Linode VM efímero — vida ~60-75 min                          │
│ g6-standard-1 (2 GB, $0.018/hr) — Ubuntu 24.04 minimal       │
│                                                              │
│  cloud-init instala Docker (~60-90s bootstrap)              │
│     │                                                        │
│     ▼                                                        │
│  Container CDT (ghcr.io/<org>/cdt:latest, base kali-rolling) │
│     whatweb + wafw00f + nikto + Python + CDT codebase       │
│                                                              │
│  IP pública: nueva cada run (Linode asigna aleatoria)        │
│  Al terminar: terraform destroy → VM + IP + disk eliminados │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
Salida única: **GitHub Actions artifact (zip)** con los CSVs.

El operador descarga el .zip desde la UI de GitHub Actions y pega manualmente las filas en la SharePoint List vía Grid view (~2-3 min por corrida, paso aceptado para MVP — ver §11.2).

```

**El input nunca se persiste en disco compartido.** Llega como parámetro del workflow (transiente en GitHub), se escribe a un tmpfs del runner, viaja por SCP al VM efímero, y se destruye junto con el VM. El artifact de GitHub tiene retención configurable (por default 90 días; recomendado 30 días por sensibilidad de la data).

**Por qué no rclone/OneDrive:** evaluamos rclone para automatizar la salida a OneDrive y de ahí a Power Automate, pero los tenants M365 corporativos típicamente bloquean OAuth de clientes "unmanaged" como rclone (Conditional Access policies, app consent gating, MFA sin app passwords). El path artifact-manual funciona en cualquier tenant sin necesidad de aprobaciones de IT corporativo y se puede automatizar más tarde post-MVP si la política del tenant lo permite (ver §11.2).

**Sensibilidad del `csv_content`:** el contenido queda visible en logs del run si se loguea directamente (no lo haremos). Se escribe a archivo sin print intermedio. Usuarios con acceso al repo pueden ver los parámetros de runs anteriores en la UI de Actions — considerarse al decidir quién tiene permiso `actions:read`.

**Beneficios operativos:**
- IP rota por run; cero acumulación de reputación hostil.
- Si nikto quema la IP, solo afecta la run actual.
- Abuse-contact casi irrelevante: complaints llegan después de que el VM se destruyó.
- Sin dominio propio requerido.
- Superficie de ataque persistente: **cero** (fuera de runs, no hay infra CDT arriba).

**Compromisos:**
- Cada run paga ~2 min de bootstrap.
- Terraform `apply/destroy` implica más lógica en el workflow que un simple SSH.

### 12.3 Repositorios y responsabilidades

| Repo | Contenido | Workflows |
|---|---|---|
| `cdt-scanner` | Código Python, `Dockerfile`, `config/*.yaml`, tests | `ci.yml`, `release.yml`, `scan.yml` |
| `cdt-infra` | Terraform (`*.tf`), módulos, políticas | `validate.yml`, `plan.yml`, `apply.yml` |

Separación deliberada: un repo no puede romper el otro. Quien puede cambiar infra no necesariamente cambia código scanner, y viceversa. Permisos granulares en GitHub.

### 12.4 Workflows de `cdt-scanner`

**`ci.yml` — on PR y push a `main`:**

1. `pip install -e .[dev]` + `ruff check` + `mypy` + `pytest --cov`
2. `docker build .` (smoke)
3. Si `main`: push imagen a `ghcr.io/<org>/cdt:dev` y `:main-<sha>`

**`release.yml` — on tag `v*.*.*`:**

1. Build multi-arch (`linux/amd64`, `linux/arm64`)
2. Push a `ghcr.io/<org>/cdt:<tag>` y `:latest`
3. GitHub Release con CHANGELOG

**`scan.yml` — inputs + phase switch:**

```yaml
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
        description: "Contenido CSV (pega aquí accounts_in.csv)"
        type: string
        required: false
      csv_file_in_repo:
        description: "Ruta a CSV committeado en el repo (alternativa a csv_content)"
        type: string
        required: false
        default: "inputs/recurring.csv"
      country_filter:
        description: "Filtrar por país (opcional)"
        type: string
        required: false
  schedule:
    - cron: '0 6 * * 1'  # lunes 06:00 UTC — usa csv_file_in_repo

concurrency:
  group: cdt-scan-${{ inputs.phase }}
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ${{ inputs.phase == 'dev' && fromJSON('["self-hosted","linode","cdt-dev"]') || 'ubuntu-latest' }}
    timeout-minutes: 90
    steps:
      - name: Checkout cdt-scanner
        uses: actions/checkout@v4

      - name: Resolve input CSV
        run: |
          mkdir -p ./in
          if [ -n "${{ inputs.csv_content }}" ]; then
            printf '%s' "${{ inputs.csv_content }}" > ./in/accounts_in.csv
          else
            cp "${{ inputs.csv_file_in_repo }}" ./in/accounts_in.csv
          fi
          # verifica encabezados mínimos
          head -1 ./in/accounts_in.csv | grep -q "Title,Country,Website" || {
            echo "CSV sin encabezados esperados"; exit 1; }

      # --- PHASE DEV (self-hosted runner sobre Linode persistente) ---
      - name: [DEV] Run scan on persistent Linode
        if: ${{ inputs.phase == 'dev' }}
        run: |
          docker pull ghcr.io/<org>/cdt:dev
          docker run --rm \
            -v "$PWD/in:/app/in:ro" \
            -v "$PWD/out:/app/out" \
            -v "$PWD/cache:/app/cache" \
            -e GOOGLE_CSE_API_KEY=${{ secrets.GOOGLE_CSE_API_KEY }} \
            -e GOOGLE_CSE_ENGINE_ID=${{ secrets.GOOGLE_CSE_ENGINE_ID }} \
            --user 1000:1000 --read-only --tmpfs /tmp \
            ghcr.io/<org>/cdt:dev \
            scan --in /app/in/accounts_in.csv --tier ${{ inputs.tier }} \
                 --country "${{ inputs.country_filter }}" --out /app/out/

      # --- PHASE PROD (ephemeral Linode provisionado por Terraform) ---
      - name: [PROD] Checkout cdt-infra
        if: ${{ inputs.phase == 'prod' }}
        uses: actions/checkout@v4
        with:
          repository: <org>/cdt-infra
          token: ${{ secrets.INFRA_TOKEN }}
          path: infra

      - name: [PROD] Setup Terraform
        if: ${{ inputs.phase == 'prod' }}
        uses: hashicorp/setup-terraform@v3
        with: { cli_config_credentials_token: ${{ secrets.HCP_TF_TOKEN }} }

      - name: [PROD] Restore cache
        if: ${{ inputs.phase == 'prod' }}
        uses: actions/cache@v4
        with:
          path: ./cache
          key: cdt-cache-${{ hashFiles('config/*.yaml') }}
          restore-keys: cdt-cache-

      - name: [PROD] Terraform apply (ephemeral VM)
        if: ${{ inputs.phase == 'prod' }}
        working-directory: infra/env/ephemeral
        run: |
          terraform init
          terraform apply -auto-approve -var run_id=${{ github.run_id }}
          echo "VM_IP=$(terraform output -raw ip)" >> $GITHUB_ENV

      - name: [PROD] Wait for SSH and run scan
        if: ${{ inputs.phase == 'prod' }}
        env:
          GOOGLE_CSE_API_KEY: ${{ secrets.GOOGLE_CSE_API_KEY }}
          GOOGLE_CSE_ENGINE_ID: ${{ secrets.GOOGLE_CSE_ENGINE_ID }}
          SSH_KEY: ${{ secrets.EPHEMERAL_SSH_KEY }}
        run: |
          echo "$SSH_KEY" > /tmp/ssh_key && chmod 600 /tmp/ssh_key
          for i in {1..30}; do nc -z $VM_IP 22 && break; sleep 5; done
          scp -i /tmp/ssh_key -o StrictHostKeyChecking=no -r ./in ./cache ephemeral@$VM_IP:/srv/cdt/
          ssh -i /tmp/ssh_key -o StrictHostKeyChecking=no ephemeral@$VM_IP "
            docker pull ghcr.io/<org>/cdt:latest
            docker run --rm \
              -v /srv/cdt/in:/app/in:ro \
              -v /srv/cdt/out:/app/out \
              -v /srv/cdt/cache:/app/cache \
              -e GOOGLE_CSE_API_KEY \
              -e GOOGLE_CSE_ENGINE_ID \
              --user 1000:1000 --read-only --tmpfs /tmp \
              ghcr.io/<org>/cdt:latest scan \
              --in /app/in/accounts_in.csv \
              --tier ${{ inputs.tier }} \
              --country '${{ inputs.country_filter }}' \
              --out /app/out/
          "
          scp -i /tmp/ssh_key -r ephemeral@$VM_IP:/srv/cdt/out ./out
          scp -i /tmp/ssh_key -r ephemeral@$VM_IP:/srv/cdt/cache ./cache

      # --- COMÚN: artifacts + cache + destroy ---
      - name: Upload outputs as artifact
        uses: actions/upload-artifact@v4
        with:
          name: cdt-scan-${{ github.run_id }}
          path: ./out
          retention-days: 30

      - name: Save cache
        if: ${{ inputs.phase == 'prod' && always() }}
        uses: actions/cache/save@v4
        with:
          path: ./cache
          key: cdt-cache-${{ hashFiles('config/*.yaml') }}-${{ github.run_id }}

      - name: [PROD] Terraform destroy (always)
        if: ${{ inputs.phase == 'prod' && always() }}
        working-directory: infra/env/ephemeral
        run: terraform destroy -auto-approve -var run_id=${{ github.run_id }}

      - name: Shred local sensitive files
        if: always()
        run: shred -u ./in/*.csv 2>/dev/null || true
```

El CSV **nunca se persiste en disco compartido ni queda logueado**: `printf '%s' "${{ inputs.csv_content }}"` evita echo/print, y `shred -u` sobreescribe antes de borrar. El secret `EPHEMERAL_SSH_KEY` se escribe a `/tmp` del runner y se descarta al destruirse el runner hosted.

### 12.5 Workflows de `cdt-infra` (Terraform)

- **`validate.yml` — on PR:** `terraform fmt -check`, `terraform validate`, `tflint`, `checkov` (policy scan) sobre ambos workspaces.
- **`plan.yml` — on PR a `main`:** `terraform plan` por workspace, comentado en el PR.
- **`apply.yml` — on push a `main`:** `apply` sobre `env/dev-persistent/` tras aprobación. El workspace `env/ephemeral/` no se aplica desde aquí; se aplica desde `scan.yml` de `cdt-scanner` en cada run.

**Backend:** HCP Terraform Free tier, dos workspaces separados (`cdt-dev-persistent`, `cdt-ephemeral`), permisos granulares (apply en ephemeral solo vía token del runner).

### 12.6 Recursos Terraform — dos workspaces

Estructura del repo `cdt-infra`:

```
cdt-infra/
├── env/
│   ├── dev-persistent/          # workspace cdt-dev-persistent
│   │   ├── linode.tf
│   │   ├── firewall.tf
│   │   ├── stackscript.tf
│   │   └── variables.tf
│   └── ephemeral/                # workspace cdt-ephemeral
│       ├── linode.tf
│       ├── firewall.tf
│       ├── stackscript.tf
│       └── variables.tf
├── modules/
│   └── linode-base/              # módulo común (firewall, SSH, backups)
└── .github/workflows/
```

**`env/dev-persistent/linode.tf`**

```hcl
resource "linode_instance" "dev_cdt" {
  label           = "dev-cdt"
  region          = "us-east"
  type            = "g6-standard-1"           # 2 GB, $12/mo
  image           = "linode/kali"              # Kali marketplace
  root_pass       = var.root_pass
  authorized_keys = [var.ssh_pubkey]
  backups_enabled = true
  stackscript_id  = linode_stackscript.dev_init.id
  stackscript_data = {
    runner_token = var.gh_runner_token
  }
}
```

**`env/ephemeral/linode.tf`**

```hcl
variable "run_id" { type = string }

resource "random_password" "root" {
  length  = 32
  special = false
}

resource "linode_instance" "ephemeral_cdt" {
  label           = "cdt-eph-${var.run_id}"
  region          = "us-east"
  type            = "g6-standard-1"
  image           = "linode/ubuntu24.04"      # host minimal
  root_pass       = random_password.root.result
  authorized_keys = [var.ssh_pubkey]
  backups_enabled = false
  stackscript_id  = linode_stackscript.ephemeral_init.id
}

output "ip" { value = linode_instance.ephemeral_cdt.ip_address }
```

**StackScripts:**
- `dev_init`: instala Docker + fail2ban + registra GH Actions runner como systemd service. Long-lived.
- `ephemeral_init`: instala Docker únicamente. Sin runner. Boot time ~60-90s.

### 12.7 Cache entre runs (GitHub Actions cache)

En Fase Prod, el cache vive en `actions/cache`. Se conserva:

| Contenido | Tamaño | TTL |
|---|---|---|
| IP ranges AWS/Azure/GCP/OCI/Cloudflare/Fastly | ~5 MB | 24 h (hash-keyed) |
| Discovery cache (Title+Country → URL validada) | <10 MB | 7 días |
| Feeds públicos de detección de WAF/CDN | <2 MB | 7 días |

Quota GH Actions cache: 10 GB por repo. Uso esperado <100 MB.

Lo que NO se cachea: inputs, outputs, scan results, secrets.

### 12.8 Secrets management

| Secret | Ubicación | Uso |
|---|---|---|
| `GOOGLE_CSE_API_KEY`, `GOOGLE_CSE_ENGINE_ID` | GitHub Secrets (cdt-scanner) | Env vars al `docker run` |
| `SHODAN_API_KEY` (opcional, Host API paga) | GitHub Secrets | Env var al `docker run` |
| `CENSYS_API_ID`, `CENSYS_API_SECRET` (opcional, free tier 250/mes) | GitHub Secrets | Env vars al `docker run` |
| `BUILTWITH_API_KEY` (opcional, último recurso) | GitHub Secrets | Env var al `docker run` |
| `LINODE_TOKEN` | GitHub Secrets (cdt-scanner + cdt-infra) | Terraform provider |
| `HCP_TF_TOKEN` | GitHub Secrets | Backend auth |
| `GH_RUNNER_TOKEN` | GitHub Secrets (cdt-infra) | Solo Fase Dev — registra self-hosted runner |
| `EPHEMERAL_SSH_KEY` | GitHub Secrets | SSH privada al VM efímero |
| `INFRA_TOKEN` | GitHub Secrets | PAT para checkout del repo cdt-infra desde cdt-scanner |

Rotación trimestral. Nada persiste en Linode entre runs en Fase Prod.

### 12.9 Dimensionamiento y costos

**Fase Dev (mensual, VM persistente):**
- Linode `g6-standard-1`: $12.00
- Backups Linode: $2.50
- HCP Terraform Free, GH Actions free tier: $0
- **Total Dev: ~$14.50/mes**

**Fase Prod (mensual, 4 runs):**
- Linode `g6-standard-1` efímero × 4 h/mes: ~$0.08
- GH Actions hosted runner (~300 min/mes): $0 (dentro de free tier 2000)
- HCP Terraform Free: $0
- **Total Prod: ~$0.08-0.40/mes**

Upgrade path: si se necesita más RAM/CPU, cambiar `type` a `g6-standard-2` (4 GB, $24) en Terraform → `apply`. Online, downtime ~1 min en Dev; en Prod es instantáneo porque cada run es nuevo.

### 12.10 Criterios de cutover Dev → Prod

Migramos a Prod como default solo cuando TODOS se cumplen:

- [ ] Coverage tests unitarios ≥ 80%
- [ ] Integration tests contra ≥ 3 sitios fixture (con WAF, sin WAF, con CDN only)
- [ ] Golden file test sobre ≥ 10 cuentas reales en los 7 países
- [ ] Terraform `apply + destroy` sobre `env/ephemeral/` ejecutado manualmente sin errores ≥ 3 veces
- [ ] Workflow `scan.yml phase=prod` corrido exitosamente end-to-end ≥ 3 veces
- [ ] Documentación operativa lista (§19 runbook)
- [ ] `security-review` skill aprueba el último commit
- [ ] SharePoint List recibe correctamente el copy-paste del CSV en Grid view (probado manualmente con un run completo)

Cutover: cambiar default de `phase` en `scan.yml` a `prod`, deshabilitar triggers schedule para el dev runner, `terraform destroy` del workspace `cdt-dev-persistent` (o pausar si se quiere mantener para escaladas de debug). Documentar en CHANGELOG.

### 12.11 Dominio e identidad operacional

Decisiones tomadas:

- **Sin DNS record** del Linode en `threathunt.cloud`. Nada vincula el scanner al brand de AppSec Assessment.
- **Reverse DNS** queda el default de Linode (`li<id>.members.linode.com`).
- **User-Agent** del scanner: `CDT/0.4 (research scanner)`. Transparente, sin datos identificatorios.
- **Abuse-contact**: en Fase Prod es irrelevante por naturaleza efímera de las IPs. En Fase Dev, el default `abuse@linode.com` basta — si llega una queja, el operador responde desde su cuenta Linode o la deja expirar al rotar la VM.
- **Justificación defensiva**: si hay disputa, la documentación oficial del proyecto (este spec, el CLAUDE.md del repo, el disclaimer) sostiene que CDT opera en el espectro de "information gathering" y que las medidas técnicas (tiers graduales, nikto condicional con early termination, User-Agent identificable, scope jurisdiccional declarado) fueron implementadas proactivamente para minimizar impacto en terceros.

### 12.12 Risk register

Revisable trimestralmente por el operador.

| # | Categoría | Riesgo | Probabilidad | Impacto | Mitigación |
|--|---|---|:---:|:---:|---|
| R1 | Legal | Denuncia en jurisdicción en scope por scanning no autorizado | Baja | Alto | Scope limitado a 7 países documentados; tiers pasivos/browser-like como default; nikto condicional + early termination; User-Agent transparente |
| R2 | Legal | CFAA (US) si target hosteado en AWS/Cloudflare US | Baja | Alto | Sin ejecución de payloads, sin brute force, sin auth attempts |
| R3 | Reputacional | IP en AbuseIPDB/Spamhaus | Media | Medio (Dev) / Bajo (Prod) | IPs efímeras en Prod; rotación vía `terraform taint` en Dev |
| R4 | Reputacional | Cliente identifica scan y escala a Fortinet/partner | Baja | Alto | User-Agent neutral, sin vínculo a threathunt.cloud, rationale documentado |
| R5 | Operacional | Ban de IP por WAF del target durante run | Alta | Bajo (Prod) | IP rota por run en Prod |
| R6 | Operacional | Google CSE agota quota mid-run | Media | Bajo | Cache 7 días + pause automático con warning |
| R7 | Datos | Logs capturan tokens en error pages | Baja | Medio | Log sanitization: nunca body completo ni headers con cookies |
| R8 | Datos | CSV findings es sensible | Media | Medio | Artifact en GitHub (retention 30d) y SharePoint List corporativa solo. Acceso a artifacts gobernado por permisos del repo |
| R9 | Técnico | FP/FN detección WAF → recomendación errada | Media | Medio | Fixtures regresión por vendor, sistema de confianza §14.5, revisión manual de `confidence=medium` |
| R10 | Técnico | Early termination nikto corta antes de resolver | Baja | Bajo | Criterios conservadores; re-run manual con tier 3 si hace falta |
| R11 | Supply chain | Paquete pip comprometido | Baja | Alto | Versiones pinneadas, Dependabot review, security-review skill |
| R12 | Supply chain | Imagen Kali comprometida | Muy baja | Alto | Pin de digest, verificación checksums Kali oficial |
| R13 | Operacional | Linode suspende VM (Dev) tras denuncia | Baja | Medio | Responder en 24 h; si suspenden, rearmar con Terraform en otra región en ~5 min |
| R14 | Legal | Retención de logs contiene evidencia | Media | Medio | Retención max 30 días, política de no conservar `Evidence` con payloads |

### 12.13 Jurisdicciones documentadas (scope de diseño)

CDT está diseñado para escanear cuentas ubicadas en los siguientes 7 países. **Este scope es documental, no enforcement técnico** — el tool acepta cualquier valor en el campo `Country` del input. El uso fuera de este scope es responsabilidad exclusiva del operador.

| País | ISO | Norma aplicable a "acceso ilícito" |
|---|:---:|---|
| Perú | PE | Ley 30096 — delitos informáticos |
| Ecuador | EC | COIP arts. 229–234 |
| Chile | CL | Ley 19.223 + Ley 21.459 (ciberseguridad) |
| Bolivia | BO | Código Penal arts. 363 bis y ter |
| Paraguay | PY | Ley 4439/2011 |
| Uruguay | UY | Código Penal art. 300 + Ley 18.237 |
| Venezuela | VE | Ley Especial contra los Delitos Informáticos (2001) |

Todos son estados parte o adherentes al Convenio de Budapest, lo que homogeneiza la tipificación. La arquitectura técnica de CDT (tiers graduales, nikto condicional con early termination, User-Agent transparente, IP efímera en Prod) está calibrada para minimizar superficie de infracción dentro de estas jurisdicciones.

**Disclaimer formal** (en el `CLAUDE.md` y `README.md` de ambos repos):

> CDT is a web application discovery and exposure scanner designed for use in seven specific jurisdictions (Peru, Ecuador, Chile, Bolivia, Paraguay, Uruguay, Venezuela) where legal constraints have been analyzed and mitigated by design. Use outside of these jurisdictions is at the operator's sole responsibility and may constitute unauthorized access under applicable laws.

---

## 13. (reservado) — placeholder para futuras extensiones de pipeline operativo

---

## 14. Catálogo de reglas de detección

El scanner depende de reglas explícitas, auditables y versionadas en `config/detection_rules.yaml`. Esta sección documenta las cuatro categorías de detección que produce cada fila del CSV: **WAF**, **Cloud Provider**, **CDN**, **Tech Stack**. Al final (§14.5) se define cómo se combinan las señales cuando entran en conflicto.

### 14.1 Detección de WAF

Para cada vendor, se listan las señales en orden de confianza descendente. CDT aplica las señales en orden; la primera con puntaje ≥ umbral asigna el vendor y termina. Si ninguna dispara, `WAF=No`.

#### 14.1.1 Matriz de firmas por vendor

| Vendor | Señal primaria (alta confianza) | Señales secundarias | Señal por block page (403/429) |
|---|---|---|---|
| **Cloudflare** | Header `server: cloudflare` + header `cf-ray: <hex>-<pop>` | Cookies `__cfduid`, `__cf_bm`, `cf_clearance`; header `cf-cache-status`; CNAME a `*.cloudflare.net` / `*.cloudflare.com` | Body contiene `Attention Required! | Cloudflare`, `Ray ID:`, `cloudflare-error` |
| **AWS CloudFront + AWS WAF** | Header `via: <ver> <id>.cloudfront.net` + `x-amz-cf-id` | Header `x-cache`, `x-amz-cf-pop`; CNAME a `*.cloudfront.net` | Body `Request blocked`, `CloudFront` en `<title>` |
| **Azure Front Door / WAF** | Header `x-azure-ref` | Header `x-msedge-ref`; CNAME `*.azurefd.net`, `*.azureedge.net` | Body con `Microsoft-Azure-Application-Gateway/` + status 403 |
| **Akamai** (Kona Site Defender, App & API Protector, Ghost) | Header `server: AkamaiGHost` o `server: AkamaiNetStorage` | Headers `x-akamai-*`; cookie `ak_bmsc`, `bm_sz`, `_abck`; CNAME `*.akamaized.net`, `*.edgekey.net`, `*.edgesuite.net` | Body `Reference #\d+\.[a-f0-9]+\.\d+\.[a-f0-9]+`, `Access Denied` estilo Akamai |
| **Fortinet FortiWeb** | Header `server: FortiWeb` (algunas versiones) | Cookie `FORTIWAFSID=`; header `x-fw-debug` (solo en modo debug, raro) | Body `<title>FortiWeb</title>`, imagen `/error_pages/`, página blanca con logo Fortinet y `Block Rule ID:` |
| **Fortinet FortiGate UTM (WAF module)** | Header `server: FortiGate` | Cookie `FGTServer`; TLS cert emitido por Fortinet CA | Body `Blocked because of IPS sensor` o `FortiGate Web Filter` |
| **Imperva (Incapsula)** | Header `x-iinfo` o `x-cdn: Incapsula` | Cookie `incap_ses_*`, `visid_incap_*`; CNAME `*.incapdns.net` | Body `Request unsuccessful. Incapsula incident ID:` |
| **F5 BIG-IP ASM** | Header `server: BigIP` | Cookie `TS[0-9a-f]{7,8}=`, `BIGipServer*` | Body `The requested URL was rejected`, `Support ID:` |
| **Sucuri** | Header `x-sucuri-id`, `x-sucuri-cache` | `server: Sucuri/Cloudproxy` | Body `Access Denied - Sucuri Website Firewall` |
| **Barracuda** | Header `server: Barracuda` | Cookie `barra_counter_session` | Body `You've been blocked`, logo Barracuda |
| **Citrix NetScaler** | Header `via: NS-CACHE` | Cookie `citrix_ns_id`, `NSC_*` | — |
| **StackPath** | Header `x-sp-request-id` | CNAME `*.stackpathdns.com` | — |
| **Wallarm** | Header `nemesida` | — | — |

#### 14.1.2 Diferenciación CDN-only vs CDN+WAF

Cloudflare, CloudFront, Akamai y Azure Front Door ofrecen **ambos** productos: CDN y WAF. Estar detrás del CDN no significa tener el WAF activo.

| Pista de que el WAF está efectivamente activo | Cómo se observa |
|---|---|
| Challenge page de bot mitigation en lugar de la página real | Primera carga devuelve interstitial con JS challenge (`cf_chl_cd`, `akamai-challenge`, `/_Incapsula_Resource`). |
| Headers de `security-level` explícitos | Cloudflare: `cf-mitigated`, `cf-apo-via`. Akamai: `x-akam-sw-version` + `x-check-cacheable`. |
| Respuesta 403 con body del vendor a peticiones "sospechosas" | CDT envía un `User-Agent: curl/8.0` + `GET /.env` en Tier 2; si devuelve 403 con body del vendor → WAF activo. Si devuelve 404 normal → solo CDN. |

La regla es: **WAF=Yes** solo si al menos una de estas tres señales dispara, además de la señal primaria del vendor. Si solo aparecen CNAMEs o headers de CDN genéricos sin evidencia de filtrado, CDT marca `CDN=<vendor>` pero `WAF=Further investigation needed`.

### 14.2 Atribución de Cloud Provider

Árbol de decisión aplicado por sitio. Se resuelve la IP del dominio canónico (post-redirect) y se ejecutan las etapas en orden. La primera que matchea asigna el `CloudProvider`.

```
┌─────────────────────────────┐
│ 1. IP range lookup          │   ← más confiable
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 2. Reverse DNS              │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 3. CNAME chain              │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 4. ASN lookup               │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 5. Banner / Server header   │   ← menos confiable
└─────────────┬───────────────┘
              │
              ▼
     CloudProvider = unknown / -
```

#### 14.2.1 IP ranges (fuentes públicas, cache 24h)

| Provider | URL | Formato |
|---|---|---|
| AWS | `https://ip-ranges.amazonaws.com/ip-ranges.json` | JSON con `prefixes[].ip_prefix` + `service` (EC2, CLOUDFRONT, S3, …) |
| Azure | `https://www.microsoft.com/download/details.aspx?id=56519` (ServiceTags, mensual) | JSON con `values[].properties.addressPrefixes` |
| GCP | `https://www.gstatic.com/ipranges/cloud.json` | JSON con `prefixes[].ipv4Prefix` + `scope` (region) |
| OCI | `https://docs.oracle.com/iaas/tools/public_ip_ranges.json` | JSON con `regions[].cidrs[]` |
| Cloudflare | `https://www.cloudflare.com/ips-v4` + `/ips-v6` | texto plano, CIDR por línea |
| Fastly | `https://api.fastly.com/public-ip-list` | JSON |
| Akamai | No publica lista. Se usa detección por CNAME (`*.akamaiedge.net`). |

CDT carga los JSONs al startup (cache 24h), construye un árbol radix (`pytricia`) y resuelve lookups IP→proveedor en O(log n).

#### 14.2.2 Reverse DNS patterns

| Patrón `PTR` | Provider |
|---|---|
| `*.compute.amazonaws.com`, `*.compute-1.amazonaws.com` | AWS (EC2) |
| `*.cloudfront.net`, `*.amazonaws.com` (ELB) | AWS (CloudFront, ELB) |
| `*.cloudapp.net`, `*.cloudapp.azure.com` | Azure |
| `*.azurewebsites.net` | Azure App Service |
| `*.azureedge.net`, `*.azurefd.net` | Azure CDN / Front Door |
| `*.googleusercontent.com`, `*.1e100.net` | GCP |
| `*.bc.googleusercontent.com` | GCP Compute Engine |
| `*.oraclecloud.com`, `*.oraclevcn.com` | OCI |
| `*.cloudflare.com`, `*.cloudflaressl.com` | Cloudflare |
| `*.akamaiedge.net`, `*.edgekey.net`, `*.edgesuite.net`, `*.akamaized.net` | Akamai |
| `*.fastly.net`, `*.fastlylb.net` | Fastly |

#### 14.2.3 ASN lookup

Usando `ipwhois` o el servicio gratuito `bgp.tools` / `Team Cymru`, se resuelve ASN. Tabla de ASNs relevantes:

| ASN | Organización | Provider asignado |
|---|---|---|
| 14618, 16509, 14061 | Amazon | AWS |
| 8075, 8068 | Microsoft Corp | Azure |
| 15169 | Google LLC | GCP |
| 31898, 63775 | Oracle Corp | OCI |
| 13335 | Cloudflare Inc | Cloudflare |
| 20940, 16625, 16702 | Akamai Technologies | Akamai |
| 54113 | Fastly | Fastly |
| 45102 | Alibaba Cloud | Alibaba |
| 58779, 36351 | IBM | IBM Cloud |
| Cualquier otro | — | `datacenter` o `unknown` según rDNS |

Cuando ASN pertenece a un ISP/telco regional (ej. Telefónica, Claro, Movistar, CANTV, CNT) y no a un hyperscaler, CDT asigna `CloudProvider = datacenter` con nota del operador ASN en `sites.csv`.

#### 14.2.4 CNAME chain

Se sigue la cadena de CNAMEs hasta el A/AAAA final, anotando cada salto. Si un salto intermedio es `*.cloudfront.net` pero el origen apunta a `*.compute.amazonaws.com`, hay dos hallazgos útiles:

- `CDN = CloudFront`
- `Origin = AWS EC2`

CDT consigna el **edge** (frente público visto por el navegador) en `CloudProvider`. El `Origin` aparece solo en `sites.csv` como campo separado `OriginCloudProvider` para no sobrecargar la fila de cuenta.

#### 14.2.5 Server header (fallback débil)

| Header value | Provider inferido |
|---|---|
| `Server: AmazonS3` | AWS |
| `Server: Google Frontend`, `gws` | GCP |
| `Server: Microsoft-IIS/*` + Azure headers | Azure (pero IIS en sí no es señal) |
| `x-served-by: cache-*.fastly.net` | Fastly |

Solo se usa si las señales 1-4 fallan.

### 14.3 Detección de CDN (independiente del WAF)

`CDN` es un campo aparte de `WAF`. Se pobla con la primera señal clara de edge/caching:

| CDN | Señal | Nota |
|---|---|---|
| Cloudflare | `cf-ray`, `cf-cache-status`, CNAME `*.cloudflare.net` | Puede o no traer WAF activo |
| CloudFront | `via: ... cloudfront.net`, `x-amz-cf-id`, `x-amz-cf-pop` | |
| Akamai | CNAMEs `*.akamaiedge.net`, `*.edgekey.net`; `server: AkamaiGHost` | |
| Fastly | `x-served-by: cache-*`, `x-cache: HIT/MISS`, `fastly-debug-*` | |
| Azure CDN / Front Door | `x-msedge-ref`, `x-azure-ref` | |
| StackPath | `x-sp-request-id` | |
| KeyCDN | `server: keycdn-engine` | |
| BunnyCDN | `server: BunnyCDN-*` | |
| CDN77 | `x-cdn77-*` | |
| Google Cloud CDN | `via: 1.1 google` + ASN 15169 | |

Si hay CDN **y** WAF detectado, ambos se reportan. Si solo hay CDN sin WAF confirmado, `WAF=Further investigation needed`.

### 14.4 Tech Stack fingerprinting

Objetivo: poblar `WebServer`, `CMSFramework`, y como hallazgo en `findings.csv` detectar versiones desactualizadas.

#### 14.4.1 Web servers

| Señal | Valor asignado |
|---|---|
| `Server: nginx/X.Y.Z` | `nginx/X.Y.Z` |
| `Server: Apache/X.Y.Z (Ubuntu)` | `Apache/X.Y.Z` |
| `Server: Microsoft-IIS/X.Y` | `IIS/X.Y` |
| `Server: openresty/X.Y.Z` | `openresty/X.Y.Z` |
| `Server: LiteSpeed` | `LiteSpeed` |
| `Server: Caddy` | `Caddy` |
| `Server: cloudflare` (oculta origen) | `-` (no se sabe) |

Si el server banner está oculto, CDT intenta huellas secundarias: TLS fingerprint (JA3), orden de headers, casing de header names. En v0.5 se detalla.

#### 14.4.2 CMS / Framework

| CMS | Señales (cualquiera dispara) |
|---|---|
| **WordPress** | `meta name="generator" content="WordPress X.Y"`; paths `/wp-content/`, `/wp-includes/`, `/wp-json/`; cookie `wordpress_logged_in_*` |
| **Drupal** | `X-Generator: Drupal X`; path `/sites/default/files/`; JS file `misc/drupal.js` |
| **Joomla** | `meta name="generator" content="Joomla! - ..."`; path `/media/jui/` |
| **Magento** | Cookie `X-Magento-Vary`; path `/skin/frontend/`; CSS variable `mage/` |
| **Shopify** | Header `x-shopid`, `x-shopify-*`; CNAME a `shops.myshopify.com` |
| **Wix** | `meta name="generator" content="Wix.com Website Builder"`; JS `static.wixstatic.com` |
| **Squarespace** | `x-served-by: squarespace-edge` |
| **Ghost** | `meta name="generator" content="Ghost X.Y"`; `/ghost/` path |
| **Strapi** | Header `x-powered-by: Strapi` |
| **Sitecore** | Cookie `SC_ANALYTICS_GLOBAL_COOKIE`; path `/sitecore/` |

#### 14.4.3 App frameworks / languages

| Framework | Señal |
|---|---|
| **Django** | Cookie `csrftoken`, `sessionid`; header `X-Frame-Options: DENY` patrón Django |
| **Rails** | Cookie `_*_session`; header `x-powered-by: Phusion Passenger` |
| **Laravel** | Cookie `laravel_session`, `XSRF-TOKEN` en body PHP |
| **Express.js** | `x-powered-by: Express` |
| **ASP.NET** | `x-powered-by: ASP.NET`; cookie `ASP.NET_SessionId` |
| **Next.js** | Header `x-nextjs-*`; path `/_next/` |
| **Nuxt** | `__NUXT__` en HTML |

### 14.5 Cruce de señales y resolución de conflictos

Cuando señales apuntan a resultados distintos, se aplica este orden de prioridad:

1. **IP range match directo** (hard evidence de red) > todo lo demás para atribución cloud.
2. **Block page específica del vendor** > headers para WAF.
3. **Headers propietarios no falsificables** (`cf-ray`, `x-amz-cf-id`, `x-azure-ref`, `x-akamai-*`) > server banner.
4. **Server banner** es la señal más débil (fácil de ocultar o falsificar).

#### 14.5.1 Sistema de puntaje

Cada señal aporta puntos a una hipótesis:

- Señal primaria de tabla `14.1.1`: +10
- Señal secundaria: +5
- Block page: +7
- IP range match: +10 (para cloud provider)
- Reverse DNS match: +7
- ASN match: +5
- CNAME match: +6
- Server header match: +2

CDT acumula puntos por hipótesis (ej. "vendor=Cloudflare"). Si la hipótesis ganadora supera 10 puntos y aventaja a la segunda por ≥ 5, se asigna con `confidence=high`. Si no, se asigna con `confidence=medium` y se añade un finding `LOW_CONFIDENCE_<campo>` a `findings.csv` para que el operador lo revise.

Los puntajes exactos viven en `config/detection_rules.yaml` y son reemplazables sin tocar código.

### 14.5.2 Integración con herramientas de Kali preinstaladas

CDT no reinventa; orquesta. Las reglas del §14 propias conviven con tres herramientas embebidas en el container Kali. La estrategia de cruce es: **las tools externas amplían recall; las reglas propias del §14 son el ground truth cuando hay conflicto** (porque están versionadas en código y auditables fixture por fixture).

#### wafw00f (github.com/enablesecurity/wafw00f)

- **Integración**: librería Python, no subprocess. Permite control fino y no paga el costo de `fork+exec`.

  ```python
  from wafw00f.main import WAFW00F
  w = WAFW00F(url, debuglevel=0, followredirect=True,
              extraheaders={'User-Agent': 'CDT-Scanner/0.4'})
  hits = w.identwaf()   # lista de vendors detectados
  generic = w.genericdetect() if not hits else None
  ```

- **Tier**: 2 y 3. Dispara 1–5 requests por sitio.
- **Output consumido**: `hits` es lista; si hay múltiples, CDT prioriza los que matchean con una hipótesis propia del §14.1. Si wafw00f reporta `Generic` (heurística sin vendor), CDT registra `WAFVendor=Other`.
- **Contribución al puntaje**: señal primaria de vendor (+10) si wafw00f identifica con certeza (no `genericdetect`), secundaria (+5) si es genérica.
- **Versión**: pinneada en Dockerfile (`pip install wafw00f==2.3.1`) para reproducibilidad. Actualización por PR.

#### whatweb (github.com/urbanadventurer/whatweb)

- **Integración**: subprocess con stdout JSON parseado.

  ```bash
  whatweb -q -a 3 --log-json=/tmp/whatweb-<siteid>.json \
          -U 'CDT-Scanner/0.4 (+https://cdt.threathunt.cloud/about)' \
          --no-errors \
          <url>
  ```

- **Aggression level `-a 3`** (Aggressive) según la wiki oficial: recomendado para scanning estándar, ~5–15 requests. Tier 2 lo usa por default. Tier 3 sube a `-a 4` (Heavy).
- **Output consumido**: JSON con plugins por categoría. CDT mapea:
  - `plugins.HTTPServer.string[]` → `WebServer`
  - `plugins.WordPress.string[]`, `plugins.Drupal.*`, `plugins.Joomla.*`, `plugins.Magento.*` → `CMSFramework`
  - `plugins.Cloudflare.*`, `plugins.CloudFront.*`, `plugins.Akamai.*` → refuerza `CDN` y `WAFVendor`
  - `plugins.*.version` → enriquece `findings.csv` con versiones detectadas (para cruce CVE en Tier 3)
- **Contribución al puntaje**: señales secundarias (+5) para stack, secundarias (+5) para CDN/WAF vendor si coinciden con reglas propias.

#### nikto (github.com/sullo/nikto) — condicional + early termination

**Principio:** nikto es ruidoso. En Tier 2 no corre por default; solo se activa como fallback cuando el resto del stack (passive + browser-like + wafw00f + whatweb + Wappalyzer) no resolvió los campos objetivo. Cuando dispara, corta apenas los campos están resueltos.

**Condición de activación en Tier 2** (se chequea tras completar los pasos previos; basta UNA para activar):

| Campo sin resolver | Umbral de activación |
|---|---|
| `WAFVendor` | `wafw00f` devolvió `Generic` o nada, y las reglas propias del §14.1 dieron `confidence=low` |
| `CMSFramework` | whatweb + Wappalyzer ambos devolvieron `-` |
| `WebServer` | Server header oculto por CDN/WAF y no hay fingerprint secundario |
| `PublicCloud` | IP no matchea ningún range, rDNS ambiguo, ASN inconclusivo |

Flag override: `--force-nikto` en el CLI salta las condiciones y ejecuta nikto contra esa cuenta siempre.

**Algoritmo de ejecución con early termination** (pseudocódigo Python):

```python
STOP_FIELDS = {"WAFVendor", "CMSFramework", "WebServer"}  # PublicCloud no se resuelve con nikto
HARD_TIME_CAP_SEC = 300
HARD_REQ_CAP = 400

def run_nikto_tier2(url: str, initial_state: dict) -> dict:
    unresolved = {f for f in STOP_FIELDS if not initial_state.get(f)}
    if not unresolved:
        return initial_state  # nada que hacer

    proc = subprocess.Popen(
        ["nikto", "-host", url,
         "-Tuning", "b,a,5",       # software ID + auth bypass + remote files
         "-Pause", "2",             # 2s throttle
         "-maxtime", str(HARD_TIME_CAP_SEC),
         "-Format", "json",
         "-output", output_path,
         "-useragent", "CDT/0.4 (research scanner)",
         "-nointeractive"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    req_count = 0
    state = initial_state.copy()
    start = time.time()
    for line in proc.stdout:
        req_count += count_requests_from_line(line)
        state = update_state_from_nikto_line(line, state)  # parses Server, CMS hints, WAF banners

        resolved_now = {f for f in STOP_FIELDS if state.get(f)}
        if resolved_now.issuperset(unresolved):
            log_event("nikto_early_term", url=url, reason="resolved_all_fields",
                      reqs_sent=req_count, elapsed_sec=time.time()-start, state=state)
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill()
            break
        if req_count >= HARD_REQ_CAP:
            log_event("nikto_early_term", reason="request_cap", ...)
            proc.terminate(); break

    return state

def run_nikto_tier3(url: str) -> dict:
    # Tier 3 corre completo, sin early termination por "resolved", solo hard timeout
    proc = subprocess.run(
        ["nikto", "-host", url,
         "-Tuning", "1,2,3,4,5,6,7,8,9,0,a,b,c,x",
         "-maxtime", "900",  # 15 min
         "-Format", "json",
         "-output", output_path,
         "-useragent", "CDT/0.4 (research scanner)",
         "-nointeractive"],
        capture_output=True, text=True, timeout=1200,
    )
    return parse_json_output(output_path)
```

**Hard caps (orden de prioridad):**

1. Los 3 campos objetivo (`WAFVendor` + `CMSFramework` + `WebServer`) resueltos → SIGTERM gracioso, SIGKILL a los 10 s.
2. `-maxtime 300` (5 min absoluto). Nikto termina solo.
3. Contador interno > 400 requests enviados → SIGTERM.

**Registro obligatorio en `nikto_runs.jsonl`** (journal local, se incluye en el artifact de GitHub Actions al final):

```json
{"timestamp":"2026-04-23T14:32:11Z","url":"https://acme.com","tier":"browser",
 "trigger_reason":"unresolved_WAFVendor,unresolved_CMSFramework",
 "tuning":"b,a,5","reqs_sent":147,"elapsed_sec":78,
 "termination":"resolved_all_fields","resolved_fields":["WAFVendor","CMSFramework","WebServer"]}
```

**Output consumido**: JSON parseado tras el run (parcial o completo). Cada `vulnerability` → `finding` en `findings.csv` con `FindingCode=NIKTO_<id>`. Hallazgos parciales son válidos — se marca `NiktoEarlyTerminated=1` + `NiktoTerminationReason` en `sites.csv`.

**Allowlist de dominios a NO niktar** (en `config/nikto_skip.yaml`): TLDs gubernamentales del scope (`*.gob.ec`, `*.gob.pe`, `*.gob.cl`, `*.gub.uy`, `*.gob.bo`, `*.gov.py`, `*.gob.ve`), dominios bancarios centrales. En estos casos el `Opportunity` se calcula con la data que haya al momento, y se marca `findings.csv` con `NIKTO_SKIPPED_SENSITIVE_DOMAIN` para transparencia.

**Kill switch**: env var `CDT_NIKTO_ENABLED=false` en el workflow deshabilita nikto globalmente para esa run. Útil si Linode avisa que revisará actividad.

#### Shodan — InternetDB (siempre) + Host API (opcional)

Integra dos APIs distintas de Shodan con características opuestas de costo.

- **Shodan InternetDB** (`https://internetdb.shodan.io/{ip}`)
  - **Gratuito, sin API key.** Siempre activo.
  - Rate limit: 1 req/s (informal, sin autenticación).
  - Devuelve: `ports[]`, `cpes[]`, `hostnames[]`, `tags[]`, `vulns[]`.
  - **Contribución a CDT**:
    - `ports[]` confirma si el sitio tiene más que 80/443 (señal adicional para `findings.csv` si hay DB exposed, SSH público, etc.).
    - `cpes[]` (Common Platform Enumeration) puebla `WebServer` y `CMSFramework` cuando whatweb/Wappalyzer no resolvieron.
    - `vulns[]` → findings con CVE-ID directo.
    - `tags[]` (ej. `cdn`, `cloud`) refuerza `CloudProvider` y `CDN`.
  - **Puntaje**: señales secundarias (+5 cada una) cuando coinciden con hipótesis propias.
  - **Cache**: 7 días por IP en GH Actions cache.

- **Shodan Host API** (`https://api.shodan.io/shodan/host/{ip}`)
  - **Requiere `SHODAN_API_KEY`** + membership pagada (desde $69/mes base).
  - Se activa solo si la env var está presente.
  - Devuelve mucho más detalle: banners completos, last_update, services, `org`, `isp`, `asn`.
  - **Contribución**: refuerza atribución de cloud y banner de server con high confidence.
  - **Cuando no se activa**: CDT corre sin ella y lo documenta en el log (`shodan_host_api=disabled`).

**Integración Python**:
```python
# InternetDB (librería standard urllib o httpx, no requiere SDK)
import httpx
r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
data = r.json() if r.status_code == 200 else {}

# Host API (librería oficial `shodan`)
import shodan
api = shodan.Shodan(os.environ["SHODAN_API_KEY"])
host = api.host(ip)
```

#### Censys — alternativa a BuiltWith para tech stack/cloud

**Preferida sobre BuiltWith** por free tier más generoso y Python SDK oficial.

- **Librería**: `pip install censys`
- **API key** via `CENSYS_API_ID` + `CENSYS_API_SECRET` en secrets.
- **Free tier**: 250 search queries/mes + 250 hosts lookups/mes. Cubre scope v0.4 (~500 cuentas con cache).
- **Endpoints consumidos**:
  - `Hosts.view(ip)` — servicios corriendo, cert, autonomous_system, dns.names, operating_system.
  - `Certificates.search(domain)` — cert transparency (complemento a crt.sh).
- **Contribución**: `CloudProvider`, `WebServer`, `findings.csv` (servicios expuestos fuera de 80/443), y expansión de cert transparency para descubrir más subdominios que crt.sh podría haber cacheado stale.
- **Cache**: 7 días por IP/domain.
- **Puntaje**: señal secundaria (+5).

#### BuiltWith — opcional puro, solo con API key

Se mantiene como enriquecimiento opcional; **no es recomendada como primary** por su modelo de precios (Trial 1000 lookups gratis una vez, luego $295/mo Basic).

- Endpoint: `https://api.builtwith.com/v21/api.json?KEY=<key>&LOOKUP=<domain>`
- HTTP wrapper sin librería (no hay SDK oficial).
- Se activa solo si `BUILTWITH_API_KEY` está presente. Sin key, el tool sigue funcional con Wappalyzer + whatweb + Shodan + Censys cubriendo el 90%.
- **Cache**: 30 días por domain (la data cambia lento).
- **Puntaje**: señal secundaria (+5).
- **Cuándo tiene sentido pagar**: si el operador necesita cobertura exhaustiva de tech stack (plug-ins específicos, analytics providers, hosting providers finos) y Censys + Wappalyzer + whatweb se quedan cortos en su experiencia.

#### Resumen de precedencia de tools de fingerprinting

| Tool | Costo | Activación | Primary para |
|---|---|---|---|
| Wappalyzer (python-Wappalyzer) | Gratis | Siempre | `CMSFramework`, `WebServer`, `CDN` base |
| whatweb (-a 3) | Gratis | Siempre en Tier 2 | CMS versionado, plug-ins, banner extendido |
| wafw00f (library) | Gratis | Siempre en Tier 2 | `WAFVendor` primario |
| Shodan InternetDB | Gratis | Siempre | `ports`, `vulns` (findings), refuerzo cloud |
| Shodan Host API | $69/mo | Si key presente | Banners pro, ASN detallado |
| Censys | Free 250/mes | Si key presente | Alternativa a BuiltWith, services exposure |
| BuiltWith | $0–$295/mo | Si key presente | Último recurso para tech stack fino |
| nikto | Gratis | Condicional (solo si campos sin resolver) | Software ID detallado, findings adicionales |

### 14.6 Gobernanza del catálogo

- **Ubicación:** `config/detection_rules.yaml` en el repo `cdt-scanner`.
- **Formato:** YAML estructurado con `waf_vendors`, `cdn_vendors`, `cloud_providers`, `cms`, `frameworks`.
- **Actualizaciones:** PR al repo → CI corre tests de fixtures (ver §16) → merge a main → siguiente scan usa las reglas nuevas al pullear `:latest`.
- **Fixtures de test:** para cada regla, un HTTP response grabado (`.http`/`.json`) que debe disparar la detección. Evita regresiones.
- **Contribuciones:** cuando el operador encuentre un sitio mal clasificado, genera un issue → se agrega fixture → se ajusta regla.

---

## 15. Inventario de Claude Skills y conectores MCP

Mapeo de tareas del proyecto contra skills ya disponibles en el entorno, y gaps que cubriremos creando skills propias o delegando a Claude Code.

### 15.1 Skills que se usan directamente

| Skill | Tarea CDT cubierta | Cuándo se invoca |
|---|---|---|
| **init** | Arranque de cada repo con `CLAUDE.md` contextualizado | Al crear `cdt-scanner` y `cdt-infra` en §16 |
| **review** | Code review automatizado de PRs | En workflow `ci.yml` de cada repo |
| **security-review** | Barrido de seguridad del código scanner y de la infra Terraform | Obligatorio en cada PR. Audita manejo de secrets, egress points, uso de subprocess con input externo, configuraciones de firewall |
| **skill-creator** | Creación de la skill propia `cdt-scanner-dev` (§15.3) | Una vez al iniciar §16 |
| **schedule** | Disparar corridas de scan desde Cowork, además del cron de GH Actions | Cuando el operador quiera "correr ahora para México" desde Claude sin abrir GitHub |
| **docx** | Reporte ejecutivo por cliente a partir de `findings.csv` | Post-scan, si se quiere entregable imprimible al AE |
| **pdf** | Variante PDF del mismo reporte | Idem |
| **xlsx** | Export alternativo para ops que prefieren Excel a CSV | Ad-hoc |
| **pptx** | Deck comercial por cuenta con recomendación Fortinet + evidencias | Para el AE de cara a discovery call |

### 15.2 Skills que quedan fuera por irrelevantes

Design suite (`accessibility-review`, `design-critique`, `design-handoff`, `design-system`, `research-synthesis`, `user-research`, `ux-copy`), `consolidate-memory`, `setup-cowork`, `cowork-plugin-customizer`, `create-cowork-plugin`. No aplican al scanner.

### 15.3 Skill propia a crear: `cdt-scanner-dev`

Se genera con `skill-creator` al arrancar §16. Concentra los patrones idiomáticos del proyecto para que Claude Code no tenga que reinventarlos cada vez. Contenido:

- **Templates de Terraform para Linode**: `linode_instance` con Kali + StackScript, `linode_firewall` con allowlist, `linode_domain_record`, backend HCP Terraform.
- **Templates de GitHub Actions**: `ci.yml` con ruff+mypy+pytest, `release.yml` con multi-arch build a GHCR, `scan.yml` con self-hosted runner y docker run.
- **Templates de Dockerfile Kali-based**: multi-stage, non-root user, read-only FS, herramientas pinneadas por versión.
- **Snippets Python**: wrappers idiomáticos para wafw00f (library), whatweb (subprocess + JSON), nikto (subprocess + JSON), CSV readers/writers con pydantic models.
- **Convenciones**: naming de módulos (`src/cdt/discovery.py`, `src/cdt/scan/browser.py`, `src/cdt/detect/waf.py`, …), estructura de tests, cómo agregar un nuevo vendor de WAF al catálogo.

### 15.4 Skill operacional opcional: `cdt-operator` (Cowork)

Post-MVP. Permite al operador correr scans desde Claude Cowork sin tocar GitHub:

- `cdt status` — estado del último run, cuentas pendientes, errores recientes.
- `cdt run --country X --tier Y` — dispara `workflow_dispatch` de `scan.yml` vía GitHub API.
- `cdt explain <Title>` — lee el último CSV de salida para esa cuenta y explica por qué salió la recomendación.

No es prioridad de v0.5. Se agenda para v0.6.

### 15.5 Conectores MCP evaluados

Del marketplace MCP evalué:

- **GitHub MCP**: necesario para `cdt-operator` (disparar workflows, leer runs). No apareció en los primeros resultados relevantes de mi búsqueda — si más adelante aparece un GitHub MCP oficial de Anthropic o community, lo adoptamos. Mientras tanto, `cdt-operator` usa `gh` CLI via subprocess.
- **Linode MCP**: no existe en el registry. Si se necesita, creamos un MCP propio expuesto por un worker en el propio VM. Baja prioridad porque Terraform cubre casi todo el ciclo.
- **Terraform Cloud / HCP MCP**: no existe. HCP Terraform tiene API REST; si se automatiza algo más allá de plan/apply, se agregaría.
- **Marketplace dominante hoy** (Stripe, Monday, Close, Docusign, G2, PagerDuty, Egnyte, Process Street, n8n, Lorikeet) — todos orientados a ventas/CRM/productividad, nada aplicable a CDT.

**Decisión:** no se agregan conectores MCP en v0.5. La operación vive en GH Actions + Terraform (dos superficies programáticas), y Claude interactúa con ellas via `gh` CLI y `terraform` CLI dentro del runner. Si aparece necesidad puntual, la agregamos con ADR.

### 15.6 Orden de adopción de skills

```
§16 (arranque)                        — init, skill-creator (genera cdt-scanner-dev)
  │
  ▼
§16+ (desarrollo iterativo)           — cdt-scanner-dev (propia), review, security-review
  │
  ▼
§17 (tests)                           — cdt-scanner-dev (continua), review
  │
  ▼
MVP listo                             — schedule (programar corridas), docx/pdf/xlsx/pptx (entregables)
  │
  ▼
v0.6 (opcional)                        — cdt-operator (Cowork), skill-creator para empaquetarla
```

---

## 16. Reservado

---

## 17. Arquitectura Claude Code

Cómo Claude Code recoge este spec y lo traduce en código operativo. Esta sección describe repos, estructura, stack, skills y plan de trabajo por fases. **No contiene código; es la hoja de ruta del agente.**

### 17.1 Dos repositorios separados

División deliberada para que los cambios de infra y los de código viajen por pipelines distintos y con revisores distintos.

| Repo | Scope | Revisor | Workflows | Skills principales |
|---|---|---|---|---|
| `cdt-scanner` | Código Python, Dockerfile, config YAML, tests, catálogo de detección | Dev + Tech Lead | `ci.yml`, `release.yml`, `scan.yml` | `cdt-scanner-dev`, `review`, `security-review`, `init` |
| `cdt-infra` | Terraform (dos workspaces), stackscripts, cloud-init, políticas | Tech Lead + Ops | `validate.yml`, `plan.yml`, `apply.yml` | `cdt-scanner-dev`, `review`, `security-review` |

Branch protection en `main` de ambos: PR obligatorio, al menos un review aprobado, CI verde.

### 17.2 Estructura de `cdt-scanner`

```
cdt-scanner/
├── CLAUDE.md                      # Contexto permanente para Claude Code
├── README.md                      # Disclaimer de scope (§12.13), quick start
├── pyproject.toml                 # Python 3.12, deps pinneadas, ruff + mypy config
├── Dockerfile                     # Multi-stage, base kalilinux/kali-rolling pinneado por digest
├── .dockerignore
├── .gitignore
├── src/
│   └── cdt/
│       ├── __init__.py
│       ├── __main__.py             # entry point para `python -m cdt`
│       ├── cli.py                  # typer: comandos scan, validate, dry-run, diff, doctor
│       ├── models.py               # pydantic: AccountIn, AccountEnriched, Site, Finding
│       ├── context.py              # dataclass de configuración global (tier, paths, keys)
│       │
│       ├── io/
│       │   ├── csv_in.py           # lee accounts_in.csv, authorized.csv
│       │   ├── csv_out.py          # escribe los 4 CSVs de salida
│       │   # (no rclone wrapper — outputs van solo a artifact de GH Actions)
│       │   └── journal.py          # nikto_runs.jsonl + scan audit log
│       │
│       ├── discovery/
│       │   ├── google_cse.py       # Validate + Discover via Google CSE
│       │   ├── validator.py        # HEAD + parsing normalization
│       │   └── expander.py         # crt.sh subdomain expansion
│       │
│       ├── scan/
│       │   ├── passive.py          # DNS, WHOIS, IP ranges
│       │   ├── browser.py          # GET /, robots, TLS, headers
│       │   ├── dast.py             # Tier 3 nikto completo (authorized)
│       │   ├── runner.py           # orquesta tiers con asyncio.Semaphore
│       │   └── throttle.py         # rate limit por dominio/IP/ASN
│       │
│       ├── detect/
│       │   ├── waf.py              # §14.1 reglas propias + cruce wafw00f
│       │   ├── cloud.py            # §14.2 árbol IP → rDNS → CNAME → ASN
│       │   ├── cdn.py              # §14.3
│       │   ├── stack.py            # §14.4 Wappalyzer + whatweb cross
│       │   └── scoring.py          # §14.5 sistema de confianza y cruce
│       │
│       ├── tools/                  # wrappers a herramientas externas
│       │   ├── wafw00f_wrapper.py  # library
│       │   ├── whatweb_wrapper.py  # subprocess + JSON parsing
│       │   ├── nikto_wrapper.py    # subprocess + streaming monitor (§14.5.2)
│       │   ├── shodan_wrapper.py   # InternetDB (free) + Host API (opt)
│       │   ├── censys_wrapper.py   # free tier search + hosts
│       │   ├── builtwith_wrapper.py # opt, HTTP directo
│       │   └── wappalyzer_wrapper.py # python-Wappalyzer
│       │
│       ├── scoring/
│       │   ├── risk.py             # §6 rúbrica /15
│       │   ├── opportunity.py      # §7 booleanos RecommendsFortiAppSec/Web/CNAPP
│       │   └── rationale.py        # §7.5 templates de OpportunityRationale
│       │
│       └── config/
│           ├── discovery.yaml
│           ├── detection_rules.yaml
│           ├── scoring.yaml
│           ├── fortinet_products.yaml
│           ├── rationale_templates.yaml
│           └── nikto_skip.yaml
│
├── tests/
│   ├── fixtures/
│   │   ├── http/                   # responses HTTP grabadas (Cloudflare, AWS, Akamai, FortiWeb, …)
│   │   ├── dns/                    # respuestas DNS simuladas
│   │   ├── crt_sh/                 # respuestas crt.sh
│   │   ├── whatweb/                # outputs JSON de whatweb
│   │   ├── nikto/                  # outputs JSON de nikto
│   │   └── accounts/               # CSVs de entrada/salida golden
│   ├── unit/
│   └── integration/                # end-to-end contra fixtures
│
├── scripts/
│   ├── build-image.sh
│   └── bump-version.sh
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── release.yml
│       └── scan.yml
│
└── inputs/                         # fallback para cron (CSVs recurrentes, sanitizados)
    └── recurring.csv.example
```

### 17.3 Estructura de `cdt-infra`

```
cdt-infra/
├── CLAUDE.md
├── README.md
├── env/
│   ├── dev-persistent/
│   │   ├── backend.tf              # HCP Terraform workspace
│   │   ├── linode.tf               # g6-standard-1 Kali
│   │   ├── firewall.tf             # UFW + Linode firewall
│   │   ├── stackscript.tf          # ref a scripts/dev-init.sh
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── ephemeral/
│       ├── backend.tf              # HCP Terraform workspace distinto
│       ├── linode.tf               # g6-standard-1 Ubuntu, random_password
│       ├── firewall.tf
│       ├── stackscript.tf          # ref a scripts/ephemeral-init.sh
│       ├── variables.tf
│       └── outputs.tf
├── modules/
│   └── linode-base/                # módulo común (firewall baseline, SSH key)
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
├── scripts/
│   ├── dev-init.sh                 # StackScript persistente
│   └── ephemeral-init.sh           # StackScript efímero
├── policies/
│   └── checkov/                    # reglas custom de checkov para Terraform
├── .github/
│   └── workflows/
│       ├── validate.yml
│       ├── plan.yml
│       └── apply.yml
└── .terraform-docs.yml             # auto-doc para README de cada env
```

### 17.4 Stack técnico y pinning

| Componente | Versión objetivo | Pin strategy |
|---|---|---|
| Python | 3.12.x | Dockerfile base image + pyproject `requires-python` |
| typer | ~0.12 | `pyproject.toml` |
| pydantic | ~2.9 | `pyproject.toml` |
| httpx | ~0.27 | `pyproject.toml` |
| dnspython | ~2.7 | `pyproject.toml` |
| pytricia | ~1.0 | `pyproject.toml` |
| python-Wappalyzer | ~0.4 | `pyproject.toml` |
| wafw00f | 2.3.1 | `pyproject.toml` exacto |
| shodan | ~1.31 | `pyproject.toml` |
| censys | ~2.2 | `pyproject.toml` |
| rich | ~13 | `pyproject.toml` |
| structlog | ~24 | `pyproject.toml` |
| PyYAML | ~6.0 | `pyproject.toml` |
| pytest | ~8 (dev) | `pyproject.toml [project.optional-dependencies]` |
| ruff | ~0.5 (dev) | — |
| mypy | ~1.11 (dev) | — |
| kalilinux/kali-rolling | digest pinned | `Dockerfile` `FROM kalilinux/kali-rolling@sha256:...` |
| whatweb | apt package version de Kali vigente | `apt-mark hold` en Dockerfile |
| nikto | apt package version de Kali vigente | `apt-mark hold` |
| Terraform | 1.9.x | `required_version` en cada env |
| Linode provider | ~2.x | `required_providers` |

Dependabot (`dependabot.yml`) para alertas de vulnerabilidades, PRs semanales agrupados.

### 17.5 Skill `cdt-scanner-dev` — contenido concreto

Se crea con `skill-creator` al arrancar Fase 1. Ubicación: `.claude/skills/cdt-scanner-dev/SKILL.md` + templates anexos.

**Secciones del SKILL.md:**

1. **Convenciones de proyecto**
   - Naming de módulos, estructura de imports, estilo typer, patrones pydantic v2.
   - Cómo nombrar tests (`test_<module>__<behavior>.py`).
   - Uso de structlog (eventos nombrados, nunca f-strings).
   - Cómo agregar una firma nueva de WAF al `detection_rules.yaml` + fixture correspondiente.

2. **Templates embebidos**
   - `Dockerfile` multi-stage (builder + runtime) con apt-mark hold.
   - `pyproject.toml` con dependencias pinneadas.
   - `linode_instance` resource para Terraform.
   - `workflow_dispatch` de scan.yml con phase switch.
   - pydantic model template para una fila de `accounts_enriched.csv`.
   - Test template con `respx` para mockear httpx.

3. **Patterns idiomáticos**
   - Subprocess streaming wrapper (nikto monitor como referencia canónica).
   - Asyncio rate-limited task pool con `asyncio.Semaphore + asyncio.Queue`.
   - Retry con backoff exponencial vía `tenacity`.
   - YAML config load con validación pydantic.
   - CSV writer que preserva encoding UTF-8 con BOM para Excel.

4. **Decisiones ya tomadas (no re-debatir)**
   - Scope geográfico 7 países documental, no enforcement.
   - Nikto condicional + early termination.
   - Wappalyzer primario, BuiltWith opcional.
   - IP efímera en Prod, persistente en Dev.
   - Sin dominio propio para el scanner.

5. **Don'ts**
   - No hardcodear endpoints en código; leer de `config/*.yaml`.
   - No loguear `csv_content` completo ni cuerpos de respuesta del target.
   - No commitear CSVs reales al repo (usar `inputs/recurring.csv.example`).
   - No usar `print()`, siempre `structlog`.
   - No llamar APIs externas sin cache ni rate limit.

### 17.6 Flujo de trabajo con Claude Code

Cada fase del plan (§17.7) se ejecuta con este ritual:

1. **Issue en GitHub** describe el alcance de la fase (referencia al §N del spec).
2. **Claude Code abre rama** `feat/<fase>` desde `main`.
3. **init skill** genera/actualiza `CLAUDE.md` con contexto específico de la fase.
4. **cdt-scanner-dev skill** provee templates e idioms.
5. **Implementación iterativa**: Claude Code implementa, testea, commit. Tests rojos no se mergean.
6. **PR abierto**, **review skill** ejecuta revisión automatizada, **security-review skill** chequea postura.
7. **Human approval** del Tech Lead tras revisar findings de los skills.
8. **Merge a main** → CI publica imagen, issue se cierra.

Skills se invocan con `/skill` dentro de Claude Code; no hay lógica secreta, cada paso es auditable en git log.

### 17.7 Plan de trabajo por fases

Orden de construcción. Cada fase cierra con PR mergeado, imagen publicada en GHCR, y fixtures de tests pasando.

**Fase 0 — Bootstrap (2–3 días)**
- Crear repos `cdt-scanner` y `cdt-infra` en GitHub org.
- Configurar secrets iniciales (`LINODE_TOKEN`, `HCP_TF_TOKEN`, `SSH keys`).
- Crear workspaces HCP Terraform (`cdt-dev-persistent`, `cdt-ephemeral`).
- `init` skill → `CLAUDE.md` base en ambos repos con referencia a este spec.
- `skill-creator` → genera `cdt-scanner-dev` con templates y convenciones.
- Primer `terraform apply` manual del dev-persistent.
- Verificar SSH al dev Linode.

**Fase 1 — Scaffold Python (2 días)**
- `pyproject.toml` con deps pinneadas.
- `src/cdt/cli.py` con comandos `scan` / `validate` / `dry-run` / `doctor` (stub).
- `src/cdt/models.py` con pydantic models de entrada/salida.
- `Dockerfile` multi-stage con Kali base y whatweb/wafw00f/nikto.
- `tests/unit/test_models.py` con validación de CSVs.
- CI `ci.yml` operativo.

**Fase 2 — Discovery (3–4 días)**
- `discovery/google_cse.py` con Validate y Discover modes.
- `discovery/validator.py` (HEAD + parking detection + Title match).
- `discovery/expander.py` (crt.sh + ranking).
- Cache unificado en `~/.cache/cdt/discovery/`.
- Fixtures: 10 queries Google CSE grabadas + crt.sh responses.

**Fase 3 — Scan primitives (4–5 días)**
- `scan/passive.py` (DNS, WHOIS, IP range lookup con pytricia).
- `scan/browser.py` (GET /, robots, TLS handshake, header inspection).
- `scan/runner.py` (asyncio Semaphore, rate limit 2 RPS/dominio).
- `tools/wafw00f_wrapper.py` (library integration).

**Fase 4 — Tool wrappers (3–4 días)**
- `tools/whatweb_wrapper.py` (subprocess JSON).
- `tools/nikto_wrapper.py` (streaming monitor + early termination según §14.5.2).
- `tools/shodan_wrapper.py` (InternetDB free + Host API opt).
- `tools/censys_wrapper.py`.
- `tools/wappalyzer_wrapper.py`.
- `tools/builtwith_wrapper.py` (opt).

**Fase 5 — Detection engine (5–6 días)**
- `detect/waf.py` — catálogo §14.1 con reglas YAML.
- `detect/cloud.py` — árbol §14.2.
- `detect/cdn.py` — §14.3.
- `detect/stack.py` — §14.4.
- `detect/scoring.py` — sistema de confianza §14.5.
- Fixtures extensivos por vendor.

**Fase 6 — Scoring + Opportunity (2 días)**
- `scoring/risk.py` — rúbrica /15.
- `scoring/opportunity.py` — tres booleanos.
- `scoring/rationale.py` — templates.

**Fase 7 — Output y journal (2 días)**
- `io/csv_out.py` con los 4 CSVs + `nikto_runs.jsonl`.
- Formato exacto según §3.3–3.6.
- Golden file tests.

**Fase 8 — Infra efímera end-to-end (3–4 días)**
- `env/ephemeral/` completo en `cdt-infra`.
- `scan.yml` phase=prod operativo.
- StackScript ephemeral-init.sh.
- Test manual de apply + scan + destroy ≥ 3 veces.

**Fase 9 — MVP testing & hardening (4–5 días)**
- Integration tests end-to-end contra 3 sitios fixture reales (autorizados para pruebas).
- Golden file test sobre lista de 10 cuentas reales.
- `security-review` skill sobre toda la rama.
- Documentación runbook (§19).

**Fase 10 — Cutover Dev → Prod (1 día)**
- Ejecutar checklist §12.10.
- Deshabilitar `cdt-dev-persistent`.
- Cron schedule activado.
- Announce to stakeholders.

**Estimado total: 30–40 días hábiles**, asumiendo 1 dev + Claude Code + revisores disponibles.

### 17.8 Post-MVP (fuera de v0.4)

- `cdt-operator` MCP server (§15.4) para invocación desde Claude Cowork.
- Reportes automáticos DOCX/PDF por cuenta con skills `docx`/`pdf`.
- Deck comercial con skill `pptx` por cuenta de alto valor.
- Scheduling inteligente (mover cuentas críticas a la primera corrida del día).
- Evolución del catálogo §14 por feedback operativo.

---

## 19. Estrategia de tests

Cobertura por capa, organización de fixtures, mocking, y gates en CI. El objetivo es **detectar regresiones en el catálogo de detección antes de que lleguen a producción** y garantizar que los CSVs de salida son bit-exactos cuando la entrada y las reglas no cambian.

### 19.1 Pirámide de tests

```
         ┌─────────────────┐
         │  E2E (manual)   │  ← 3–5 tests contra sitios fixture reales autorizados
         └─────────────────┘
       ┌─────────────────────┐
       │ Integration (auto)  │  ← ~30 tests por módulo contra fixtures grabadas
       └─────────────────────┘
    ┌───────────────────────────┐
    │   Unit tests (auto)       │  ← ~200+ tests, coverage ≥ 80% por módulo
    └───────────────────────────┘
```

### 19.2 Unit tests

**Coverage targets (gated por CI):**

| Módulo | Coverage mínimo | Prioridad de tests |
|---|---|---|
| `detect/waf.py` | 90% | Cada firma del §14.1 tiene un test positivo + uno negativo |
| `detect/cloud.py` | 90% | Cada provider del §14.2 con match por IP, rDNS, ASN, CNAME |
| `detect/scoring.py` | 95% | Sistema de confianza, cruce de señales, ties y gaps |
| `scoring/opportunity.py` | 95% | Cada rama del árbol §7.3 |
| `scoring/risk.py` | 90% | Cada fila de la rúbrica §6 |
| `discovery/*.py` | 80% | Validate, Discover, Expand, cache keys |
| `scan/*.py` | 75% | Tier logic, rate limit, timeout |
| `tools/*.py` | 85% | Parsers de whatweb, nikto, Shodan, Censys |
| `io/*.py` | 85% | CSV encoding, headers, pydantic roundtrip |
| `cli.py` | 70% | Smoke tests por comando |

**Herramientas:**
- `pytest` + `pytest-cov` + `pytest-asyncio`.
- `respx` para mockear `httpx` (Google CSE, crt.sh, Shodan, Censys, BuiltWith).
- `dnspython` tiene un stub resolver; usamos `dnspython.resolver.override_system_resolver()` con fixtures.
- `unittest.mock.patch` para subprocess (whatweb, nikto).

**Convenciones**: tests nombrados `test_<module>__<behavior>.py::test_<scenario>`. Cada archivo de test importa solo el módulo que testea + fixtures comunes.

### 19.3 Fixtures — organización y fuentes

```
tests/fixtures/
├── http/
│   ├── waf/
│   │   ├── cloudflare_pro_challenge.json      # response con cf-ray + challenge page
│   │   ├── aws_waf_blocked.json                # 403 con body CloudFront
│   │   ├── azure_front_door_blocked.json
│   │   ├── akamai_ghost.json
│   │   ├── fortiweb_block_page.json
│   │   ├── imperva_incap.json
│   │   ├── f5_big_ip_rejected.json
│   │   ├── sucuri_blocked.json
│   │   └── ...  (una por vendor de §14.1)
│   ├── cdn/
│   │   ├── cloudflare_only_no_waf.json
│   │   ├── cloudfront_pass_through.json
│   │   └── fastly_hit.json
│   ├── stack/
│   │   ├── wordpress_6.5_exposed.json
│   │   ├── drupal_10.json
│   │   ├── magento_2_commerce.json
│   │   ├── openresty_banner.json
│   │   └── ...
│   └── mixed/
│       ├── tipti_grupo_favorita_public.json   # sitio real capturado (anonimizado)
│       └── ...
├── dns/
│   ├── aws_ec2_ptr.json                        # PTR → *.compute.amazonaws.com
│   ├── azure_cloudapp_ptr.json
│   ├── cloudflare_cname_chain.json
│   └── multi_region_cname.json
├── crt_sh/
│   ├── tipti_market_crtsh.json                 # subdominios históricos
│   └── ...
├── whatweb/
│   ├── wordpress_output.json                   # salida JSON de whatweb
│   ├── openresty_output.json
│   └── ...
├── nikto/
│   ├── software_id_only.txt                    # stdout streaming fixtures
│   ├── partial_before_termination.txt
│   └── full_run_authorized.json
├── shodan/
│   ├── internetdb_cloudflare_ip.json
│   └── host_api_aws_ec2.json
├── censys/
│   └── hosts_view_azure.json
├── ip_ranges/
│   ├── aws-mini.json                            # subset con 10 prefixes
│   ├── azure-mini.json
│   ├── gcp-mini.json
│   └── oci-mini.json
└── accounts/
    ├── ecuador_sample_10_in.csv
    ├── ecuador_sample_10_enriched_golden.csv   # golden file
    └── ...
```

**Fuente de las fixtures:**
- **Capturadas reales de sitios autorizados** (plan de pruebas en Fase 9 incluye lista de 3-5 sitios donde tienes permiso explícito de grabar respuestas).
- **Sintéticas curadas** (cloudflare/akamai/etc. basadas en documentación oficial del vendor).
- **Crowdsourced de GitHub** (hay repos públicos con responses de WAFs famosos que podemos usar con atribución).

**Regla de actualización**: una firma nueva en `detection_rules.yaml` no se mergea sin fixture correspondiente. CI falla si falta.

### 19.4 Mocking strategy

| Capa | Estrategia | Por qué |
|---|---|---|
| HTTP outbound (`httpx`) | `respx` intercepta URLs, devuelve fixture | Sin tráfico real a APIs externas en unit/integration |
| DNS | `dnspython` override resolver + fixture JSON | Respuestas determinísticas |
| Subprocess (whatweb, nikto) | `unittest.mock.patch("subprocess.Popen")` devuelve process mock con stdout de fixture | Sin ejecutar binarios en CI |
| Filesystem | `tmp_path` fixture de pytest | Isolation entre tests |
| Clock | `freezegun` para timestamps determinísticos | Golden files reproducibles |
| Rate limiting / asyncio | Timeouts reducidos, `asyncio.sleep` mockeado | Tests rápidos |

**NO se mockean:**
- Pydantic validation (es el SUT para los tests de `models.py`).
- Lógica de scoring `detect/scoring.py` (es el SUT).

### 19.5 Integration tests

Ejecutan el pipeline completo sobre CSVs fixture, con HTTP/DNS/subprocess mockeados. Verifican que los módulos se orquestan correctamente.

**Casos canónicos:**

| Test | Input | Expectativa |
|---|---|---|
| `test_e2e_clean_site_with_waf` | 1 cuenta, sitio con Cloudflare WAF | `WAF=Yes, WAFVendor=Cloudflare, Recommends*=No` |
| `test_e2e_no_waf_single_csp` | 1 cuenta, AWS single CSP sin WAF | `RecommendsFortiAppSec=Yes`, resto `No` |
| `test_e2e_multi_csp_with_fortinet` | 1 cuenta, AWS + GCP + FortiWeb | `RecommendsFortiCNAPP=Yes`, resto `No` |
| `test_e2e_nikto_triggers_on_unresolved` | 1 cuenta con Server header oculto | nikto se invoca, early termination al resolver WebServer |
| `test_e2e_nikto_skipped_when_resolved` | 1 cuenta con WAF+stack detectado por wafw00f+whatweb | nikto NO se invoca |
| `test_e2e_discovery_validates_ok` | Website correcto | Se escanea sin ir a validation_issues |
| `test_e2e_discovery_typo` | Website mal escrito | Va a validation_issues con sugerencia |
| `test_e2e_unsupported_country` | Country=Brasil | Warning en log, sigue escaneando |
| `test_e2e_multi_site_primary_plus_4` | 1 cuenta con 5 subdominios vivos | Website01–05 poblados, sites.csv con 5 filas |

### 19.6 Golden file tests

Para cada CSV de salida (`accounts_enriched.csv`, `sites.csv`, `findings.csv`), se mantiene un archivo "golden" en `tests/fixtures/accounts/*_golden.csv`. El test compara byte-a-byte la salida con el golden.

**Reglas:**
- Se incluyen al menos 3 escenarios: "happy path all resolved", "nikto triggered early-term", "discovery failure".
- Actualizar el golden requiere un commit explícito con comentario justificando el cambio.
- El CI reporta diff cuando falla, para revisión manual.

### 19.7 CI integration

`ci.yml` en `cdt-scanner`:

```yaml
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - ruff check
      - mypy src/
      - pytest tests/unit --cov=src/cdt --cov-fail-under=80
      - pytest tests/integration
      - docker build . --target test   # smoke
```

En PR:
- Si coverage baja: bloqueado hasta remediar.
- Si golden file falla: bloqueado hasta actualizar golden con justificación.
- Si falta fixture para nueva regla en `detection_rules.yaml`: bloqueado.

`security-review` skill corre como job separado (comment-only, no bloquea pero se lee antes de aprobar).

### 19.8 Política de regresión del catálogo §14

Cada PR que toque `detection_rules.yaml`, `tools/*_wrapper.py`, o `detect/*.py` **debe** incluir:

1. **Fixture HTTP** correspondiente (respuesta que dispara la regla).
2. **Unit test** con dos casos: hit (positivo) y no-hit (negativo con una respuesta cercana pero distinta).
3. **Golden file regenerado** si el cambio afecta el output.

PR sin esos tres artefactos → CI falla con mensaje explicativo.

### 19.9 Performance y carga (opcional v0.5+)

No bloqueantes para MVP. Cuando haga falta:
- Benchmark de scan por cuenta: target < 90 s/sitio en Tier 2 default (sin nikto).
- Test de concurrencia: 20 cuentas paralelas sin degradación.
- Test de quota: verificar que Google CSE cache sirve > 95% en corridas repetidas.

---

## 20. Runbook operativo

Playbook para cuando algo se rompe o necesita mantenimiento. Vive en `docs/RUNBOOK.md` del repo `cdt-scanner` además del spec, para que el operador lo tenga a mano.

### 20.1 Pre-flight checklist (antes de cada run programada)

- [ ] Último PR mergeado tiene CI verde y `security-review` sin issues críticas.
- [ ] HCP Terraform dashboard muestra `cdt-ephemeral` en estado "no infrastructure" (no hay VM orphaned).
- [ ] GitHub Actions: no hay runs corriendo o colgados para `scan.yml`.
- [ ] Google CSE quota del día: chequear `cdt doctor --cse-quota` — debe mostrar < 70% usado antes de una corrida grande.
- [ ] GitHub Actions artifacts del repo dentro de quota (en repo Settings → Actions → check "Artifact storage usage", ~50-100 MB por run).
- [ ] Última rotación de secrets fue hace < 90 días (si > 90 días, ver §20.4).

### 20.2 Flujo operativo normal (Fase Prod)

1. **Operador abre** `github.com/<org>/cdt-scanner/actions/workflows/scan.yml`.
2. Click "Run workflow".
3. Completa:
   - `phase`: prod
   - `tier`: browser (default)
   - `csv_content`: pegar contenido del CSV, o dejar vacío para usar `inputs/recurring.csv` del repo.
   - `country_filter`: vacío (todos) o "Ecuador", "Perú", etc.
4. Click "Run". El workflow:
   - Valida headers del CSV (falla temprano si mal formateado).
   - `terraform apply` provisiona VM efímero (~2 min).
   - Corre el scan (~50 min para 500 cuentas).
   - Sube outputs como artifact `cdt-scan-<run_id>` (retention 30 días).
   - `terraform destroy` (~1 min).
5. Operador verifica:
   - Run en estado verde en la UI de GitHub Actions.
   - Artifact disponible para descarga al pie de la página del run.
   - Notificación de fallo si hubo error (configurable).
6. Operador descarga el artifact, descomprime, sigue §11.2 para hacer paste en SharePoint List.
7. Si hay `validation_issues.csv` con filas, el operador las revisa y corrige en la siguiente corrida (modo Discover failed o validation issues).

### 20.3 Fallas comunes y respuesta

#### 20.3.1 Workflow falla en paso "Terraform apply"

**Síntomas**: error en el job con mensaje de Linode API ("rate limit", "auth failed", "region unavailable").

**Diagnóstico**:
1. Revisar logs del paso `terraform apply` en GitHub Actions.
2. Validar `LINODE_TOKEN` → en GitHub Settings → Secrets, verificar que existe y no está expirado.
3. Probar localmente: `curl -H "Authorization: Bearer $LINODE_TOKEN" https://api.linode.com/v4/profile`.

**Respuesta**:
- Si token inválido: rotar (ver §20.4).
- Si rate limit: esperar 5 min, reintentar (Linode API permite 800 requests/minute).
- Si region `us-east` caída: editar `env/ephemeral/variables.tf` → cambiar region a `us-southeast`, PR + apply. Reintento del scan.

#### 20.3.2 SSH al VM efímero timeout

**Síntomas**: workflow espera 150s y falla con "Connection refused" o "nc: connect timed out".

**Diagnóstico**:
1. StackScript `ephemeral-init.sh` puede estar tardando más de lo previsto (paquetes lentos, mirror apt down).
2. Linode firewall mal configurado.

**Respuesta**:
- Aumentar loop de `nc -z` a 60 intentos × 5s = 5 min.
- Si persiste: SSH manual a la IP (obtenida del Terraform output) para investigar. Si el SSH manual también falla, `terraform destroy` y reintentar.
- Log del StackScript queda en Linode Manager → Events → View StackScript output.

#### 20.3.3 Docker pull de GHCR falla

**Síntomas**: "unauthorized" o "manifest unknown".

**Diagnóstico**:
1. La imagen `ghcr.io/<org>/cdt:latest` podría no existir (release pipeline nunca corrió).
2. Token `GITHUB_TOKEN` puede no tener permisos `read:packages`.

**Respuesta**:
- Verificar últimos releases en GHCR (UI del package).
- Si no hay imagen: correr `release.yml` manualmente con un tag.
- Si permisos: Settings → Packages → visibility del package (private → visible por repo actions).

#### 20.3.4 Google CSE quota exhausted mid-run

**Síntomas**: en el log aparece "Google CSE quota exceeded (daily limit 100)", las siguientes cuentas caen a `validation_issues.csv` con reason `QUOTA_EXCEEDED`.

**Respuesta inmediata**:
- Dejar correr el scan; las cuentas que ya descubrieron website se escanean normalmente. Solo las que requerían discovery nuevo fallan.
- Cuenta `doctor`: `cdt doctor --cse-quota` para confirmar estado.

**Respuesta estructural**:
- Habilitar billing en Google Cloud y subir quota a 10,000/día ($5/1000 queries extra).
- Alternativa: pagar para acelerar, o partir la corrida en días.

#### 20.3.5 Artifact upload falla

**Síntomas**: paso "Upload outputs as artifact" falla con error de quota o conectividad.

**Diagnóstico**:
1. Settings → Actions → Storage usage. Si la organización agotó quota gratuita (500 MB en plan Free, 50 GB en Team, 250 GB en Enterprise), los uploads fallan.
2. Posibles errores transitorios de GitHub Actions infra.

**Respuesta**:
- **Quota agotada**: aumentar plan, o eliminar artifacts viejos via Settings → Actions → Artifacts (purge manual o automatizar con `actions/delete-artifacts`).
- **Error transitorio**: re-run del workflow. Los outputs están en el VM efímero hasta que `terraform destroy` corra; si hay urgencia, comentar el destroy step y SSH al VM para SCP los outputs antes de destruirlo.
- **Mitigación preventiva**: agregar retención reducida (`retention-days: 14`) si el storage se llena seguido. Job de housekeeping que borra artifacts > 30 días.

#### 20.3.6 Ban de IP detectado mid-run (Fase Prod)

**Síntomas**: muchos sitios consecutivos devuelven 403 con body de WAF bloqueando al scanner (ej. Cloudflare "You have been blocked"). `findings.csv` se llena de eventos `FAILED_SCAN_POSSIBLE_BAN`.

**Respuesta inmediata**:
- La run actual probablemente seguirá fallando. Dejarla terminar; `terraform destroy` libera la IP "quemada" automáticamente.
- La próxima run tendrá IP diferente (nueva VM efímera).

**Respuesta si pasa recurrente**:
- Bajar Tier o desactivar nikto globalmente: `CDT_NIKTO_ENABLED=false` como variable del run.
- Revisar si hay `-Tuning` en nikto demasiado agresivo; ajustar en `config/nikto_skip.yaml`.

#### 20.3.7 nikto streaming parser falla silencioso

**Síntomas**: `nikto_runs.jsonl` muestra runs sin `termination=resolved`, siempre `timeout`. Sugiere que el regex que detecta fields resueltos en stdout de nikto no matchea.

**Diagnóstico**:
1. Comparar stdout capturado (en artifact) contra fixtures de `tests/fixtures/nikto/`.
2. Posible cambio en formato de nikto por actualización apt.

**Respuesta**:
- Pinear versión de nikto en Dockerfile (`apt install nikto=<version>` + `apt-mark hold`).
- Actualizar regex en `tools/nikto_wrapper.py` si la versión nueva es intencionalmente actualizada.
- Agregar fixture correspondiente.

#### 20.3.8 Terraform destroy falla — VM orphaned

**Síntomas**: workflow termina con destroy failed. Linode Manager muestra el VM todavía corriendo.

**Respuesta**:
- Ejecutar `terraform destroy -auto-approve -var run_id=<run_id>` localmente en el checkout de `cdt-infra`.
- Si eso falla: borrar el VM manualmente desde Linode Manager UI, + `terraform state rm linode_instance.ephemeral_cdt`.
- Documentar en issue de GitHub para investigar causa raíz.

**Costo residual**: un VM orphaned cuesta ~$0.50/día si se olvida. Alerta recomendada: script diario que lista VMs con label `cdt-eph-*` y reporta los de > 24h.

#### 20.3.9 SharePoint schema drift

**Síntomas**: Power Automate falla con "Column not found" o los valores no cargan.

**Diagnóstico**:
1. Alguien modificó columnas de la SharePoint List manualmente.
2. El CSV generado tiene nombres/tipos que ya no coinciden.

**Respuesta**:
- Comparar columnas esperadas (§3.3) vs columnas reales en SharePoint.
- Si alguien borró una columna: recrearla con el tipo correcto.
- Si se agregaron columnas nuevas: el CSV no las poblará (no es error crítico).
- Documentar regla: **cambios al schema de la SharePoint List requieren PR al spec + actualización de §3.3**.

#### 20.3.10 Discovery NOT_FOUND masivo

**Síntomas**: `validation_issues.csv` tiene > 30% de las cuentas con `NO_RESULTS` o `LOW_CONFIDENCE`.

**Diagnóstico**:
- Posible: Google CSE Programmable Search Engine mal configurado (ej. filtros geográficos demasiado restrictivos).
- Posible: CSV de input con Titles en idioma/formato que CSE no indexa bien (acrónimos sin contexto).

**Respuesta**:
- Validar manualmente 3 cuentas NOT_FOUND: ¿Google las encuentra en búsqueda web normal?
- Si sí → ajustar `engine_id` o expandir `blacklisted_domains`.
- Si no → el operador añade `Website` manualmente en el CSV (modo Scan-only).

### 20.4 Rotación de secrets

**Cadencia obligatoria**: trimestral (90 días). Excepción: rotación inmediata si alguien con acceso al secret deja el equipo.

**Orden de rotación**:

1. **`GOOGLE_CSE_API_KEY`**: Google Cloud Console → API credentials → regenerate → actualizar GH Secret.
2. **`LINODE_TOKEN`**: Linode Manager → Personal Access Tokens → crear nuevo → revocar anterior → actualizar GH Secret.
3. **`HCP_TF_TOKEN`**: HCP Terraform → User Settings → Tokens → nuevo → revocar anterior → actualizar GH Secret.
4. **SSH keys (`EPHEMERAL_SSH_KEY` + pubkey en Terraform)**:
   - Generar par nuevo: `ssh-keygen -t ed25519 -f ~/.ssh/cdt-ephemeral-new`.
   - Actualizar GH Secret `EPHEMERAL_SSH_KEY` (privada).
   - Actualizar variable Terraform `ssh_pubkey` en HCP → `terraform apply` en `cdt-dev-persistent`.
   - Para `cdt-ephemeral`, la pubkey se lee de la variable en cada run nuevo, así que se actualiza automáticamente.
5. **`INFRA_TOKEN`**: fine-grained PAT en GitHub → regenerar → actualizar GH Secret.
6. **`GH_RUNNER_TOKEN`** (Fase Dev): Settings → Actions → Runners → desregistrar runner actual → generar nuevo token → `terraform taint linode_instance.dev_cdt && terraform apply` (el StackScript re-registra con el nuevo token).

Documentar la rotación en `docs/secret-rotation-log.md` con fecha, operador, secret rotado.

### 20.5 Rotación de IP del dev Linode

Cuando la IP del dev-cdt está quemada (sitios legítimos la bloquean y estás debuggeando):

```bash
cd cdt-infra/env/dev-persistent
terraform taint -target=linode_instance.dev_cdt
terraform apply
```

Tiempo: ~3 min. Disco/data NO se pierde porque el StackScript re-corre y GHCR tiene la imagen. Pero:
- Se pierde la sesión SSH activa.
- Cualquier estado local del operador en el VM (notas, logs en `~/`) se pierde — usar `git` o `scp` para preservar antes.

Para rotación que sí preserve disco: Linode → Rebuild con la misma imagen → mantiene volume. Costo: ~5 min downtime, IP nueva.

### 20.6 Playbook de respuesta a queja de abuse

Si Linode notifica una queja (email al account holder):

**Paso 1 — Clasificar** (dentro de 4h de recibida):

| Tipo de queja | Severidad |
|---|---|
| "Tu IP escaneó mi sitio" sin más detalle | Baja — responder con explicación del proyecto |
| "Tu IP intentó ataques brute force" | Alta — investigar; si cierto, apagar esa run y tool |
| "Denuncia formal con referencia legal" | Crítica — consultar legal + pausar operaciones |

**Paso 2 — Responder** (dentro de 24h):

Template para queja baja:

```
Hola,

Soy [Dave], propietario de la cuenta Linode referenciada. Agradezco el aviso.

La IP en cuestión corresponde a un proyecto de investigación en ciberseguridad
que realiza descubrimiento de superficie pública de sitios web. El alcance se
limita a peticiones equivalentes a un navegador normal (User-Agent: CDT/0.4
(research scanner)) y, en casos excepcionales, fingerprinting de software.

No realizamos intentos de explotación ni de acceso no autorizado.

Para excluir su dominio de futuras corridas, por favor envíeme el dominio o
rango y lo agrego inmediatamente a nuestra allowlist.

Atentamente,
[Dave]
```

**Paso 3 — Agregar el dominio al allowlist** (dentro de 24h):

- Editar `config/nikto_skip.yaml` del repo `cdt-scanner` → agregar el dominio.
- Editar `config/scan_exclusions.yaml` (si no existe, se crea) → agregar para excluir completamente de futuras corridas.
- PR → merge.

**Paso 4 — Escalar si severidad Alta/Crítica**:

- Pausar `scan.yml` (cambiar `on: schedule` a comentado o deshabilitar el workflow en GitHub UI).
- Crear issue en el repo con contexto.
- Consultar con legal de la organización antes de responder formalmente.
- Preservar logs relevantes (del run, de nikto journal) como evidencia.

### 20.7 Escalamiento y contactos

| Situación | Contacto |
|---|---|
| Problema técnico del tool | Dev principal (Dave) |
| Queja de abuse baja/media | Dave responde directo |
| Queja legal / citación | Legal corporativo + Dave |
| Brecha de seguridad (secrets comprometidos) | Security team + rotar todos los secrets en 2h |
| Linode suspende la cuenta | Dave + appeal a Linode support |
| Power Automate / SharePoint roto | IT / M365 admin |

Mantener estos contactos actualizados en `docs/CONTACTS.md` del repo.

---

*Fin de v0.4 — spec completo. Próximo hito: comenzar Fase 0 de §17.7 cuando esté aprobado.*
