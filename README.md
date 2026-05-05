# cdt-scanner

CDT (Cloud Development Tool) is a website discovery and exposure scanner aimed at Fortinet AppSec opportunities in LATAM. It takes a CSV of accounts (`Title, Country, Website`), validates and discovers domains, scans with Kali tooling (whatweb, wafw00f, nikto), attributes cloud provider, detects WAFs/CDNs, computes a `RiskScore /15` and emits three Fortinet recommendation booleans.

## Geographic scope

The tool is designed for 7 LATAM countries: **Perú, Ecuador, Chile, Bolivia, Paraguay, Uruguay, Venezuela** (spec v0.4 §12.13). Inputs from other countries are accepted with a warning, but using the tool outside the documented scope is the operator's responsibility.

## Quick start

```bash
# Inside the container (recommended)
docker run --rm \
  -v "$PWD/in:/app/in:ro" \
  -v "$PWD/out:/app/out" \
  -e BRAVE_SEARCH_API_KEY \
  ghcr.io/fortidz/cdt:latest \
  scan --in /app/in/accounts_in.csv --out /app/out/

# Discover commands and flags
cdt --help
cdt scan --help
```

## Specs

- `docs/spec/spec-cdt-v0.4.md` — base spec.
- `docs/spec/spec-cdt-v0.5.md` — delta on v0.4 (CLI, post-MVP pipeline, detection rule pack).

If the two specs conflict, **v0.5 wins**.

## Development

See `CLAUDE.md` for project conventions, stack pins, and the phased build plan.
