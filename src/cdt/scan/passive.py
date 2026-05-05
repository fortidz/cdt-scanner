"""Passive scanner — DNS / WHOIS / ASN / cloud attribution.

Passive means: no traffic to the target. Only resolution against public
infrastructure (DNS roots, WHOIS registrars, RDAP) and lookups against
locally-cached IP range databases.

Cloud attribution decision tree (v0.4 §14.2):

    1. ip_range — pytricia trie hit (high confidence)
    2. rdns     — reverse DNS suffix match (medium)
    3. cname    — CNAME chain suffix match (medium)
    4. asn      — ASN -> provider table (low)
    5. unknown  — none of the above (low)
"""

from __future__ import annotations

import asyncio
import fnmatch
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx
import pytricia
import structlog

from cdt.discovery.cache import DiscoveryCache
from cdt.scan.models import (
    ASNResult,
    CloudAttribution,
    CloudConfidence,
    CloudSource,
    DNSResult,
    IPRangeMatch,
    PassiveResult,
    WhoisResult,
)

log = structlog.get_logger()

_PROVIDER_NAME_IP_RANGES = "ip_ranges"
_CACHE_KEY_PREFIX = "ip_ranges::"

# ASN -> provider. Mirrors v0.4 §14.2.3; canonical copy lives in
# ``config/scan.yaml`` and overrides this when the orchestrator (Phase 6+)
# wires loaders. Phase 3 keeps it as a constant so the unit suite is hermetic.
_DEFAULT_ASN_TABLE: dict[int, str] = {
    14618: "AWS", 16509: "AWS", 14061: "AWS",
    8075: "Azure", 8068: "Azure",
    15169: "GCP",
    31898: "OCI", 63775: "OCI",
    13335: "Cloudflare",
    20940: "Akamai", 16625: "Akamai", 16702: "Akamai",
    54113: "Fastly",
}

_DEFAULT_RDNS_PATTERNS: dict[str, list[str]] = {
    "AWS": ["*.compute.amazonaws.com", "*.compute-1.amazonaws.com",
            "*.cloudfront.net", "*.amazonaws.com"],
    "Azure": ["*.cloudapp.net", "*.cloudapp.azure.com",
              "*.azurewebsites.net", "*.azureedge.net", "*.azurefd.net"],
    "GCP": ["*.googleusercontent.com", "*.1e100.net",
            "*.bc.googleusercontent.com"],
    "OCI": ["*.oraclecloud.com", "*.oraclevcn.com"],
    "Cloudflare": ["*.cloudflare.com", "*.cloudflaressl.com"],
    "Akamai": ["*.akamaiedge.net", "*.edgekey.net",
               "*.edgesuite.net", "*.akamaized.net"],
}

_DEFAULT_IP_RANGE_URLS: dict[str, str] = {
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    "oci": "https://docs.oracle.com/iaas/tools/public_ip_ranges.json",
    "cloudflare_v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare_v6": "https://www.cloudflare.com/ips-v6",
    "fastly": "https://api.fastly.com/public-ip-list",
}


class IPRangesIndex:
    """Loads provider IP-range datasets and answers ``lookup(ip) → match?``.

    Each provider is fetched independently; a failure in one (timeout, 4xx,
    5xx) logs a warning and skips that provider — the index degrades
    gracefully so a single rotted URL cannot break passive attribution.
    """

    def __init__(
        self,
        cache: DiscoveryCache,
        urls: dict[str, str] | None = None,
        ttl_hours: int = 24,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache = cache
        self._urls = urls or _DEFAULT_IP_RANGE_URLS
        self._ttl_hours = ttl_hours
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None
        self._trie_v4: pytricia.PyTricia = pytricia.PyTricia(32)
        self._trie_v6: pytricia.PyTricia = pytricia.PyTricia(128)
        self._loaded = False

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def load_or_refresh(self) -> None:
        """Pull every dataset (cached for ``ttl_hours``) and rebuild the trie."""

        for provider, url in self._urls.items():
            try:
                payload = await self._fetch_dataset(provider, url)
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
                log.warning(
                    "passive_ip_ranges_fetch_failed",
                    provider=provider,
                    url=url,
                    error=str(exc),
                )
                continue

            try:
                self._ingest(provider, payload)
            except (ValueError, KeyError, TypeError) as exc:
                log.warning(
                    "passive_ip_ranges_parse_failed",
                    provider=provider,
                    error=str(exc),
                )
                continue

        self._loaded = True
        log.info(
            "passive_ip_ranges_loaded",
            v4_prefixes=len(list(self._trie_v4)),
            v6_prefixes=len(list(self._trie_v6)),
        )

    async def _fetch_dataset(self, provider: str, url: str) -> dict[str, Any] | str:
        cache_key = f"{_CACHE_KEY_PREFIX}{provider}"
        cached = self._cache.get(_PROVIDER_NAME_IP_RANGES, cache_key)
        if cached is not None:
            cached_payload = cached.get("payload", cached)
            if isinstance(cached_payload, (dict, str)):
                return cached_payload

        response = await self._client.get(url)
        response.raise_for_status()

        content_type = response.headers.get("content-type", "")
        payload: dict[str, Any] | str
        if "json" in content_type or url.endswith(".json"):
            parsed = response.json()
            payload = parsed if isinstance(parsed, dict) else {"raw": parsed}
        else:
            payload = response.text

        # ``DiscoveryCache.set`` requires a dict; wrap text payloads.
        cached_value: dict[str, Any] = (
            payload
            if isinstance(payload, dict)
            else {"payload": payload, "_text": True}
        )
        self._cache.set(
            _PROVIDER_NAME_IP_RANGES,
            cache_key,
            cached_value,
            ttl_hours=self._ttl_hours,
        )
        return payload

    def _ingest(self, provider: str, payload: dict[str, Any] | str) -> None:
        if provider == "aws" and isinstance(payload, dict):
            self._ingest_aws(payload)
        elif provider == "gcp" and isinstance(payload, dict):
            self._ingest_gcp(payload)
        elif provider == "oci" and isinstance(payload, dict):
            self._ingest_oci(payload)
        elif provider in {"cloudflare_v4", "cloudflare_v6"} and isinstance(payload, str):
            self._ingest_cloudflare(provider, payload)
        elif provider == "fastly" and isinstance(payload, dict):
            self._ingest_fastly(payload)

    def _ingest_aws(self, payload: dict[str, Any]) -> None:
        for entry in payload.get("prefixes", []):
            cidr = entry.get("ip_prefix")
            if not isinstance(cidr, str):
                continue
            self._trie_v4[cidr] = IPRangeMatch(
                provider="AWS",
                prefix=cidr,
                region=entry.get("region"),
                service=entry.get("service"),
            )
        for entry in payload.get("ipv6_prefixes", []):
            cidr = entry.get("ipv6_prefix")
            if not isinstance(cidr, str):
                continue
            self._trie_v6[cidr] = IPRangeMatch(
                provider="AWS",
                prefix=cidr,
                region=entry.get("region"),
                service=entry.get("service"),
            )

    def _ingest_gcp(self, payload: dict[str, Any]) -> None:
        for entry in payload.get("prefixes", []):
            v4 = entry.get("ipv4Prefix")
            v6 = entry.get("ipv6Prefix")
            if isinstance(v4, str):
                self._trie_v4[v4] = IPRangeMatch(
                    provider="GCP",
                    prefix=v4,
                    region=entry.get("scope") or entry.get("region"),
                    service=entry.get("service"),
                )
            if isinstance(v6, str):
                self._trie_v6[v6] = IPRangeMatch(
                    provider="GCP",
                    prefix=v6,
                    region=entry.get("scope") or entry.get("region"),
                    service=entry.get("service"),
                )

    def _ingest_oci(self, payload: dict[str, Any]) -> None:
        for region in payload.get("regions", []):
            region_name = region.get("region")
            for cidr_block in region.get("cidrs", []):
                cidr = cidr_block.get("cidr")
                if not isinstance(cidr, str):
                    continue
                trie = self._trie_v6 if ":" in cidr else self._trie_v4
                trie[cidr] = IPRangeMatch(
                    provider="OCI",
                    prefix=cidr,
                    region=region_name,
                    service=",".join(cidr_block.get("tags", []))
                    if cidr_block.get("tags")
                    else None,
                )

    def _ingest_cloudflare(self, provider: str, payload: str) -> None:
        is_v6 = provider == "cloudflare_v6"
        trie = self._trie_v6 if is_v6 else self._trie_v4
        for line in payload.splitlines():
            cidr = line.strip()
            if not cidr:
                continue
            trie[cidr] = IPRangeMatch(provider="Cloudflare", prefix=cidr)

    def _ingest_fastly(self, payload: dict[str, Any]) -> None:
        for cidr in payload.get("addresses", []):
            if isinstance(cidr, str):
                self._trie_v4[cidr] = IPRangeMatch(provider="Fastly", prefix=cidr)
        for cidr in payload.get("ipv6_addresses", []):
            if isinstance(cidr, str):
                self._trie_v6[cidr] = IPRangeMatch(provider="Fastly", prefix=cidr)

    def lookup(self, ip: str) -> IPRangeMatch | None:
        if not ip:
            return None
        trie = self._trie_v6 if ":" in ip else self._trie_v4
        try:
            match = trie.get(ip)
        except (KeyError, ValueError):
            return None
        if isinstance(match, IPRangeMatch):
            return match
        return None


class PassiveScanner:
    def __init__(
        self,
        ip_ranges: IPRangesIndex,
        timeout_sec: float = 10.0,
        asn_table: dict[int, str] | None = None,
        rdns_patterns: dict[str, list[str]] | None = None,
        resolver: dns.asyncresolver.Resolver | None = None,
    ) -> None:
        self._ip_ranges = ip_ranges
        self._timeout = timeout_sec
        self._asn_table = asn_table or _DEFAULT_ASN_TABLE
        self._rdns_patterns = rdns_patterns or _DEFAULT_RDNS_PATTERNS
        self._resolver = resolver or dns.asyncresolver.Resolver()

    async def resolve_dns(self, apex: str) -> DNSResult:
        a_records: list[str] = []
        aaaa_records: list[str] = []
        cname_chain: list[str] = []

        cname_chain = await self._follow_cname(apex)
        terminal = cname_chain[-1] if cname_chain else apex

        a_records = await self._resolve_records(terminal, "A")
        aaaa_records = await self._resolve_records(terminal, "AAAA")

        log.info(
            "passive_dns_resolved",
            apex=apex,
            a=len(a_records),
            aaaa=len(aaaa_records),
            cname_hops=len(cname_chain),
        )
        return DNSResult(
            apex=apex,
            a_records=a_records,
            aaaa_records=aaaa_records,
            cname_chain=cname_chain,
        )

    async def _follow_cname(self, name: str, max_hops: int = 10) -> list[str]:
        chain: list[str] = []
        current = name
        for _ in range(max_hops):
            try:
                answer = await self._resolver.resolve(current, "CNAME")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break
            except dns.exception.DNSException:
                break
            try:
                target = str(answer[0].target).rstrip(".")
            except (IndexError, AttributeError):
                break
            if not target or target == current:
                break
            chain.append(target)
            current = target
        return chain

    async def _resolve_records(self, name: str, rrtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rrtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException:
            return []

        out: list[str] = []
        for record in answer:
            try:
                out.append(record.address)
            except AttributeError:
                out.append(str(record))
        return out

    async def whois_lookup(self, apex: str) -> WhoisResult:
        try:
            entry = await asyncio.to_thread(_run_whois, apex)
        except Exception as exc:  # noqa: BLE001
            log.warning("passive_whois_failed", apex=apex, error=str(exc))
            return WhoisResult(apex=apex)

        log.info("passive_whois_done", apex=apex, registrar=entry.get("registrar"))
        return WhoisResult(
            apex=apex,
            registrar=_first_str(entry.get("registrar")),
            created=_first_dt(entry.get("creation_date")),
            updated=_first_dt(entry.get("updated_date")),
            expires=_first_dt(entry.get("expiration_date")),
            name_servers=_str_list(entry.get("name_servers")),
            raw_text=_first_str(entry.get("text")) if entry.get("text") else None,
        )

    async def asn_lookup(self, ip: str) -> ASNResult:
        try:
            data = await asyncio.to_thread(_run_ipwhois, ip)
        except Exception as exc:  # noqa: BLE001
            log.warning("passive_asn_failed", ip=ip, error=str(exc))
            return ASNResult(ip=ip)

        asn_raw = data.get("asn")
        asn_num: int | None
        if asn_raw in (None, "", "NA"):
            asn_num = None
        else:
            try:
                asn_num = int(asn_raw)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                asn_num = None

        log.info("passive_asn_resolved", ip=ip, asn=asn_num)
        return ASNResult(
            ip=ip,
            asn=asn_num,
            asn_org=_first_str(data.get("asn_description")),
            asn_country=_first_str(data.get("asn_country_code")),
            asn_description=_first_str(data.get("asn_description")),
        )

    async def attribute_cloud(
        self, dns_result: DNSResult, asn: ASNResult | None
    ) -> CloudAttribution:
        # 1. IP range trie lookup — strongest signal.
        for ip in dns_result.a_records + dns_result.aaaa_records:
            match = self._ip_ranges.lookup(ip)
            if match is not None:
                attribution = CloudAttribution(
                    provider=match.provider,
                    source=CloudSource.IP_RANGE,
                    confidence=CloudConfidence.HIGH,
                    matched_value=match.prefix,
                )
                log.info(
                    "passive_cloud_attributed",
                    provider=match.provider,
                    source="ip_range",
                    prefix=match.prefix,
                )
                return attribution

        # 2. Reverse DNS — match against suffix patterns per provider.
        for ip in dns_result.a_records:
            try:
                rev = await self._reverse_dns(ip)
            except Exception:  # noqa: BLE001
                rev = None
            if rev:
                provider = _match_rdns(rev, self._rdns_patterns)
                if provider:
                    log.info(
                        "passive_cloud_attributed",
                        provider=provider,
                        source="rdns",
                        rdns=rev,
                    )
                    return CloudAttribution(
                        provider=provider,
                        source=CloudSource.RDNS,
                        confidence=CloudConfidence.MEDIUM,
                        matched_value=rev,
                    )

        # 3. CNAME chain — match against the same suffix table.
        for cname in dns_result.cname_chain:
            provider = _match_rdns(cname, self._rdns_patterns)
            if provider:
                log.info(
                    "passive_cloud_attributed",
                    provider=provider,
                    source="cname",
                    cname=cname,
                )
                return CloudAttribution(
                    provider=provider,
                    source=CloudSource.CNAME,
                    confidence=CloudConfidence.MEDIUM,
                    matched_value=cname,
                )

        # 4. ASN table — last resort.
        if asn and asn.asn is not None:
            provider = self._asn_table.get(asn.asn)
            if provider:
                log.info(
                    "passive_cloud_attributed",
                    provider=provider,
                    source="asn",
                    asn=asn.asn,
                )
                return CloudAttribution(
                    provider=provider,
                    source=CloudSource.ASN,
                    confidence=CloudConfidence.LOW,
                    matched_value=str(asn.asn),
                )

        log.info("passive_cloud_attributed", provider=None, source="unknown")
        return CloudAttribution(
            provider=None,
            source=CloudSource.UNKNOWN,
            confidence=CloudConfidence.LOW,
        )

    async def _reverse_dns(self, ip: str) -> str | None:
        try:
            ptr = dns.reversename.from_address(ip)
            answer = await self._resolver.resolve(ptr, "PTR")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except dns.exception.DNSException:
            return None
        try:
            return str(answer[0]).rstrip(".")
        except (IndexError, AttributeError):
            return None

    async def scan(self, url: str) -> PassiveResult:
        from cdt.discovery.normalize import apex_of

        errors: list[str] = []
        try:
            apex = apex_of(url)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"normalize: {exc}")
            return PassiveResult(
                url=url,
                scanned_at=datetime.now(UTC),
                errors=errors,
            )

        dns_result: DNSResult | None = None
        whois_result: WhoisResult | None = None
        asn_result: ASNResult | None = None
        attribution = CloudAttribution()

        try:
            dns_result = await self.resolve_dns(apex)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"dns: {exc}")

        try:
            whois_result = await self.whois_lookup(apex)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"whois: {exc}")

        if dns_result and dns_result.a_records:
            try:
                asn_result = await self.asn_lookup(dns_result.a_records[0])
            except Exception as exc:  # noqa: BLE001
                errors.append(f"asn: {exc}")

        if dns_result is not None:
            try:
                attribution = await self.attribute_cloud(dns_result, asn_result)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"attribute: {exc}")

        log.info(
            "passive_scan_finished",
            apex=apex,
            errors=len(errors),
            cloud=attribution.provider,
        )
        return PassiveResult(
            url=url,
            dns=dns_result,
            whois=whois_result,
            asn=asn_result,
            cloud_attribution=attribution,
            scanned_at=datetime.now(UTC),
            errors=errors,
        )


def _match_rdns(name: str, patterns: dict[str, list[str]]) -> str | None:
    name_lc = name.lower().rstrip(".")
    for provider, globs in patterns.items():
        for g in globs:
            if fnmatch.fnmatchcase(name_lc, g.lower()):
                return provider
    return None


def _run_whois(apex: str) -> dict[str, Any]:
    """Synchronous helper for python-whois, called via ``asyncio.to_thread``."""
    import whois

    entry = whois.whois(apex)
    if entry is None:
        return {}
    if hasattr(entry, "__dict__"):
        return dict(entry)
    return entry  # type: ignore[no-any-return]


def _run_ipwhois(ip: str) -> dict[str, Any]:
    from ipwhois import IPWhois

    handle = IPWhois(ip)
    return dict(handle.lookup_rdap(depth=0))


def _first_str(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    if value is None:
        return None
    return str(value)


def _first_dt(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]
