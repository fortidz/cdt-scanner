"""Pydantic v2 models for scan results (passive + browser tier)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CloudSource(StrEnum):
    IP_RANGE = "ip_range"
    RDNS = "rdns"
    ASN = "asn"
    CNAME = "cname"
    BANNER = "banner"
    UNKNOWN = "unknown"


class CloudConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DNSResult(BaseModel):
    apex: str
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class WhoisResult(BaseModel):
    apex: str
    registrar: str | None = None
    created: datetime | None = None
    updated: datetime | None = None
    expires: datetime | None = None
    name_servers: list[str] = Field(default_factory=list)
    raw_text: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class ASNResult(BaseModel):
    ip: str
    asn: int | None = None
    asn_org: str | None = None
    asn_country: str | None = None
    asn_description: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class IPRangeMatch(BaseModel):
    provider: str
    prefix: str
    region: str | None = None
    service: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class CloudAttribution(BaseModel):
    """Outcome of the cloud attribution decision tree (v0.4 §14.2)."""

    provider: str | None = None
    source: CloudSource = CloudSource.UNKNOWN
    confidence: CloudConfidence = CloudConfidence.LOW
    matched_value: str | None = None  # e.g. matching prefix, rDNS suffix, ASN

    model_config = ConfigDict(str_strip_whitespace=True)


class TLSInfo(BaseModel):
    version: str | None = None
    cipher: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class PassiveResult(BaseModel):
    url: str
    dns: DNSResult | None = None
    whois: WhoisResult | None = None
    asn: ASNResult | None = None
    cloud_attribution: CloudAttribution = Field(default_factory=CloudAttribution)
    scanned_at: datetime
    errors: list[str] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True)


class BrowserResult(BaseModel):
    url: str
    status: int
    final_url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_snippet: str = ""
    body_size: int = 0
    tls: TLSInfo | None = None
    robots_txt: str | None = None
    redirects: list[str] = Field(default_factory=list)
    scanned_at: datetime
    error: str | None = None

    model_config = ConfigDict(str_strip_whitespace=True)
