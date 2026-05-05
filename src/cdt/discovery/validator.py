"""HTTP-side validation of an account's provided Website (v0.4 §4.2).

The pipeline:
  1. Parse the URL — INVALID_URL if it is unparseable.
  2. Resolve A/AAAA records — DEAD_DOMAIN if neither resolves.
  3. HEAD; fall back to GET if the server rejects HEAD.
  4. If the body matches a known parking signature, PARKED_DOMAIN.
  5. If the landing page does not contain the account Title in
     ``<title>``, ``<meta og:site_name>`` or ``<h1>``, mark
     ``needs_semantic_check=True`` so the caller can delegate to
     ``BraveSearch.validate``.
"""

from __future__ import annotations

import re
from types import TracebackType
from typing import Self

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import structlog
from bs4 import BeautifulSoup

from cdt.discovery.models import IssueCode, ValidationResult
from cdt.discovery.normalize import parse_url
from cdt.errors import InputError
from cdt.models import AccountIn

log = structlog.get_logger()

_PARKING_SIGNATURES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"domain is for sale",
        r"sedoparking",
        r"sedo\.com",
        r"godaddy parked",
        r"parkingcrew",
        r"parked\.com",
        r"namecheap parking",
        r"bluehost parking",
        r"hugedomains",
        r"this domain has expired",
        r"register4less",
        r"buy this domain",
        r"this web page is parked",
    )
)


class Validator:
    def __init__(
        self,
        timeout_sec: float = 10.0,
        client: httpx.AsyncClient | None = None,
        resolver: dns.asyncresolver.Resolver | None = None,
    ) -> None:
        self._timeout = timeout_sec
        self._client = client or httpx.AsyncClient(
            timeout=timeout_sec,
            follow_redirects=True,
            headers={"User-Agent": "cdt-scanner/0.1 (validator)"},
        )
        self._owns_client = client is None
        self._resolver = resolver or dns.asyncresolver.Resolver()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def resolve_dns(self, apex: str) -> bool:
        """True if ``apex`` has at least one A or AAAA record."""

        for rrtype in ("A", "AAAA"):
            try:
                answer = await self._resolver.resolve(apex, rrtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException:
                continue
            if len(answer) > 0:
                return True
        return False

    async def head_request(self, url: str) -> tuple[int, str | None]:
        """HEAD ``url``; fall back to GET if HEAD is rejected.

        Returns ``(status, body_snippet)``. ``status == 0`` means the network
        layer never produced a response (timeout / DNS error / connection
        refused). ``body_snippet`` is the first 64 KB of body when we did a
        GET, otherwise ``None``.
        """

        try:
            head = await self._client.head(url)
        except (httpx.TimeoutException, httpx.NetworkError):
            return 0, None

        if head.status_code in {200, 301, 302, 303, 307, 308}:
            try:
                response = await self._client.get(url)
            except (httpx.TimeoutException, httpx.NetworkError):
                return head.status_code, None
            return response.status_code, response.text[:64_000]

        if head.status_code in {405, 501}:
            try:
                response = await self._client.get(url)
            except (httpx.TimeoutException, httpx.NetworkError):
                return 0, None
            return response.status_code, response.text[:64_000]

        return head.status_code, None

    @staticmethod
    def is_parking_page(html_snippet: str) -> bool:
        if not html_snippet:
            return False
        return any(p.search(html_snippet) for p in _PARKING_SIGNATURES)

    @staticmethod
    def title_in_landing(html: str, title_query: str) -> bool:
        if not html or not title_query:
            return False
        needle = title_query.strip().lower()
        if not needle:
            return False

        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        title_tag = soup.find("title")
        if title_tag and needle in title_tag.get_text(strip=True).lower():
            return True

        og = soup.find("meta", attrs={"property": "og:site_name"})
        if og:
            content = og.get("content", "")
            if isinstance(content, str) and needle in content.lower():
                return True

        for h1 in soup.find_all("h1"):
            if needle in h1.get_text(strip=True).lower():
                return True

        return False

    async def validate(self, account: AccountIn) -> ValidationResult:
        try:
            parts = parse_url(account.website)
        except InputError:
            log.warning(
                "discovery_validate_fail",
                title=account.title,
                website=account.website,
                issue=IssueCode.INVALID_URL.value,
            )
            return ValidationResult(confirmed=False, issue=IssueCode.INVALID_URL)

        apex = parts["apex"]
        host = f"{parts['subdomain']}.{apex}" if parts["subdomain"] else apex
        path = parts["path"] if parts["path"] not in ("", "/") else ""
        canonical = f"{parts['scheme']}://{host}{path}"

        alive = await self.resolve_dns(apex)
        if not alive:
            log.warning(
                "discovery_validate_fail",
                apex=apex,
                issue=IssueCode.DEAD_DOMAIN.value,
                reason="dns",
            )
            return ValidationResult(confirmed=False, issue=IssueCode.DEAD_DOMAIN)

        status, body = await self.head_request(canonical)
        if status == 0 or status >= 500:
            log.warning(
                "discovery_validate_fail",
                apex=apex,
                issue=IssueCode.DEAD_DOMAIN.value,
                reason="http",
                status=status,
            )
            return ValidationResult(confirmed=False, issue=IssueCode.DEAD_DOMAIN)

        if body and self.is_parking_page(body):
            log.warning(
                "discovery_validate_fail",
                apex=apex,
                issue=IssueCode.PARKED_DOMAIN.value,
            )
            return ValidationResult(
                confirmed=False,
                canonical_url=canonical,
                issue=IssueCode.PARKED_DOMAIN,
            )

        title_match = body is not None and self.title_in_landing(body, account.title)
        if not title_match:
            log.info(
                "discovery_validate_needs_semantic_check",
                apex=apex,
                title=account.title,
            )
            return ValidationResult(
                confirmed=False,
                canonical_url=canonical,
                issue=None,
                needs_semantic_check=True,
            )

        log.info("discovery_validate_ok", apex=apex)
        return ValidationResult(confirmed=True, canonical_url=canonical, issue=None)
