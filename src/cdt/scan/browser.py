"""Browser-tier scanner — single GET with TLS + headers + redirects + robots."""

from __future__ import annotations

import os
import ssl
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self

import httpx
import structlog
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from cdt.scan.models import BrowserResult, TLSInfo

log = structlog.get_logger()

_DEFAULT_UA = "CDT-Scanner/0.1 (+https://github.com/fortidz/cdt-scanner)"
_BODY_SNIPPET_BYTES = 8 * 1024


class BrowserScanner:
    def __init__(
        self,
        timeout_sec: float = 15.0,
        user_agent: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._timeout = timeout_sec
        self._ua = user_agent or os.environ.get("CDT_USER_AGENT") or _DEFAULT_UA
        # http2 needs the h2 package and adds little for the browser tier
        # (most CDN edges still serve us http/1.1). Off by default to keep
        # the dep tree small; orchestrator can opt in by injecting a custom
        # client via ``client=``.
        self._client = client or httpx.AsyncClient(
            timeout=timeout_sec,
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": self._ua, "Accept": "*/*"},
        )
        self._owns_client = client is None

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

    async def fetch(self, url: str) -> BrowserResult:
        log.info("browser_fetch_started", url=url)
        scanned_at = datetime.now(UTC)
        try:
            response = await self._do_fetch(url)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            log.warning(
                "browser_fetch_failed", url=url, error=f"{type(exc).__name__}: {exc}"
            )
            return BrowserResult(
                url=url,
                status=0,
                final_url=url,
                scanned_at=scanned_at,
                error=f"{type(exc).__name__}: {exc}",
            )
        except httpx.HTTPError as exc:
            log.warning(
                "browser_fetch_failed", url=url, error=f"{type(exc).__name__}: {exc}"
            )
            return BrowserResult(
                url=url,
                status=0,
                final_url=url,
                scanned_at=scanned_at,
                error=f"{type(exc).__name__}: {exc}",
            )

        body_bytes = response.content
        snippet_bytes = body_bytes[:_BODY_SNIPPET_BYTES]
        try:
            snippet = snippet_bytes.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, UnicodeDecodeError):
            snippet = snippet_bytes.decode("utf-8", errors="replace")

        body_size = (
            int(response.headers.get("content-length"))
            if response.headers.get("content-length", "").isdigit()
            else len(body_bytes)
        )

        redirects = [str(r.url) for r in response.history]
        headers = {k.lower(): v for k, v in response.headers.items()}
        tls = _extract_tls(response)

        log.info(
            "browser_fetch_ok",
            url=url,
            status=response.status_code,
            final_url=str(response.url),
            redirects=len(redirects),
        )
        return BrowserResult(
            url=url,
            status=response.status_code,
            final_url=str(response.url),
            headers=headers,
            body_snippet=snippet,
            body_size=body_size,
            tls=tls,
            redirects=redirects,
            scanned_at=scanned_at,
        )

    async def fetch_robots(self, apex: str) -> str | None:
        url = f"https://{apex}/robots.txt"
        try:
            response = await self._client.get(url)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError):
            return None
        if response.status_code == 404:
            log.info("browser_robots_fetched", apex=apex, status=404)
            return None
        if response.status_code >= 400:
            return None
        log.info("browser_robots_fetched", apex=apex, status=response.status_code)
        return response.text

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    async def _do_fetch(self, url: str) -> httpx.Response:
        return await self._client.get(url)

    @staticmethod
    def parse_tls(ssl_obj: Any) -> TLSInfo:
        return _parse_ssl_object(ssl_obj)


def _extract_tls(response: httpx.Response) -> TLSInfo | None:
    """Pull TLS metadata out of an httpx response if the connection used HTTPS."""

    network_stream = response.extensions.get("network_stream")
    if network_stream is None:
        return None
    try:
        ssl_obj = network_stream.get_extra_info("ssl_object")
    except Exception:  # noqa: BLE001
        return None
    if ssl_obj is None:
        return None
    return _parse_ssl_object(ssl_obj)


def _parse_ssl_object(ssl_obj: Any) -> TLSInfo:
    info = TLSInfo()
    try:
        info.version = ssl_obj.version()
    except (AttributeError, ssl.SSLError):
        info.version = None
    try:
        cipher = ssl_obj.cipher()
        if isinstance(cipher, tuple) and cipher:
            info.cipher = str(cipher[0])
    except (AttributeError, ssl.SSLError):
        info.cipher = None

    der: bytes | None = None
    try:
        der = ssl_obj.getpeercert(binary_form=True)
    except (AttributeError, ssl.SSLError):
        der = None

    if not der:
        return info

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return info

    try:
        info.cert_subject = cert.subject.rfc4514_string()
    except Exception:  # noqa: BLE001
        info.cert_subject = None
    try:
        info.cert_issuer = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        info.cert_issuer = None
    try:
        info.not_before = cert.not_valid_before_utc
    except AttributeError:
        info.not_before = cert.not_valid_before.replace(tzinfo=UTC)
    try:
        info.not_after = cert.not_valid_after_utc
    except AttributeError:
        info.not_after = cert.not_valid_after.replace(tzinfo=UTC)

    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        info.sans = [name.value for name in san_ext if hasattr(name, "value")]
    except x509.ExtensionNotFound:
        info.sans = []
    except Exception:  # noqa: BLE001
        info.sans = []

    # ``Encoding`` is referenced so the import is not flagged unused — it is
    # the canonical way to re-encode the cert for downstream callers.
    _ = Encoding

    return info
