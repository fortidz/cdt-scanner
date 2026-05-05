"""URL normalisation helpers used by Validator / BraveSearch / Expander.

The implementation deliberately avoids the public-suffix-list dependency
(``tldextract``) to keep the dep tree small. We hard-code the LATAM
multi-part TLDs we care about and fall back to "last two labels" elsewhere.
"""

from __future__ import annotations

import re
from typing import TypedDict
from urllib.parse import urlsplit

from cdt.errors import InputError


class ParsedURL(TypedDict):
    scheme: str
    apex: str
    subdomain: str
    path: str


_LABEL = r"[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_MULTI_PART_TLDS: frozenset[str] = frozenset(
    {
        # LATAM scope
        "com.pe", "gob.pe", "edu.pe", "org.pe", "net.pe", "nom.pe",
        "com.ec", "gob.ec", "edu.ec", "org.ec", "net.ec",
        "com.cl", "gob.cl", "edu.cl", "org.cl", "net.cl",
        "com.bo", "gob.bo", "edu.bo", "org.bo", "net.bo",
        "com.py", "gov.py", "edu.py", "org.py", "net.py",
        "com.uy", "gub.uy", "edu.uy", "org.uy", "net.uy",
        "com.ve", "gob.ve", "edu.ve", "org.ve", "net.ve",
        # other multi-part TLDs occasionally seen in the dataset
        "co.uk", "co.in", "com.br", "com.ar", "com.mx", "com.co",
    }
)


def parse_url(s: str) -> ParsedURL:
    """Parse ``s`` into ``{scheme, apex, subdomain, path}``.

    Accepts ``acme.com``, ``https://acme.com``, ``https://www.acme.com/ruta``.
    Raises ``InputError`` (E03) when ``s`` does not look like a domain URL.
    """

    if not s or not s.strip():
        raise InputError("Empty URL")

    raw = s.strip()
    if "://" not in raw:
        raw = f"https://{raw}"

    parts = urlsplit(raw)
    hostname = (parts.hostname or "").lower()
    if not hostname:
        raise InputError(f"Invalid URL: {s!r}")
    if _IPV4_RE.match(hostname):
        raise InputError(f"IP addresses are not supported: {hostname}")
    if "." not in hostname or not _HOSTNAME_RE.match(hostname):
        raise InputError(f"Invalid hostname: {hostname!r}")

    apex, subdomain = _split_apex(hostname)

    return ParsedURL(
        scheme=parts.scheme or "https",
        apex=apex,
        subdomain=subdomain,
        path=parts.path or "/",
    )


def _split_apex(hostname: str) -> tuple[str, str]:
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname, ""

    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_PART_TLDS:
        if len(labels) >= 3:
            apex = ".".join(labels[-3:])
            subdomain = ".".join(labels[:-3])
            return apex, subdomain
        return hostname, ""

    apex = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2])
    return apex, subdomain


def apex_of(url: str) -> str:
    """Return only the apex (registrable domain) for ``url``."""

    return parse_url(url)["apex"]


def is_apex_match(url: str, apex: str) -> bool:
    """True iff ``url`` resolves to ``apex`` regardless of subdomain or scheme."""

    try:
        return parse_url(url)["apex"] == apex.lower()
    except InputError:
        return False
