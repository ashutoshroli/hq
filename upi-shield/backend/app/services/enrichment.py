"""Infrastructure enrichment: resolve a host to hosting/network entities.

Best-effort, offline-safe and fully stubbable. Each external lookup (DNS, ASN,
TLS cert, WHOIS registrar) is an injectable resolver with a safe default that
returns ``None`` on any failure. ``enrich`` NEVER raises; it returns only the
entities it could resolve and ``[]`` when every resolver fails. Analytics IDs are
scraped from ``fetch_result.html`` with no network at all.

The default resolvers DO touch the network (socket/ssl stdlib), so callers that
must stay offline (tests, CI, the default pipeline path) inject stub resolvers or
rely on the pipeline's fetch/enrich flag which keeps this disabled by default.
"""
import logging
import re
import socket
import ssl
from typing import Callable, Optional

from app.schemas import Entity

logger = logging.getLogger(__name__)

# Tracking / analytics IDs commonly embedded in cloned pages. Shared IDs are a
# strong campaign-linking signal (clones reuse the attacker's analytics account).
_ANALYTICS_RE = re.compile(r"\b((?:UA-\d{4,}-\d+)|(?:G-[A-Z0-9]{6,})|(?:GTM-[A-Z0-9]{4,}))\b")

# Type aliases for the injectable resolvers.
IPResolver = Callable[[str], Optional[str]]
ASNResolver = Callable[[str], Optional[str]]
CertResolver = Callable[[str], Optional[str]]
RegistrarResolver = Callable[[str], Optional[str]]


def _default_ip_resolver(host: str) -> Optional[str]:
    """Resolve a hostname to an IPv4 address via stdlib socket. Network, best-effort."""
    try:
        return socket.gethostbyname(host)
    except Exception as exc:  # noqa: BLE001 - DNS failures must not propagate
        logger.debug("enrichment: IP resolve failed for %s: %s", host, exc)
        return None


def _default_asn_resolver(ip: str) -> Optional[str]:
    """Resolve an IP to an ASN. No lightweight stdlib way, so default to None.

    Kept injectable so deployments can wire in a Team Cymru / RDAP lookup without
    changing callers. Returning None keeps the function offline-safe by default.
    """
    return None


def _default_cert_resolver(host: str) -> Optional[str]:
    """Fetch the TLS leaf cert for ``host`` and return a sha256 fingerprint.

    Uses stdlib ssl; network, best-effort. Returns None on any failure.
    """
    try:
        import hashlib

        der = ssl.get_server_certificate((host, 443))
        # get_server_certificate returns PEM; convert to DER for a stable fingerprint.
        der_bytes = ssl.PEM_cert_to_DER_cert(der)
        return hashlib.sha256(der_bytes).hexdigest()[:32]
    except Exception as exc:  # noqa: BLE001
        logger.debug("enrichment: cert fetch failed for %s: %s", host, exc)
        return None


def _default_registrar_resolver(host: str) -> Optional[str]:
    """Optional WHOIS registrar lookup. python-whois is not a hard dependency, so
    this imports lazily and returns None when the library is absent or lookup fails."""
    try:
        import whois  # type: ignore

        data = whois.whois(host)
        registrar = getattr(data, "registrar", None) or (data.get("registrar") if isinstance(data, dict) else None)
        if isinstance(registrar, (list, tuple)):
            registrar = registrar[0] if registrar else None
        return str(registrar) if registrar else None
    except Exception as exc:  # noqa: BLE001 - library missing or lookup failed
        logger.debug("enrichment: WHOIS failed for %s: %s", host, exc)
        return None


def scrape_analytics_ids(html: str) -> list[str]:
    """Extract unique analytics/tracking IDs (UA-/G-/GTM-) from page HTML, in order."""
    if not html:
        return []
    seen: list[str] = []
    for match in _ANALYTICS_RE.findall(html):
        if match not in seen:
            seen.append(match)
    return seen


def enrich(host: str, fetch_result=None, resolvers: Optional[dict] = None) -> list[Entity]:
    """Resolve ``host`` to infrastructure entities. Never raises.

    Args:
        host: the hostname to enrich (e.g. "paytm-claim.click").
        fetch_result: optional FetchResult; its ``.html`` is scraped for analytics IDs.
        resolvers: optional dict overriding any of the default resolvers:
            {"ip", "asn", "cert", "registrar"} -> callable. Injecting stubs keeps
            tests fully offline. Pass ``None`` for a resolver to use the default.

    Returns:
        A list of Entity rows (types: ip, asn, cert_fingerprint, registrar,
        analytics_id) for everything that resolved; ``[]`` when all fail.
    """
    resolvers = resolvers or {}
    ip_resolver: IPResolver = resolvers.get("ip") or _default_ip_resolver
    asn_resolver: ASNResolver = resolvers.get("asn") or _default_asn_resolver
    cert_resolver: CertResolver = resolvers.get("cert") or _default_cert_resolver
    registrar_resolver: RegistrarResolver = resolvers.get("registrar") or _default_registrar_resolver

    entities: list[Entity] = []
    if not host:
        # Still scrape analytics even without a host, but there is nothing to resolve.
        host = ""

    ip: Optional[str] = None
    if host:
        try:
            ip = ip_resolver(host)
        except Exception as exc:  # noqa: BLE001 - resolver must never break enrich
            logger.debug("enrichment: ip_resolver raised for %s: %s", host, exc)
            ip = None
        if ip:
            entities.append(Entity(type="ip", value=ip))

    if ip:
        try:
            asn = asn_resolver(ip)
        except Exception as exc:  # noqa: BLE001
            logger.debug("enrichment: asn_resolver raised for %s: %s", ip, exc)
            asn = None
        if asn:
            entities.append(Entity(type="asn", value=str(asn)))

    if host:
        try:
            cert = cert_resolver(host)
        except Exception as exc:  # noqa: BLE001
            logger.debug("enrichment: cert_resolver raised for %s: %s", host, exc)
            cert = None
        if cert:
            entities.append(Entity(type="cert_fingerprint", value=str(cert)))

        try:
            registrar = registrar_resolver(host)
        except Exception as exc:  # noqa: BLE001
            logger.debug("enrichment: registrar_resolver raised for %s: %s", host, exc)
            registrar = None
        if registrar:
            entities.append(Entity(type="registrar", value=str(registrar)))

    html = getattr(fetch_result, "html", "") if fetch_result is not None else ""
    for tid in scrape_analytics_ids(html):
        entities.append(Entity(type="analytics_id", value=tid))

    return entities
