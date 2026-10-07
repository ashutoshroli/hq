"""CT-log discovery: find brand-lookalike hostnames from certificate transparency.

This stage queries a public CT source (crt.sh by default) for certificates whose
names mention a monitored brand keyword, then keeps only hosts that look like
clones (brand keyword present but the registered domain is NOT official).

All network use is OPTIONAL and best-effort. The HTTP client (`fetch_fn`) and the
base URL are injectable so tests can feed canned crt.sh-style JSON with no network.
On ANY failure (timeout, bad JSON, HTTP error) we log and return [] -- never raise.
"""
import json
import logging
from typing import Callable, Iterable, Optional

from app.services import url_features

logger = logging.getLogger(__name__)

CRTSH_BASE = "https://crt.sh/"
DEFAULT_TIMEOUT = 6.0

# A fetch_fn takes a URL + params and returns the raw response text (crt.sh JSON).
FetchFn = Callable[[str, dict], str]


def _httpx_fetch(url: str, params: dict) -> str:
    """Default fetch using httpx with a short timeout. Imported lazily so the
    module stays importable even if httpx is unavailable at import time."""
    import httpx

    resp = httpx.get(url, params=params, timeout=DEFAULT_TIMEOUT,
                     headers={"User-Agent": "upi-shield-crawler/1.0"})
    resp.raise_for_status()
    return resp.text


def _parse_ct_names(raw: str) -> list[str]:
    """Parse crt.sh JSON (a list of certificate records) into candidate hostnames.

    crt.sh returns records with `name_value` (newline-separated DNS names) and
    `common_name`. We flatten, strip wildcards, lowercase and de-duplicate.
    """
    try:
        records = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("crawler: could not parse CT JSON")
        return []
    if not isinstance(records, list):
        return []

    hosts: list[str] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        chunk = []
        nv = rec.get("name_value")
        if isinstance(nv, str):
            chunk.extend(nv.splitlines())
        cn = rec.get("common_name")
        if isinstance(cn, str):
            chunk.append(cn)
        for name in chunk:
            name = name.strip().lower().lstrip("*.")
            if name and "@" not in name:
                hosts.append(name)
    return list(dict.fromkeys(hosts))


def _is_lookalike(host: str) -> bool:
    """True if the host mentions a monitored brand but is NOT an official domain."""
    score, _signals, brand = url_features.score_url("http://" + host)
    return brand is not None


def discover_from_ct(
    domains_or_keywords: Iterable[str],
    fetch_fn: Optional[FetchFn] = None,
    base_url: str = CRTSH_BASE,
) -> list[str]:
    """Discover brand-lookalike hostnames from CT logs for each query term.

    `domains_or_keywords` are brand keywords or domain fragments (e.g. "phonepe").
    Returns a de-duplicated list of lookalike hostnames, filtering out official
    brand domains. Returns [] on any network/parse error (never raises).
    """
    fetch = fetch_fn or _httpx_fetch
    found: list[str] = []
    for term in domains_or_keywords:
        term = (term or "").strip()
        if not term:
            continue
        try:
            raw = fetch(base_url, {"q": f"%{term}%", "output": "json"})
        except Exception as exc:  # noqa: BLE001 - best effort, degrade gracefully
            logger.warning("crawler: CT fetch failed for %r: %s", term, exc)
            continue
        for host in _parse_ct_names(raw):
            if _is_lookalike(host):
                found.append(host)
    return list(dict.fromkeys(found))
