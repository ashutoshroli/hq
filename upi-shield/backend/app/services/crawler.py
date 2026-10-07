"""CT-log discovery: find brand-lookalike hostnames from certificate transparency.

This stage queries crt.sh for currently valid certificates whose names mention a
monitored brand keyword, then keeps only hosts that look like clones (brand keyword
present but the registered domain is not official).

Two backends are supported: crt.sh's public PostgreSQL replica (preferred, requires
the optional ``psycopg`` package) and its JSON web API (fallback). All network use
is best-effort. The HTTP client (``fetch_fn``) is injectable so tests can feed canned
crt.sh-style JSON with no network. On any failure we log and return [].
"""
import json
import logging
import re
from collections.abc import Callable, Iterable

from app.services import url_features

logger = logging.getLogger(__name__)

CRTSH_BASE = "https://crt.sh/"
DEFAULT_TIMEOUT = 6.0
_HOSTNAME_RE = re.compile(r"(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+")

# A fetch_fn takes a URL + params and returns the raw response text (crt.sh JSON).
FetchFn = Callable[[str, dict], str]


def _httpx_fetch(url: str, params: dict, attempts: int = 3) -> str:
    """Default fetch using httpx. crt.sh is frequently overloaded and answers with
    5xx or times out, so retry with exponential backoff before giving up."""
    import time

    import httpx

    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            resp = httpx.get(url, params=params, timeout=DEFAULT_TIMEOUT * (attempt + 1),
                             headers={"User-Agent": "upi-shield-crawler/1.0"})
            resp.raise_for_status()
            return resp.text
        except Exception as exc:  # noqa: BLE001 - retried below
            last_exc = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"CT source unavailable after {attempts} attempts: {last_exc}")


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
        hosts.extend(chunk)
    return normalize_hostnames(hosts)


def normalize_hostnames(names: Iterable[str]) -> list[str]:
    """Lower-case, strip wildcards and keep only syntactically valid DNS hostnames.

    CT identities also contain organisation names ("PhonePe Private Limited") and
    e-mail addresses; those are discarded.
    """
    hosts: list[str] = []
    for name in names:
        name = (name or "").strip().lower().removeprefix("*.").rstrip(".")
        if name and _HOSTNAME_RE.fullmatch(name):
            hosts.append(name)
    return list(dict.fromkeys(hosts))


def _is_lookalike(host: str) -> bool:
    """True if the host mentions a monitored brand but is NOT an official domain."""
    _score, _signals, brand = url_features.score_url("http://" + host)
    return brand is not None


# --- crt.sh PostgreSQL backend --------------------------------------------------------
# crt.sh exposes a read-only public PostgreSQL replica. It is markedly more reliable
# than the JSON web endpoint, which frequently answers 502 under load. The query uses
# the full-text identity index, keeps currently valid certificates only, and is bounded.
_PG_QUERY = """
WITH ci AS (
    SELECT array_agg(DISTINCT sub.name_value) AS names
    FROM (
        SELECT cai.*
        FROM certificate_and_identities cai
        WHERE plainto_tsquery('certwatch', %(keyword)s) @@ identities(cai.certificate)
          AND cai.name_value ILIKE %(pattern)s
          AND coalesce(x509_notAfter(cai.certificate), 'infinity'::timestamp) >= now() AT TIME ZONE 'UTC'
        LIMIT %(scan_limit)s
    ) sub
    GROUP BY sub.certificate
)
SELECT names FROM ci LIMIT %(row_limit)s
"""


def _pg_query(term: str, timeout_s: int = 90, scan_limit: int = 5000, row_limit: int = 1000) -> list[str]:
    import psycopg  # optional dependency; ImportError is handled by the caller

    with psycopg.connect(host="crt.sh", port=5432, user="guest", dbname="certwatch",
                         autocommit=True, connect_timeout=15) as conn, conn.cursor() as cur:
        cur.execute(f"SET statement_timeout = '{int(timeout_s)}s'")
        cur.execute(_PG_QUERY, {"keyword": term, "pattern": f"%{term}%",
                                "scan_limit": scan_limit, "row_limit": row_limit})
        return [name for (names,) in cur.fetchall() for name in (names or [])]


def _query_term(term: str, fetch_fn: FetchFn | None, base_url: str, backend: str) -> list[str]:
    """Return raw CT names for one term using the selected backend (never raises)."""
    if fetch_fn is not None or backend == "http":
        try:
            raw = (fetch_fn or _httpx_fetch)(base_url, {"q": f"%{term}%", "output": "json", "exclude": "expired"})
            return _parse_ct_names(raw)
        except Exception as exc:  # noqa: BLE001 - best effort, degrade gracefully
            logger.warning("crawler: CT fetch failed for %r: %s", term, exc)
            return []
    try:
        return normalize_hostnames(_pg_query(term))
    except Exception as exc:  # noqa: BLE001 - fall back to the HTTP API
        logger.warning("crawler: crt.sh PostgreSQL query failed for %r (%s); falling back to HTTP", term, exc)
        return _query_term(term, None, base_url, "http")


def discover_from_ct(
    domains_or_keywords: Iterable[str],
    fetch_fn: FetchFn | None = None,
    base_url: str = CRTSH_BASE,
    backend: str = "auto",
) -> list[str]:
    """Discover brand-lookalike hostnames from CT logs for each query term.

    ``domains_or_keywords`` are brand keywords (e.g. "phonepe"). ``backend`` selects
    the source: ``"auto"`` (PostgreSQL replica, falling back to HTTP), ``"postgres"``
    or ``"http"``. An injected ``fetch_fn`` always uses the HTTP JSON format, which
    keeps tests offline. Returns de-duplicated lookalike hostnames with official
    brand domains filtered out; returns [] on any network or parse error.
    """
    found: list[str] = []
    for term in domains_or_keywords:
        term = (term or "").strip()
        if not term:
            continue
        for host in _query_term(term, fetch_fn, base_url, backend):
            if _is_lookalike(host):
                found.append(host)
    return list(dict.fromkeys(found))
