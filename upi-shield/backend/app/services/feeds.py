"""Public phishing-feed connectors (community reports).

Supported feeds (both are free, plain-text, one URL per line):

* ``openphish`` - OpenPhish community feed.
* ``urlhaus``   - abuse.ch URLhaus "recent URLs" text export.

The HTTP client is injectable (``fetch_fn``) so tests run offline. Every failure
degrades to an empty list; this module never raises to its callers.
"""
from __future__ import annotations

import logging
from collections.abc import Callable

from app.services import url_features

logger = logging.getLogger(__name__)

FEED_URLS: dict[str, str] = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/",
}
DEFAULT_TIMEOUT = 15.0

FetchText = Callable[[str], str]


def _httpx_fetch(url: str) -> str:
    import httpx

    resp = httpx.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True,
                     headers={"User-Agent": "upi-shield-feeds/1.0"})
    resp.raise_for_status()
    return resp.text


def parse_feed(text: str) -> list[str]:
    """Parse a one-URL-per-line feed, skipping comments and blank lines, de-duplicated."""
    urls: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")):
            urls.append(line)
    return list(dict.fromkeys(urls))


def is_brand_related(url: str) -> bool:
    """True when the URL impersonates (or mentions) a monitored payment brand."""
    _score, _signals, brand = url_features.score_url(url)
    return brand is not None


def fetch_feed(feed: str, brand_filter: bool = True, limit: int = 200,
               fetch_fn: FetchText | None = None) -> list[str]:
    """Download and parse a public feed. Returns at most ``limit`` URLs; [] on failure."""
    source = FEED_URLS.get(feed)
    if source is None:
        logger.warning("feeds: unknown feed %r", feed)
        return []
    try:
        text = (fetch_fn or _httpx_fetch)(source)
    except Exception as exc:  # noqa: BLE001 - external feed outages must not break callers
        logger.warning("feeds: failed to download %s: %s", feed, exc)
        return []
    urls = parse_feed(text)
    if brand_filter:
        urls = [u for u in urls if is_brand_related(u)]
    return urls[:limit]
