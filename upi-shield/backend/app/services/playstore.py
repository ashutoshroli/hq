"""Google Play listing metadata (title, developer, icon) from the public details page.

Used to build genuine-app references (icon fingerprints and official developer names)
and to vet a package name reported by an analyst. Never raises; returns None when the
listing does not exist or cannot be fetched.
"""
from __future__ import annotations

import html
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DETAILS_URL = "https://play.google.com/store/apps/details"
_OG = re.compile(r'<meta property="og:(title|image)" content="([^"]+)"')
_DEV = re.compile(r'href="/store/apps/dev(?:eloper)?\?id=[^"]+"[^>]*><span>([^<]+)</span>')
_TITLE_SUFFIX = " – Apps on Google Play"

FetchFn = Callable[[str, dict], tuple[int, str]]


@dataclass
class Listing:
    package: str
    title: str
    developer: str | None
    icon_url: str | None


def _httpx_get(url: str, params: dict) -> tuple[int, str]:
    import httpx

    resp = httpx.get(url, params=params, timeout=20.0, follow_redirects=True,
                     headers={"Accept-Language": "en-IN,en;q=0.9", "User-Agent": "Mozilla/5.0"})
    return resp.status_code, resp.text


def parse_listing(package: str, page: str) -> Listing | None:
    og = dict(_OG.findall(page or ""))
    if "title" not in og:
        return None
    title = html.unescape(og["title"]).removesuffix(_TITLE_SUFFIX).strip()
    dev = _DEV.search(page)
    icon = og.get("image")
    return Listing(package=package, title=title, developer=html.unescape(dev.group(1)).strip() if dev else None,
                   icon_url=html.unescape(icon) if icon else None)


def fetch_listing(package: str, fetch_fn: FetchFn | None = None) -> Listing | None:
    try:
        status, page = (fetch_fn or _httpx_get)(DETAILS_URL, {"id": package, "hl": "en_IN", "gl": "IN"})
    except Exception as exc:  # noqa: BLE001 - Play availability must not break analysis
        logger.warning("playstore: listing fetch failed for %s: %s", package, exc)
        return None
    if status != 200:
        return None
    return parse_listing(package, page)
