"""Best-effort page fetcher: captures DOM, redirect chain and lightweight signals.

Primary path uses httpx (follow_redirects) to grab HTML + the redirect chain, then
parses the DOM with the stdlib html.parser (no heavy deps). An OPTIONAL Playwright
path is used only when playwright is importable AND a browser launches; it is wrapped
in try/except and always falls back to httpx.

Everything degrades gracefully: on total failure the fetcher returns a typed-empty
FetchResult (html='' and empty collections) and never raises.
"""
import hashlib
import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 8.0


@dataclass
class FetchResult:
    """Lightweight capture of a fetched page used by later analysis stages."""
    url: str
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    status: int = 0
    html: str = ""
    forms: list[dict] = field(default_factory=list)
    external_script_srcs: list[str] = field(default_factory=list)
    favicon_href: Optional[str] = None
    favicon_hash: Optional[str] = None
    ok: bool = False


class _PageParser(HTMLParser):
    """Extracts forms, external <script src>, and favicon link from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.script_srcs: list[str] = []
        self.favicon_href: Optional[str] = None
        self._cur_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur_form = {"action": a.get("action", ""),
                              "method": (a.get("method", "get") or "get").lower(),
                              "inputs": []}
        elif tag == "input" and self._cur_form is not None:
            self._cur_form["inputs"].append({"name": a.get("name", ""),
                                             "type": (a.get("type", "text") or "text").lower()})
        elif tag == "script" and a.get("src"):
            self.script_srcs.append(a["src"])
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "icon" in rel and a.get("href"):
                self.favicon_href = a["href"]

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


def parse_html(html: str, base_url: str = "") -> tuple[list[dict], list[str], Optional[str]]:
    """Parse HTML into (forms, external_script_srcs, favicon_href). External scripts
    are those whose src host differs from the page host (or are protocol-relative)."""
    parser = _PageParser()
    try:
        parser.feed(html or "")
    except Exception as exc:  # noqa: BLE001 - malformed HTML must not crash us
        logger.warning("fetcher: HTML parse error: %s", exc)

    base_host = _host(base_url)
    external = []
    for src in parser.script_srcs:
        if src.startswith("//") or src.startswith("http"):
            if not base_host or _host(urljoin(base_url, src)) != base_host:
                external.append(src)
    return parser.forms, external, parser.favicon_href


def _host(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _try_playwright(url: str, timeout: float) -> Optional[FetchResult]:
    """Optional Playwright render. Returns None if playwright/browser unavailable."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:  # noqa: BLE001 - not installed; this is expected/normal
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            resp = page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            html = page.content()
            final_url = page.url
            status = resp.status if resp else 0
            browser.close()
        forms, external, favicon = parse_html(html, final_url)
        return FetchResult(url=url, final_url=final_url, redirect_chain=[url, final_url] if final_url != url else [url],
                           status=status, html=html, forms=forms, external_script_srcs=external,
                           favicon_href=favicon, ok=True)
    except Exception as exc:  # noqa: BLE001 - fall back to httpx
        logger.warning("fetcher: playwright render failed, falling back: %s", exc)
        return None


def _httpx_fetch(url: str, timeout: float) -> FetchResult:
    import httpx

    with httpx.Client(follow_redirects=True, timeout=timeout,
                      headers={"User-Agent": "upi-shield-fetcher/1.0"}) as client:
        resp = client.get(url)
        chain = [str(h.url) for h in resp.history] + [str(resp.url)]
        html = resp.text if "text/html" in resp.headers.get("content-type", "") or not resp.headers.get("content-type") else resp.text
        forms, external, favicon = parse_html(html, str(resp.url))
        return FetchResult(url=url, final_url=str(resp.url), redirect_chain=chain,
                           status=resp.status_code, html=html, forms=forms,
                           external_script_srcs=external, favicon_href=favicon, ok=True)


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT, use_playwright: bool = False,
          fetch_fn: Optional[Callable[[str, float], FetchResult]] = None) -> FetchResult:
    """Fetch a URL best-effort. Never raises; returns typed-empty FetchResult on failure.

    `fetch_fn` is injectable for tests (bypasses all network). `use_playwright` opts into
    the optional render path which still falls back to httpx when unavailable.
    """
    if fetch_fn is not None:
        try:
            return fetch_fn(url, timeout)
        except Exception as exc:  # noqa: BLE001
            logger.warning("fetcher: injected fetch_fn failed for %s: %s", url, exc)
            return FetchResult(url=url)

    if use_playwright:
        pw = _try_playwright(url, timeout)
        if pw is not None:
            return pw

    try:
        return _httpx_fetch(url, timeout)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully
        logger.warning("fetcher: httpx fetch failed for %s: %s", url, exc)
        return FetchResult(url=url)


def favicon_hash_of(data: bytes) -> str:
    """Stable short hash of favicon bytes, usable as a favicon_hash linking entity."""
    return hashlib.md5(data).hexdigest()[:16]
