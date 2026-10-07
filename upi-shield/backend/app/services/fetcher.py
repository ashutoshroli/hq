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
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
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
    favicon_href: str | None = None
    favicon_hash: str | None = None
    ok: bool = False
    # Rendered-capture artefacts (Playwright path). Bytes are kept in memory for the
    # visual engine; the screenshot is also written to the evidence store.
    screenshot: bytes | None = field(default=None, repr=False)
    favicon_bytes: bytes | None = field(default=None, repr=False)
    screenshot_url: str | None = None
    title: str = ""
    user_agent: str = ""


class _PageParser(HTMLParser):
    """Extracts forms, external <script src>, and favicon link from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.script_srcs: list[str] = []
        self.favicon_href: str | None = None
        self._cur_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
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


def parse_html(html: str, base_url: str = "") -> tuple[list[dict], list[str], str | None]:
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
        is_absolute = src.startswith(("//", "http"))
        if is_absolute and (not base_host or _host(urljoin(base_url, src)) != base_host):
            external.append(src)
    return parser.forms, external, parser.favicon_href


def _host(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36")


CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def probe(url: str, user_agent: str, timeout: float = DEFAULT_TIMEOUT) -> FetchResult:
    """Plain HTTP fetch with a specific User-Agent (used to detect cloaking). Never raises."""
    try:
        return _httpx_fetch(url, timeout, user_agent=user_agent)
    except Exception as exc:  # noqa: BLE001 - a failed probe is itself evidence
        logger.debug("fetcher: probe (%s) failed for %s: %s", user_agent[:20], url, exc)
        return FetchResult(url=url, user_agent=user_agent)


def download_apk(url: str, max_bytes: int = 150 * 1024 * 1024, timeout: float = 60.0) -> bytes:
    """Download an APK with an Android user agent (kits often serve APKs to phones only).

    Raises ``ValueError`` when the response is not an APK-sized ZIP payload.
    """
    import httpx

    with httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                      headers={"User-Agent": MOBILE_UA}) as client, client.stream("GET", url) as resp:
        resp.raise_for_status()
        chunks, total = [], 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("APK exceeds the size limit")
            chunks.append(chunk)
    data = b"".join(chunks)
    if not data.startswith(b"PK"):
        raise ValueError("download is not an APK/ZIP file")
    return data


def save_evidence(data: bytes, suffix: str = "png") -> str | None:
    """Persist an evidence artefact by content hash and return its API path."""
    from app.config import get_settings

    try:
        digest = hashlib.sha256(data).hexdigest()[:24]
        directory = get_settings().evidence_dir
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{digest}.{suffix}")
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(data)
        return f"/evidence/{digest}.{suffix}"
    except OSError as exc:
        logger.warning("fetcher: could not store evidence: %s", exc)
        return None


def _try_playwright(url: str, timeout: float, mobile: bool = False) -> FetchResult | None:
    """Render the page in headless Chromium and capture a screenshot.

    Returns None when Playwright or the browser is unavailable so the caller can
    fall back to the plain HTTP fetch.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - not installed; this is expected/normal
        return None
    ua = MOBILE_UA if mobile else DESKTOP_UA
    viewport = {"width": 390, "height": 844} if mobile else {"width": 1280, "height": 800}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                ctx = browser.new_context(user_agent=ua, viewport=viewport, is_mobile=mobile,
                                          has_touch=mobile, locale="en-IN", ignore_https_errors=True)
                page = ctx.new_page()
                chain: list[str] = []
                page.on("framenavigated", lambda f: f == page.main_frame and chain.append(f.url))
                resp = page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                page.wait_for_timeout(1500)  # let client-side rendering settle
                html = page.content()
                final_url = page.url
                title = page.title()
                shot = page.screenshot()
                status = resp.status if resp else 0
                forms, external, favicon = parse_html(html, final_url)
                icon_bytes = None
                for href in [favicon, "/favicon.ico"]:
                    if not href:
                        continue
                    try:
                        r = page.request.get(urljoin(final_url, href), timeout=timeout * 1000)
                        if r.ok and r.body():
                            icon_bytes = r.body()
                            break
                    except Exception as exc:  # noqa: BLE001 - favicon optional
                        logger.debug("fetcher: favicon fetch failed: %s", exc)
            finally:
                browser.close()
        chain = list(dict.fromkeys([url, *[c for c in chain if c and c != "about:blank"], final_url]))
        return FetchResult(url=url, final_url=final_url, redirect_chain=chain, status=status, html=html,
                           forms=forms, external_script_srcs=external, favicon_href=favicon,
                           favicon_hash=favicon_hash_of(icon_bytes) if icon_bytes else None,
                           ok=True, screenshot=shot, favicon_bytes=icon_bytes,
                           screenshot_url=save_evidence(shot), title=title, user_agent=ua)
    except Exception as exc:  # noqa: BLE001 - fall back to httpx
        message = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        if "ERR_NAME_NOT_RESOLVED" in message:
            logger.info("fetcher: %s does not resolve", url)
            return FetchResult(url=url, status=0)  # dead DNS: an HTTP retry cannot succeed
        logger.info("fetcher: render failed for %s (%s); falling back to HTTP", url, message)
        return None


def _fetch_favicon(client, base_url: str, favicon_href: str | None) -> bytes | None:
    """Best-effort favicon download. Falls back to the conventional /favicon.ico when no
    <link rel=icon> was declared. Never raises; returns None on any failure."""
    href = favicon_href or "/favicon.ico"
    try:
        resp = client.get(urljoin(base_url, href))
        if resp.status_code == 200 and resp.content:
            return resp.content
    except Exception as exc:  # noqa: BLE001 - favicon is optional, must not break fetch
        logger.debug("fetcher: favicon fetch failed for %s: %s", href, exc)
    return None


def _fetch_favicon_hash(client, base_url: str, favicon_href: str | None) -> str | None:
    """Stable favicon hash, so the favicon-reuse signal and favicon_hash linking entity fire."""
    data = _fetch_favicon(client, base_url, favicon_href)
    return favicon_hash_of(data) if data else None


def _httpx_fetch(url: str, timeout: float, user_agent: str = DESKTOP_UA) -> FetchResult:
    import httpx

    # A browser-like User-Agent: phishing kits commonly serve a decoy page to bot UAs.
    # Certificate verification is disabled on purpose: phishing hosts frequently use
    # self-signed or mismatched certificates, and we only read the page, never submit.
    with httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                      headers={"User-Agent": user_agent, "Accept-Language": "en-IN,en;q=0.9"}) as client:
        resp = client.get(url)
        chain = [str(h.url) for h in resp.history] + [str(resp.url)]
        html = resp.text
        forms, external, favicon = parse_html(html, str(resp.url))
        icon = _fetch_favicon(client, str(resp.url), favicon)
        return FetchResult(url=url, final_url=str(resp.url), redirect_chain=chain,
                           status=resp.status_code, html=html, forms=forms,
                           external_script_srcs=external, favicon_href=favicon,
                           favicon_hash=favicon_hash_of(icon) if icon else None, ok=True,
                           favicon_bytes=icon, user_agent=user_agent)


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT, use_playwright: bool | None = None,
          fetch_fn: Callable[[str, float], FetchResult] | None = None) -> FetchResult:
    """Fetch a URL best-effort. Never raises; returns typed-empty FetchResult on failure.

    ``fetch_fn`` is injectable for tests (bypasses all network). ``use_playwright``
    defaults to the ``RENDER_PAGES`` setting; the render path captures a screenshot
    and falls back to the plain HTTP fetch when no browser is available.
    """
    if use_playwright is None:
        from app.config import get_settings

        use_playwright = get_settings().render_pages
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
        logger.info("fetcher: HTTP fetch failed for %s: %s", url, exc)
        return FetchResult(url=url)


def favicon_hash_of(data: bytes) -> str:
    """Stable short hash of favicon bytes, usable as a favicon_hash linking entity."""
    return hashlib.md5(data).hexdigest()[:16]
