"""Build the visual reference library from the genuine brand websites.

For every brand in ``app.brands`` this renders each reference URL in headless
Chromium (desktop and mobile viewports), fingerprints the screenshot, downloads the
favicon, and writes ``app/data/brand_refs.json``. The JSON is committed so the
detector works offline; rerun this tool whenever a brand redesigns its site.

Usage (from backend/):
    pip install playwright Pillow numpy && playwright install chromium
    python -m app.tools.build_brand_refs [--brand phonepe ...]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin

from app import brands
from app.services import imaging

logger = logging.getLogger("build_brand_refs")
OUT = Path(__file__).resolve().parent.parent / "data" / "brand_refs.json"

VIEWPORTS = {
    "desktop": {"viewport": {"width": 1280, "height": 800}},
    "mobile": {"viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True,
               "user_agent": ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36")},
}


# Titles served by bot-protection / CDN error pages. Fingerprinting these would make
# every blocked fetch "match" a brand, so such captures are discarded.
BLOCK_TITLE_MARKERS = ("sorry", "error", "access denied", "attention required", "just a moment",
                       "request could not be satisfied", "forbidden", "not found")


def is_block_page(title: str) -> bool:
    low = (title or "").strip().lower()
    return not low or any(marker in low for marker in BLOCK_TITLE_MARKERS)


def _favicons(page, base_url: str) -> list[bytes]:
    """Every icon variant the site serves (declared <link rel=icon> and /favicon.ico).
    Brands often serve different artwork at each, and clones may copy either one."""
    hrefs = page.eval_on_selector_all("link[rel*='icon']", "els => els.map(e => e.getAttribute('href'))")
    icons: list[bytes] = []
    for href in dict.fromkeys([h for h in hrefs if h] + ["/favicon.ico"]):
        try:
            resp = page.request.get(urljoin(base_url, href), timeout=15000)
            body = resp.body() if resp.ok else b""
            if body and imaging.phash(body):
                icons.append(body)
        except Exception as exc:  # noqa: BLE001 - try the next candidate
            logger.debug("favicon %s failed: %s", href, exc)
    return icons


def build(selected: list[str] | None = None) -> dict:
    from playwright.sync_api import sync_playwright

    existing = json.loads(OUT.read_text()) if OUT.exists() else {"brands": {}}
    result = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "brands": existing.get("brands", {})}
    for key in selected or []:
        result["brands"].pop(key, None)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for brand in brands.BRANDS.values():
            if selected and brand.key not in selected:
                continue
            entry = {"screenshots": [], "favicon_md5": [], "favicon_phash": [], "titles": []}
            for url in brand.reference_urls:
                for name, opts in VIEWPORTS.items():
                    ctx = browser.new_context(**opts, locale="en-IN")
                    page = ctx.new_page()
                    try:
                        page.goto(url, timeout=45000, wait_until="domcontentloaded")
                        page.wait_for_timeout(2500)
                        title = page.title().strip()
                        if is_block_page(title):
                            logger.warning("%s %s (%s): skipped block page %r", brand.key, url, name, title)
                            continue
                        fp = imaging.Fingerprint.of(page.screenshot())
                        if fp:
                            entry["screenshots"].append({"url": url, "viewport": name, **fp.to_dict()})
                        if title and title not in entry["titles"]:
                            entry["titles"].append(title)
                        if name == "desktop":
                            for icon in _favicons(page, page.url):
                                md5 = hashlib.md5(icon).hexdigest()[:16]
                                if md5 not in entry["favicon_md5"]:
                                    entry["favicon_md5"].append(md5)
                                ph = imaging.phash(icon)
                                if ph not in entry["favicon_phash"]:
                                    entry["favicon_phash"].append(ph)
                        logger.info("%s %s (%s): ok", brand.key, url, name)
                    except Exception as exc:  # noqa: BLE001 - keep building other brands
                        logger.warning("%s %s (%s): %s", brand.key, url, name, exc)
                    finally:
                        ctx.close()
            if entry["screenshots"] or entry["favicon_md5"]:
                result["brands"][brand.key] = entry
        browser.close()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--brand", action="append", help="Limit to one or more brand keys")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    out = build(args.brand)
    for key, entry in sorted(out["brands"].items()):
        print(f"{key:<10} screenshots={len(entry['screenshots'])} favicons={len(entry['favicon_md5'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
