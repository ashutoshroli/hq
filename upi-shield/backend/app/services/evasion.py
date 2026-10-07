"""Detection of common phishing evasion tactics.

Lexical (no network, used by URL scoring):
  * Unicode confusables / IDN homographs - "pаytm" with a Cyrillic "а", decoded from
    punycode and mapped to a Latin skeleton before brand matching.
  * Typosquatting - brand keywords within one edit ("phonpe", "paytn", "phonepay").
  * Combosquatting with the official domain - "phonepe.com.verify-user.top".
  * URL shorteners and free hosting / tunnelling platforms that hide the real target
    or give attackers a disposable reputation.

Content-based (needs a fetch, used by the pipeline):
  * Cloaking - the page served to a mobile visitor differs from what a crawler sees
    (decoy page, error, or redirect away), a standard trick against scanners.
  * Bot challenges - a CAPTCHA / interstitial in front of the page.
  * Newly registered domains - via RDAP registration date.
"""
from __future__ import annotations

import contextlib
import logging
import re
import unicodedata
from datetime import UTC, datetime

from app.schemas import Signal

logger = logging.getLogger(__name__)

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "t.ly", "rb.gy", "shorturl.at", "goo.gl", "ow.ly",
    "t.co", "buff.ly", "rebrand.ly", "tiny.cc", "s.id", "v.gd", "shorte.st", "bitly.com", "lnkd.in",
    "surl.li", "clck.ru", "qr.ae", "u.to", "short.gy", "urlz.fr", "bl.ink", "tny.im",
})

# Hosting platforms where anyone can publish under a shared parent domain in seconds.
FREE_HOSTING_SUFFIXES = (
    "vercel.app", "netlify.app", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "github.io",
    "gitlab.io", "000webhostapp.com", "replit.app", "repl.co", "glitch.me", "herokuapp.com", "onrender.com",
    "blogspot.com", "weebly.com", "wixsite.com", "webflow.io", "framer.app", "godaddysites.com",
    "sites.google.com", "ngrok-free.app", "ngrok.io", "trycloudflare.com", "duckdns.org", "serveo.net",
    "azurewebsites.net", "web.core.windows.net", "appspot.com", "surge.sh", "fly.dev", "railway.app",
    "carrd.co", "square.site", "mystrikingly.com", "wordpress.com", "ipfs.io", "dweb.link",
)

# Latin look-alikes from Cyrillic and Greek (the scripts used in real IDN homograph attacks).
_CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "с": "c", "е": "e", "ё": "e", "һ": "h", "і": "i", "ј": "j", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "ԛ": "q", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ԝ": "w", "ь": "b",
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w", "ӏ": "l", "ɑ": "a", "ɡ": "g", "ı": "i",
})
_DIGIT_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "8": "b"})


def decode_idn(host: str) -> str:
    """Decode punycode labels (``xn--``) to Unicode; undecodable labels are kept as-is."""
    labels = []
    for label in (host or "").split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError, ValueError):
                label = label.encode("ascii").decode("idna")
        labels.append(label)
    return ".".join(labels)


def skeleton(host: str) -> str:
    """Latin skeleton of a host: IDN-decoded, accents stripped, confusables and digit
    homoglyphs mapped, and common multi-character tricks (rn -> m, vv -> w) collapsed."""
    text = unicodedata.normalize("NFKD", decode_idn(host).lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.translate(_CONFUSABLES).translate(_DIGIT_HOMOGLYPHS)
    return text.replace("rn", "m").replace("vv", "w")


def has_mixed_scripts(host: str) -> bool:
    """True when a label mixes Latin letters with Cyrillic/Greek ones (homograph tell)."""
    for label in decode_idn(host).split("."):
        scripts = set()
        for ch in label:
            if ch.isalpha():
                name = unicodedata.name(ch, "")
                scripts.add(name.split(" ")[0])
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            return True
    return False


def _within_one_edit(a: str, b: str) -> bool:
    """Optimal string alignment distance <= 1 (insert, delete, substitute or transpose)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    shorter, longer = (a, b) if la < lb else (b, a)
    i = j = 0
    skipped = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] != longer[j]:
            if skipped:
                return False
            skipped = True
            j += 1
            continue
        i += 1
        j += 1
    return True


# Ordinary words that sit one edit away from a brand keyword.
_TYPO_ALLOWLIST = ("payment", "paytime", "paytv", "phoneme", "phonebe")


def typosquat_keyword(text: str, keywords: list[str], min_len: int = 5) -> str | None:
    """Return a brand keyword that ``text`` contains within one edit (but not exactly).

    Substitutions, transpositions and insertions are checked for every keyword of
    ``min_len`` or more characters. Deletions ("phonpe") are only checked for keywords
    of seven or more characters, because a shorter keyword minus one letter matches
    ordinary words far too often ("paym" in "payment").
    """
    flat = re.sub(r"[^a-z0-9]", "", text.lower())
    for word in _TYPO_ALLOWLIST:
        flat = flat.replace(word, "#")
    for kw in keywords:
        if len(kw) < min_len or kw in flat:
            continue
        sizes = (len(kw) - 1, len(kw), len(kw) + 1) if len(kw) >= 7 else (len(kw), len(kw) + 1)
        for size in sizes:
            for start in range(0, max(0, len(flat) - size) + 1):
                window = flat[start:start + size]
                if len(window) == size and window[0] == kw[0] and _within_one_edit(window, kw):
                    return kw
    return None


def is_shortener(host: str) -> bool:
    host = (host or "").lower().removeprefix("www.")
    return host in URL_SHORTENERS


def free_hosting_platform(host: str) -> str | None:
    host = (host or "").lower()
    return next((s for s in FREE_HOSTING_SUFFIXES if host == s or host.endswith("." + s)), None)


def embedded_official_domain(host: str, official_domains: set[str], registered: str) -> str | None:
    """Official brand domain used as a *subdomain prefix* of an unrelated domain,
    e.g. ``phonepe.com.verify-user.top``."""
    for domain in official_domains:
        if registered != domain and (host.startswith(domain + ".") or f".{domain}." in host):
            return domain
    return None


# --- content-based -----------------------------------------------------------------------

_CHALLENGE_MARKERS = ("just a moment", "attention required", "checking your browser", "verify you are human",
                      "cf-challenge", "challenges.cloudflare.com", "g-recaptcha", "hcaptcha.com/1/api.js",
                      "ddos-guard", "captcha-delivery")
_WORD_RE = re.compile(r"[a-z0-9]{3,}")
_TAG_RE = re.compile(r"<(script|style)\b.*?</\1>|<[^>]+>", re.S | re.I)


def _visible_tokens(html: str) -> set[str]:
    return set(_WORD_RE.findall(_TAG_RE.sub(" ", html or "").lower()))


def bot_challenge(fetch_result) -> Signal | None:
    html = (getattr(fetch_result, "html", "") or "").lower()
    title = (getattr(fetch_result, "title", "") or "").lower()
    hit = next((m for m in _CHALLENGE_MARKERS if m in title or m in html[:20000]), None)
    if not hit:
        return None
    return Signal(name="bot_challenge", weight=0.05,
                  detail=f"Page is behind an anti-bot challenge ({hit}); content may be hidden from scanners")


def detect_cloaking(victim, crawler, registered_domain) -> Signal | None:
    """Compare the page a mobile victim receives with what a search-engine crawler gets.

    ``registered_domain`` maps a URL to its eTLD+1. Flags cloaking when the victim view
    is a real page but the crawler view is an error, a redirect to a different site, or
    content with little overlap.
    """
    if victim is None or crawler is None or not getattr(victim, "ok", False) or not victim.html:
        return None
    if not getattr(crawler, "ok", False):
        return Signal(name="cloaking_suspected", weight=0.15,
                      detail="The page loads for a mobile browser but the crawler request failed")
    v_site = registered_domain(victim.final_url or victim.url)
    c_site = registered_domain(crawler.final_url or crawler.url)
    if c_site and v_site and c_site != v_site:
        return Signal(name="cloaking_detected", weight=0.3,
                      detail=f"Mobile visitors stay on {v_site} but crawlers are redirected to {c_site}")
    if 200 <= victim.status < 400 and crawler.status >= 400:
        return Signal(name="cloaking_detected", weight=0.3,
                      detail=f"Mobile visitors receive HTTP {victim.status}; crawlers receive HTTP {crawler.status}")
    a, b = _visible_tokens(victim.html), _visible_tokens(crawler.html)
    if len(a) >= 20:
        overlap = len(a & b) / len(a | b) if (a | b) else 1.0
        if overlap < 0.2:
            return Signal(name="cloaking_detected", weight=0.3,
                          detail=f"Crawler sees different content from mobile visitors ({overlap:.0%} overlap)")
    return None


def domain_age_signal(created: datetime | None, now: datetime | None = None) -> Signal | None:
    if created is None:
        return None
    now = now or datetime.now(UTC)
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    age = (now - created).days
    if age < 0:
        return None
    if age <= 30:
        return Signal(name="newly_registered_domain", weight=0.25, detail=f"Domain registered {age} day(s) ago")
    if age <= 180:
        return Signal(name="recently_registered_domain", weight=0.1, detail=f"Domain registered {age} days ago")
    return None
