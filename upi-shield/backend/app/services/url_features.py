"""Stage 1: cheap lexical scoring that runs on every URL (no network)."""
import re
from urllib.parse import urlparse

from app import brands as brand_catalogue
from app.schemas import Signal
from app.services import evasion

# keyword -> official registered domains (derived from the brand catalogue).
BRANDS: dict[str, frozenset[str]] = {
    kw: b.official_domains for b in brand_catalogue.BRANDS.values() for kw in b.keywords
}
_KEYWORD_TO_BRAND = brand_catalogue.keyword_index()

# Keywords shorter than this occur inside ordinary words ("lesbian" contains "sbi",
# "yono" is a casino-app brand), so they only match as whole words: the rest of the
# host token must segment completely into banking / lure vocabulary.
SHORT_KEYWORD_LEN = 5
CONTEXT_WORDS = frozenset({
    "bank", "banking", "netbanking", "net", "online", "internet", "mobile", "app", "apps", "apk", "web", "portal",
    "secure", "security", "safe", "login", "signin", "logon", "auth", "verify", "verification", "verified",
    "kyc", "ekyc", "update", "updates", "upgrade", "reward", "rewards", "point", "points", "redeem", "cashback",
    "refund", "refunds", "claim", "bonus", "gift", "offer", "offers", "prize", "win", "card", "cards", "credit",
    "debit", "pay", "payment", "payments", "upi", "wallet", "account", "accounts", "acc", "customer", "care",
    "support", "help", "helpdesk", "desk", "service", "services", "official", "india", "in", "ind", "bharat",
    "loan", "loans", "apply", "pan", "aadhar", "aadhaar", "link", "block", "blocked", "unblock", "unlock",
    "activate", "activation", "reactivate", "alert", "notice", "limit", "yono", "lite", "rbi", "npci", "home",
    "my", "e", "i", "m", "go", "get", "new", "now", "pro", "plus", "center", "centre", "team", "id", "otp",
    "pin", "mpin", "transfer", "money", "cash", "fund", "funds", "txn", "co", "corp", "fin",
})


def _segments(rest: str, vocabulary: frozenset[str]) -> bool:
    """True if ``rest`` is empty, numeric, or splits entirely into vocabulary words."""
    rest = rest.strip("0123456789")
    if not rest:
        return True
    reachable = [True] + [False] * len(rest)
    for end in range(1, len(rest) + 1):
        reachable[end] = any(reachable[start] and rest[start:end] in vocabulary
                             for start in range(max(0, end - 12), end))
    return reachable[-1]


def keyword_in_host(keyword: str, normalized_host: str) -> bool:
    """Brand keyword match that is strict for short, collision-prone keywords.

    On free hosting platforms the subdomain is chosen by the uploader and genuine brands
    never publish there, so a label that *starts* with a short keyword is enough.
    """
    if len(keyword) >= SHORT_KEYWORD_LEN:
        return keyword in normalized_host
    platform = evasion.free_hosting_platform(normalized_host)
    if platform:
        user_part = normalized_host[: -len(platform)].rstrip(".")
        if any(label.startswith(keyword) for label in re.split(r"[^a-z0-9]+", user_part)):
            return True
    vocabulary = CONTEXT_WORDS | set(BRANDS)
    for token in re.split(r"[^a-z0-9]+", normalized_host):
        start = token.find(keyword)
        while start != -1:
            if _segments(token[:start], vocabulary) and _segments(token[start + len(keyword):], vocabulary):
                return True
            start = token.find(keyword, start + 1)
    return False
# TLDs with the highest phishing-abuse rates (cheap or free registration).
SUSPICIOUS_TLDS = {"xyz", "top", "click", "live", "icu", "site", "online", "shop", "buzz", "cfd", "sbs", "cyou",
                   "pw", "tk", "ml", "ga", "cf", "gq", "club", "rest", "bond", "autos", "lol", "mom", "quest",
                   "monster", "cam", "pics", "boats", "help", "support", "info", "cc", "ws", "vip", "work",
                   "life", "store", "fun", "space", "website", "tech", "today", "win", "loan", "link", "rf.gd"}
# Banking vocabulary that, next to a brand keyword in a host, signals combosquatting.
BANKING_TERMS = ("netbanking", "internetbanking", "onlinebank", "online", "benefit", "reward", "kyc", "pan",
                 "rewards", "points", "redeem", "creditcard", "support", "helpdesk", "customercare", "secure")
LURE_WORDS = ("verify", "kyc", "update", "reward", "cashback", "refund", "secure", "login", "claim", "blocked")


def host_of(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


try:  # Public Suffix List aware parsing; uses the bundled snapshot (no network).
    import tldextract as _tldextract

    _EXTRACT = _tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                      extra_suffixes=list(brand_catalogue.EXTRA_PUBLIC_SUFFIXES))
except Exception:  # noqa: BLE001 - optional dependency; fall back to a heuristic
    _EXTRACT = None

# Second-level labels commonly used under country-code TLDs (heuristic fallback only).
_CC_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "res", "gen", "firm", "ind"}


def has_public_suffix(host: str) -> bool:
    """True when ``host`` ends in a real public suffix (e.g. ``.com``, ``.co.in``, ``.top``)."""
    host = (host or "").lower().rstrip(".")
    if _EXTRACT is None:
        return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", host))
    ext = _EXTRACT(host)
    return bool(ext.suffix and (ext.domain or ext.subdomain))


def registered_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1), e.g. ``a.b.sbi.co.in`` -> ``sbi.co.in``."""
    host = (host or "").lower().rstrip(".")
    if not host or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return host
    if _EXTRACT is not None:
        ext = _EXTRACT(host)
        reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        if reg:
            return reg
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _CC_SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


_OFFICIAL_DOMAINS = frozenset(d for b in brand_catalogue.BRANDS.values() for d in b.official_domains if "." in d)


def _brand_in_path(url: str) -> str | None:
    """An official brand domain, or a long brand keyword, inside the path or query string
    (``evil.tk/icicibank.co.in/netbanking``). Returns the matched domain or keyword."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    rest = f"{parsed.path} {parsed.query}".lower()
    if not rest.strip(" /"):
        return None
    for domain in _OFFICIAL_DOMAINS:
        if re.search(rf"(?<![a-z0-9-]){re.escape(domain)}(?![a-z0-9-])", rest) and "@" + domain not in rest:
            return domain
    return None


def score_url(url: str) -> tuple[float, list[Signal], str | None]:
    host = host_of(url)
    reg = registered_domain(host)
    normalized = evasion.skeleton(host)
    signals: list[Signal] = []
    brand_hit: str | None = None
    owner = brand_catalogue.official_brand_for(reg)

    for keyword, official in BRANDS.items():
        if owner is None and keyword_in_host(keyword, normalized):
            brand_hit = _KEYWORD_TO_BRAND[keyword]
            signals.append(Signal(name="brand_in_unofficial_domain", weight=0.5,
                                  detail=f"'{keyword}' appears in {host} but domain is not official"))
            if keyword not in evasion.decode_idn(host):
                signals.append(Signal(name="homoglyph_obfuscation", weight=0.2,
                                      detail=f"{host} resembles '{keyword}' after character normalisation"))
            subdomain = host[: -len(reg)].rstrip(".") if reg and host.endswith(reg) else ""
            if subdomain and keyword_in_host(keyword, evasion.skeleton(subdomain)) \
                    and not keyword_in_host(keyword, evasion.skeleton(reg)):
                signals.append(Signal(name="brand_in_subdomain", weight=0.2,
                                      detail=f"Brand '{keyword}' is used as a subdomain of unrelated domain {reg}"))
            # Match on the raw host too: homoglyph folding rewrites "rn" (internetbanking).
            flat = host.replace("-", "") + " " + normalized.replace("-", "")
            terms = [t for t in BANKING_TERMS if t in flat]
            if terms:
                signals.append(Signal(name="brand_with_banking_terms", weight=0.2,
                                      detail=f"Combines '{keyword}' with banking terms: " + ", ".join(terms[:3])))
            embedded = evasion.embedded_official_domain(host, set(official), reg)
            if embedded:
                signals.append(Signal(name="official_domain_in_subdomain", weight=0.2,
                                      detail=f"Official domain {embedded} is used as a prefix of {reg}"))
            break

    if brand_hit is None and owner is None:
        squatted = evasion.typosquat_keyword(normalized, list(BRANDS))
        if squatted:
            brand_hit = _KEYWORD_TO_BRAND[squatted]
            signals.append(Signal(name="typosquatting", weight=0.45,
                                  detail=f"{host} is one edit away from the brand keyword '{squatted}'"))

    if evasion.has_mixed_scripts(host):
        signals.append(Signal(name="idn_homograph", weight=0.3,
                              detail=f"{evasion.decode_idn(host)} mixes Latin with Cyrillic/Greek look-alikes"))
    if evasion.is_shortener(host):
        signals.append(Signal(name="url_shortener", weight=0.1,
                              detail=f"{host} is a URL shortener that hides the real destination"))
    platform = evasion.free_hosting_platform(host)
    if platform:
        signals.append(Signal(name="free_hosting_platform", weight=0.2,
                              detail=f"Hosted on {platform}, where anyone can publish instantly"))

    if brand_hit is None and owner is None:
        in_path = _brand_in_path(url)
        if in_path:
            brand_hit = _KEYWORD_TO_BRAND.get(in_path, brand_catalogue.official_brand_for(in_path))
            signals.append(Signal(name="brand_in_url_path", weight=0.3,
                                  detail=f"'{in_path}' appears in the path of {host}, which the brand does not own"))

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        signals.append(Signal(name="suspicious_tld", weight=0.2, detail=f".{tld} is common in throwaway domains"))
    if host.startswith("xn--") or ".xn--" in host:
        signals.append(Signal(name="punycode", weight=0.2, detail="Punycode (IDN) host"))
    hyphens = evasion.decode_idn(host).count("-")
    if hyphens >= 2:
        signals.append(Signal(name="many_hyphens", weight=0.1, detail=f"{hyphens} hyphens in host"))
    lures = [w for w in LURE_WORDS if w in url.lower()]
    if lures:
        signals.append(Signal(name="lure_keywords", weight=0.2, detail="Contains: " + ", ".join(lures)))
    if len(host) > 40:
        signals.append(Signal(name="long_host", weight=0.05, detail=f"Host length {len(host)}"))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        signals.append(Signal(name="ip_host", weight=0.3, detail="Raw IP address instead of a domain"))

    score = min(1.0, sum(s.weight for s in signals))
    return score, signals, brand_hit


def verdict_for(score: float) -> str:
    return "malicious" if score >= 0.7 else "suspicious" if score >= 0.4 else "benign"
