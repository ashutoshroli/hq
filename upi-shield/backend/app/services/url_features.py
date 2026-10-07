"""Stage 1: cheap lexical scoring that runs on every URL (no network)."""
import re
from urllib.parse import urlparse

from app import brands as brand_catalogue
from app.schemas import Signal

# keyword -> official registered domains (derived from the brand catalogue).
BRANDS: dict[str, frozenset[str]] = {
    kw: b.official_domains for b in brand_catalogue.BRANDS.values() for kw in b.keywords
}
_KEYWORD_TO_BRAND = brand_catalogue.keyword_index()
SUSPICIOUS_TLDS = {"xyz", "top", "click", "live", "icu", "site", "online", "shop", "buzz", "cfd"}
LURE_WORDS = ("verify", "kyc", "update", "reward", "cashback", "refund", "secure", "login", "claim", "blocked")
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})


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


def score_url(url: str) -> tuple[float, list[Signal], str | None]:
    host = host_of(url)
    reg = registered_domain(host)
    normalized = host.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    signals: list[Signal] = []
    brand_hit: str | None = None

    for keyword, official in BRANDS.items():
        if keyword in normalized and reg not in official:
            brand_hit = _KEYWORD_TO_BRAND[keyword]
            signals.append(Signal(name="brand_in_unofficial_domain", weight=0.5,
                                  detail=f"'{keyword}' appears in {host} but domain is not official"))
            if keyword not in host:
                signals.append(Signal(name="homoglyph_obfuscation", weight=0.2,
                                      detail=f"{host} resembles '{keyword}' after character normalisation"))
            break

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        signals.append(Signal(name="suspicious_tld", weight=0.15, detail=f".{tld} is common in throwaway domains"))
    if host.startswith("xn--") or ".xn--" in host:
        signals.append(Signal(name="punycode", weight=0.2, detail="Punycode (IDN) host"))
    if host.count("-") >= 2:
        signals.append(Signal(name="many_hyphens", weight=0.1, detail=f"{host.count('-')} hyphens in host"))
    lures = [w for w in LURE_WORDS if w in url.lower()]
    if lures:
        signals.append(Signal(name="lure_keywords", weight=0.15, detail="Contains: " + ", ".join(lures)))
    if len(host) > 40:
        signals.append(Signal(name="long_host", weight=0.05, detail=f"Host length {len(host)}"))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        signals.append(Signal(name="ip_host", weight=0.3, detail="Raw IP address instead of a domain"))

    score = min(1.0, sum(s.weight for s in signals))
    return score, signals, brand_hit


def verdict_for(score: float) -> str:
    return "malicious" if score >= 0.7 else "suspicious" if score >= 0.4 else "benign"
