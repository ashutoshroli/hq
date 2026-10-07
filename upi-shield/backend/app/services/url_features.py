"""Stage 1: cheap lexical scoring that runs on every URL. Replace/extend with ML later."""
import re
from urllib.parse import urlparse

from app.schemas import Signal

# keyword -> official registered domain(s)
BRANDS: dict[str, set[str]] = {
    "phonepe": {"phonepe.com"},
    "gpay": {"pay.google.com", "google.com"},
    "googlepay": {"pay.google.com", "google.com"},
    "paytm": {"paytm.com"},
    "bhim": {"bhimupi.org.in", "npci.org.in"},
    "sbi": {"onlinesbi.sbi", "sbi.co.in"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "live", "icu", "site", "online", "shop", "buzz", "cfd"}
LURE_WORDS = ("verify", "kyc", "update", "reward", "cashback", "refund", "secure", "login", "claim", "blocked")
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})


def host_of(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def registered_domain(host: str) -> str:
    # naive: last two labels. Swap for tldextract to handle .co.in, .org.in etc.
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def score_url(url: str) -> tuple[float, list[Signal], str | None]:
    host = host_of(url)
    reg = registered_domain(host)
    normalized = host.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    signals: list[Signal] = []
    brand_hit: str | None = None

    for brand, official in BRANDS.items():
        if brand in normalized and reg not in official:
            brand_hit = brand
            signals.append(Signal(name="brand_in_unofficial_domain", weight=0.5,
                                  detail=f"'{brand}' appears in {host} but domain is not official"))
            if brand not in host:
                signals.append(Signal(name="homoglyph_obfuscation", weight=0.2,
                                      detail=f"{host} resembles '{brand}' after character normalisation"))
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
