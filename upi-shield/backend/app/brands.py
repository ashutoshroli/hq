"""Catalogue of monitored payment and banking brands.

Single source of truth for brand keywords, officially owned registered domains and
the legal entities that genuine certificates are issued to. Used by URL scoring,
certificate-transparency discovery and the visual engine.

``official_domains`` lists registrable domains (eTLD+1). A host is official when its
registered domain is in this set. ``legal_entities`` are lower-case organisation names
found in OV/EV certificate subjects; a certificate issued to one of them is treated as
genuine brand infrastructure even if the domain is not catalogued yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Brand:
    key: str
    display_name: str
    keywords: tuple[str, ...]
    official_domains: frozenset[str]
    legal_entities: tuple[str, ...] = ()
    android_packages: tuple[str, ...] = ()
    reference_urls: tuple[str, ...] = field(default=())


BRANDS: dict[str, Brand] = {b.key: b for b in [
    Brand("phonepe", "PhonePe", ("phonepe",),
          frozenset({"phonepe.com"}),
          ("phonepe private limited", "phonepe limited"),
          ("com.phonepe.app",),
          ("https://www.phonepe.com/",)),
    Brand("gpay", "Google Pay", ("gpay", "googlepay"),
          frozenset({"google.com", "gpay.app", "pay.google.com"}),
          ("google llc",),
          ("com.google.android.apps.nbu.paisa.user",),
          ("https://pay.google.com/intl/en_in/about/", "https://pay.google.com/about/")),
    Brand("paytm", "Paytm", ("paytm",),
          frozenset({"paytm.com", "paytm.in", "paytmbank.com", "paytmpayments.com", "paytmpayments.in",
                     "paytmmoney.com", "paytminsurance.co.in", "paytm.bank.in", "paytmmall.com"}),
          ("one 97 communications limited", "paytm payments bank limited", "paytm money limited",
           "paytm payments services limited"),
          ("net.one97.paytm",),
          ("https://paytm.com/",)),
    Brand("bhim", "BHIM UPI", ("bhim",),
          frozenset({"bhimupi.org.in", "npci.org.in"}),
          ("national payments corporation of india",),
          ("in.org.npci.upiapp",),
          ("https://www.bhimupi.org.in/",)),
    Brand("sbi", "State Bank of India", ("sbi", "yono"),
          frozenset({"onlinesbi.sbi", "sbi.co.in", "sbi", "yonobusiness.sbi", "sbi.bank.in", "onlinesbi.com",
                     "sbicard.com", "yonosbi.com", "yonosbi.sbi"}),
          ("state bank of india",),
          ("com.sbi.lotusintouch", "com.sbi.SBIFreedomPlus"),
          ("https://www.onlinesbi.sbi/", "https://retail.onlinesbi.sbi/retail/login.htm")),
    Brand("hdfc", "HDFC Bank", ("hdfc",),
          frozenset({"hdfcbank.com", "hdfc.bank.in", "hdfcbank.bank.in", "hdfc.com", "hdfcbank.net"}),
          ("hdfc bank limited",),
          ("com.snapwork.hdfc",),
          ("https://www.hdfcbank.com/", "https://www.hdfcbank.com/personal")),
    Brand("icici", "ICICI Bank", ("icici",),
          frozenset({"icicibank.com", "icici.bank.in", "icicibank.co.in", "icicidirect.com"}),
          ("icici bank limited",),
          ("com.csam.icici.bank.imobile",),
          ("https://www.icicibank.com/",)),
    Brand("axisbank", "Axis Bank", ("axisbank",),
          frozenset({"axisbank.com", "axis.bank.in", "axisbank.co.in"}),
          ("axis bank limited",),
          ("com.axis.mobile",),
          ("https://www.axisbank.com/",)),
]}

# Registry suffixes that are newer than tldextract's bundled Public Suffix List snapshot.
# RBI moved Indian banks to the exclusive .bank.in zone in 2025 (and .fin.in for NBFCs).
EXTRA_PUBLIC_SUFFIXES: tuple[str, ...] = ("bank.in", "fin.in")


def keyword_index() -> dict[str, str]:
    """Map every brand keyword to its brand key."""
    return {kw: b.key for b in BRANDS.values() for kw in b.keywords}


def is_official(brand_key: str, registered_domain: str) -> bool:
    brand = BRANDS.get(brand_key)
    return bool(brand and registered_domain in brand.official_domains)


def official_brand_for(registered_domain: str) -> str | None:
    """Return the brand that owns ``registered_domain``, if any."""
    for brand in BRANDS.values():
        if registered_domain in brand.official_domains:
            return brand.key
    return None


def brand_for_legal_entity(text: str) -> str | None:
    """Return the brand whose legal entity name appears in ``text`` (e.g. a cert subject)."""
    low = (text or "").lower()
    for brand in BRANDS.values():
        if any(entity in low for entity in brand.legal_entities):
            return brand.key
    return None
