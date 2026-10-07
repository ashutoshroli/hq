"""Evasion-tactic detection: homographs, typosquats, shorteners, cloaking, domain age."""
from datetime import UTC, datetime, timedelta

import pytest

from app.services import enrichment, evasion, pipeline, url_features
from app.services.fetcher import FetchResult, parse_html


def _names(url: str) -> set[str]:
    return {s.name for s in url_features.score_url(url)[1]}


@pytest.mark.parametrize(("unicode_host", "brand"), [
    ("pаytm.com", "paytm"),          # Cyrillic a
    ("phоnepe-kyc.in", "phonepe"),   # Cyrillic o
    ("ісісі.com", "icici"),          # fully Cyrillic
])
def test_idn_homographs_are_attributed_to_the_brand(unicode_host, brand):
    url = "https://" + unicode_host.encode("idna").decode()
    score, signals, matched = url_features.score_url(url)
    assert matched == brand and score >= 0.7
    assert "homoglyph_obfuscation" in {s.name for s in signals}


def test_mixed_script_label_is_flagged():
    assert evasion.has_mixed_scripts("xn--pytm-53d.com")
    assert not evasion.has_mixed_scripts("paytm.com")


@pytest.mark.parametrize(("url", "brand"), [
    ("http://phonpe-kyc.top", "phonepe"),       # deletion (long keyword)
    ("http://paytn-cashback.in", "paytm"),      # substitution
    ("http://phonepay-reward.com", "phonepe"),  # substitution + suffix
    ("http://iccici-netbanking.top", "icici"),  # insertion
    ("http://axisbnak-kyc.in", "axisbank"),     # transposition
])
def test_typosquats_are_detected(url, brand):
    _score, signals, matched = url_features.score_url(url)
    assert matched == brand and "typosquatting" in {s.name for s in signals}


@pytest.mark.parametrize("url", [
    "https://www.payment.com", "https://paymentgateway.com", "https://hdfclife.com",
    "https://www.iciciprulife.com", "https://www.paypal.com", "https://github.com",
])
def test_ordinary_and_group_company_domains_are_not_typosquats(url):
    score, _signals, brand = url_features.score_url(url)
    assert brand is None and score < 0.4


def test_official_domain_used_as_subdomain_prefix():
    assert "official_domain_in_subdomain" in _names("http://phonepe.com.verify-user.top")


def test_shortener_and_free_hosting_are_flagged():
    assert "url_shortener" in _names("https://bit.ly/3xyz")
    assert "free_hosting_platform" in _names("https://phonepe-kyc.web.app")
    assert evasion.free_hosting_platform("phonepe.com") is None


def _page(url, html, status=200, final=None):
    forms, scripts, favicon = parse_html(html, final or url)
    return FetchResult(url=url, final_url=final or url, redirect_chain=[url] if not final else [url, final],
                       status=status, html=html, forms=forms, external_script_srcs=scripts,
                       favicon_href=favicon, ok=True)


PHISH = ("<html><title>Rewards</title><body>" + " ".join(f"word{i}" for i in range(40))
         + "<form action='https://collect.example/x'><input name='upi_pin' type='password'></form></body></html>")


def test_cloaking_redirect_for_crawlers():
    victim = _page("http://reward.top", PHISH)
    crawler = _page("http://reward.top", "<html>Google</html>", final="https://www.google.com/")
    sig = evasion.detect_cloaking(victim, crawler, lambda u: url_features.registered_domain(url_features.host_of(u)))
    assert sig is not None and sig.name == "cloaking_detected" and "google.com" in sig.detail


def test_cloaking_error_or_decoy_for_crawlers():
    reg = lambda u: url_features.registered_domain(url_features.host_of(u))  # noqa: E731
    victim = _page("http://reward.top", PHISH)
    assert evasion.detect_cloaking(victim, _page("http://reward.top", "Not found", status=404), reg).name \
        == "cloaking_detected"
    decoy = _page("http://reward.top", "<p>" + " ".join(f"recipe{i}" for i in range(40)) + "</p>")
    assert evasion.detect_cloaking(victim, decoy, reg).name == "cloaking_detected"
    assert evasion.detect_cloaking(victim, _page("http://reward.top", PHISH), reg) is None


def test_bot_challenge_is_reported():
    page = FetchResult(url="http://x.top", ok=True, html="<title>Just a moment...</title>", title="Just a moment...")
    assert evasion.bot_challenge(page).name == "bot_challenge"
    assert evasion.bot_challenge(_page("http://x.top", "<p>hello</p>")) is None


def test_domain_age_signals():
    now = datetime(2026, 1, 31, tzinfo=UTC)
    assert evasion.domain_age_signal(now - timedelta(days=3), now).name == "newly_registered_domain"
    assert evasion.domain_age_signal(now - timedelta(days=100), now).name == "recently_registered_domain"
    assert evasion.domain_age_signal(now - timedelta(days=3000), now) is None
    assert evasion.domain_age_signal(None) is None


def test_parse_rdap():
    data = {"events": [{"eventAction": "registration", "eventDate": "2026-10-01T08:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}]}
    info = enrichment.parse_rdap(data)
    assert info["registrar"] == "Example Registrar" and info["created"].year == 2026
    assert enrichment.parse_rdap({}) == {"created": None, "registrar": None}


def test_pipeline_scores_the_landing_page_behind_a_short_link():
    start, landing = "https://bit.ly/3xyz", "http://phonepe-kyc-verify.xyz/login"
    page = _page(start, "<title>x</title>", final=landing)
    cand = pipeline.analyze_url(start, "message", do_fetch=False, fetch_result=page)
    assert cand.brand_matched == "phonepe" and cand.verdict == "malicious"
    assert "landing_brand_in_unofficial_domain" in {s.name for s in cand.signals}
    assert {"bit.ly", "phonepe-kyc-verify.xyz"} <= {e.value for e in cand.entities if e.type == "domain"}


def test_pipeline_inspects_mobile_only_harvesting_form():
    url = "http://wallet-offer.top/"
    desktop = _page(url, "<title>Offer</title><p>Please open this page on your phone.</p>")
    mobile = _page(url, PHISH)
    cand = pipeline.analyze_url(url, "message", do_fetch=False, fetch_result=desktop,
                                probes={"mobile": mobile, "crawler": desktop})
    details = {s.name: s.detail for s in cand.signals}
    assert "mobile view only" in details["credential_input_fields"]
    assert "cloaking_detected" in details  # crawler sees the desktop decoy, phones see the form


def test_pipeline_adds_domain_age_when_fetching(monkeypatch):
    from app.services import fetcher

    monkeypatch.setattr(fetcher, "fetch", lambda url, *a, **k: FetchResult(url=url))
    monkeypatch.setattr(enrichment, "enrich", lambda *a, **k: [])
    monkeypatch.setattr(enrichment, "domain_created", lambda d: datetime.now(UTC) - timedelta(days=2))
    cand = pipeline.analyze_url("http://paytm-kyc-desk.top", "user_report", do_fetch=True)
    assert "newly_registered_domain" in {s.name for s in cand.signals}


def test_crawler_block_on_benign_site_is_informational_only():
    """Sites such as Wikipedia answer spoofed crawler requests with 403; without a
    phishing context that must not raise the score."""
    url = "https://en.wikipedia.org/"
    page = _page(url, "<title>Wikipedia</title><p>" + " ".join(f"article{i}" for i in range(40)) + "</p>")
    blocked = _page(url, "Forbidden", status=403)
    cand = pipeline.analyze_url(url, "feed", do_fetch=False, fetch_result=page,
                                probes={"mobile": page, "crawler": blocked})
    cloak = next(s for s in cand.signals if s.name == "cloaking_detected")
    assert cloak.weight == 0.0 and cand.risk_score == 0.0
