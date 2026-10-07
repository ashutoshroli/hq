"""Tests for infrastructure enrichment, enriched-entity clustering, and recipient
context in takedown reports. Everything runs fully offline via stubbed resolvers."""
from datetime import UTC, datetime
from types import SimpleNamespace

from app.schemas import Candidate, Entity, Signal
from app.services import clustering, enrichment, takedown


def _cand(cid: str, url: str, domain: str, entities: list[Entity], brand="phonepe") -> Candidate:
    return Candidate(
        id=cid, url=url, domain=domain, source="ct_log",
        first_seen=datetime.now(UTC), risk_score=0.9, verdict="malicious",
        brand_matched=brand,
        signals=[Signal(name="brand_in_unofficial_domain", weight=0.5, detail="x")],
        entities=[Entity(type="domain", value=domain), *entities],
    )


# --- enrich() with stubbed resolvers (no network) -------------------------------

def test_enrich_returns_typed_entities_from_stubbed_resolvers():
    resolvers = {
        "ip": lambda host: "203.0.113.9",
        "asn": lambda ip: "AS12345",
        "cert": lambda host: "deadbeef" * 4,
        "registrar": lambda host: "Example Registrar Inc",
    }
    html = '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ"></script>UA-1234567-1'
    fr = SimpleNamespace(html=html)
    ents = enrichment.enrich("paytm-claim.click", fetch_result=fr, resolvers=resolvers)
    by_type = {(e.type, e.value) for e in ents}
    assert ("ip", "203.0.113.9") in by_type
    assert ("asn", "AS12345") in by_type
    assert ("cert_fingerprint", "deadbeef" * 4) in by_type
    assert ("registrar", "Example Registrar Inc") in by_type
    assert ("analytics_id", "G-ABC123XYZ") in by_type
    assert ("analytics_id", "UA-1234567-1") in by_type


def test_enrich_returns_empty_when_all_resolvers_fail():
    resolvers = {
        "ip": lambda host: None,
        "asn": lambda ip: None,
        "cert": lambda host: None,
        "registrar": lambda host: None,
    }
    ents = enrichment.enrich("nope.invalid", fetch_result=None, resolvers=resolvers)
    assert ents == []


def test_enrich_never_raises_when_resolvers_throw():
    resolvers = {
        "ip": lambda host: (_ for _ in ()).throw(RuntimeError("boom")),
        "asn": lambda ip: (_ for _ in ()).throw(RuntimeError("boom")),
        "cert": lambda host: (_ for _ in ()).throw(RuntimeError("boom")),
        "registrar": lambda host: (_ for _ in ()).throw(RuntimeError("boom")),
    }
    # Must not raise and must return [] when nothing resolves.
    assert enrichment.enrich("x.test", fetch_result=None, resolvers=resolvers) == []


def test_scrape_analytics_ids_dedupes_and_ignores_empty():
    assert enrichment.scrape_analytics_ids("") == []
    # G-/GTM- IDs are only picked up inside a tracking context (quotes, '=', gtag/config
    # calls); UA- IDs are distinctive enough to match in prose too. Duplicates collapse.
    html = (
        "<script>gtag('config','G-ABCDEF1234');gtag('config','G-ABCDEF1234');</script>"
        '<script src="https://www.googletagmanager.com/gtag/js?id=GTM-WXYZ99"></script>'
        "UA-1234-7"
    )
    assert enrichment.scrape_analytics_ids(html) == ["G-ABCDEF1234", "GTM-WXYZ99", "UA-1234-7"]


def test_scrape_analytics_ids_ignores_bare_uppercase_prose():
    """A strong clustering link must not fire on stray uppercase words in page copy."""
    html = "<p>Our G-SERIES phones and the GTM-PLAYBOOK are great. Visit now!</p>"
    assert enrichment.scrape_analytics_ids(html) == []
    # But a genuine gtag call in the same page is still captured.
    html2 = html + "<script>gtag('config', 'G-REALID9876');</script>"
    assert enrichment.scrape_analytics_ids(html2) == ["G-REALID9876"]


# --- clustering with enriched entities ------------------------------------------

def test_shared_ip_clusters_into_one_campaign():
    ip = Entity(type="ip", value="198.51.100.5")
    cands = [
        _cand("a", "http://a.example", "a.example", [ip]),
        _cand("b", "http://b.example", "b.example", [ip]),
    ]
    camps = clustering.build_campaigns(cands)
    assert len(camps) == 1
    assert camps[0].size == 2


def test_asn_only_sharing_does_not_create_campaign():
    asn = Entity(type="asn", value="AS64500")
    cands = [
        _cand("a", "http://a.example", "a.example", [asn]),
        _cand("b", "http://b.example", "b.example", [asn]),
    ]
    camps = clustering.build_campaigns(cands)
    assert camps == []


def test_asn_reinforces_but_ip_links():
    # Shared IP links them; ASN additionally shows up as shared evidence.
    ip = Entity(type="ip", value="198.51.100.9")
    asn = Entity(type="asn", value="AS64500")
    cands = [
        _cand("a", "http://a.example", "a.example", [ip, asn]),
        _cand("b", "http://b.example", "b.example", [ip, asn]),
    ]
    camps = clustering.build_campaigns(cands)
    assert len(camps) == 1
    shared = {(e.type, e.value) for e in camps[0].shared_entities}
    assert ("ip", "198.51.100.9") in shared
    assert ("asn", "AS64500") in shared


# --- takedown recipient context --------------------------------------------------

def test_hosting_report_includes_ip_asn_and_reported_urls():
    ip = Entity(type="ip", value="198.51.100.5")
    asn = Entity(type="asn", value="AS64500")
    cands = [
        _cand("a", "http://a.example", "a.example", [ip, asn]),
        _cand("b", "http://b.example", "b.example", [ip, asn]),
    ]
    camps = clustering.build_campaigns(cands)
    assert len(camps) == 1
    rep = takedown.generate(camps[0], cands, "hosting")
    assert "Reported URLs" in rep.body
    assert "198.51.100.5" in rep.body
    assert "AS64500" in rep.body
    assert "Hosting / network context" in rep.body


def test_report_degrades_when_relevant_entities_absent():
    # bank report wants upi_id/phone; this campaign only shares an IP.
    ip = Entity(type="ip", value="198.51.100.5")
    cands = [
        _cand("a", "http://a.example", "a.example", [ip]),
        _cand("b", "http://b.example", "b.example", [ip]),
    ]
    camps = clustering.build_campaigns(cands)
    rep = takedown.generate(camps[0], cands, "bank")
    assert "Reported URLs" in rep.body
    assert "(none available)" in rep.body


def test_registrar_report_lists_member_domains():
    # registrar context must list the per-member domains (read from members, since
    # 'domain' is unique per candidate and never a shared entity).
    ip = Entity(type="ip", value="198.51.100.5")
    cands = [
        _cand("a", "http://a.example/login", "a.example", [ip]),
        _cand("b", "http://b.example/pay", "b.example", [ip]),
    ]
    camps = clustering.build_campaigns(cands)
    rep = takedown.generate(camps[0], cands, "registrar")
    assert "domain: a.example" in rep.body
    assert "domain: b.example" in rep.body
    assert "Reported URLs" in rep.body


def test_cert_in_report_lists_member_domains_and_shared_entities():
    ip = Entity(type="ip", value="198.51.100.5")
    cands = [
        _cand("a", "http://a.example/login", "a.example", [ip]),
        _cand("b", "http://b.example/pay", "b.example", [ip]),
    ]
    camps = clustering.build_campaigns(cands)
    rep = takedown.generate(camps[0], cands, "cert_in")
    assert "domain: a.example" in rep.body
    assert "domain: b.example" in rep.body
    assert "198.51.100.5" in rep.body  # shared ip still surfaced


def test_safe_browsing_lists_all_urls():
    ip = Entity(type="ip", value="198.51.100.5")
    cands = [
        _cand("a", "http://a.example/login", "a.example", [ip]),
        _cand("b", "http://b.example/pay", "b.example", [ip]),
    ]
    camps = clustering.build_campaigns(cands)
    rep = takedown.generate(camps[0], cands, "safe_browsing")
    assert "http://a.example/login" in rep.body
    assert "http://b.example/pay" in rep.body
    assert "Reported URLs" in rep.body
