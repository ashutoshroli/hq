"""Infrastructure graph, CDN-aware linking, network enrichment and pivots."""
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import Candidate, Entity, InfrastructureSummary
from app.services import clustering, enrichment, graph, pipeline
from app.store import store


def _cand(cid, host, entities, infra=None, score=0.9, kind="web"):
    return Candidate(id=cid, url=f"http://{host}/", domain=host, source="ct_log", first_seen=datetime.now(UTC),
                     risk_score=score, verdict="malicious", brand_matched="sbi", kind=kind,
                     entities=[Entity(type="domain", value=host), *entities], infrastructure=infra)


CDN = InfrastructureSummary(ip="104.17.75.195", asn="AS13335", as_name="Cloudflare", shared_hosting=True)
VPS = InfrastructureSummary(ip="203.0.113.7", asn="AS64500", as_name="Example VPS", shared_hosting=False)


def test_shared_cdn_ip_does_not_merge_campaigns():
    a = _cand("a", "sbi-kyc-a.top", [Entity(type="ip", value=CDN.ip)], CDN)
    b = _cand("b", "hdfc-kyc-b.top", [Entity(type="ip", value=CDN.ip)], CDN)
    assert clustering.build_campaigns([a, b]) == []


def test_dedicated_ip_still_merges_campaigns():
    a = _cand("a", "sbi-kyc-a.top", [Entity(type="ip", value=VPS.ip)], VPS)
    b = _cand("b", "hdfc-kyc-b.top", [Entity(type="ip", value=VPS.ip)], VPS)
    camps = clustering.build_campaigns([a, b])
    assert len(camps) == 1 and ("ip", VPS.ip) in {(e.type, e.value) for e in camps[0].shared_entities}


def test_cdn_sites_still_link_through_payment_handles():
    upi = Entity(type="upi_id", value="mule.kyc@okaxis")
    a = _cand("a", "sbi-kyc-a.top", [Entity(type="ip", value=CDN.ip), upi], CDN)
    b = _cand("b", "hdfc-kyc-b.top", [Entity(type="ip", value=CDN.ip), upi], CDN)
    assert len(clustering.build_campaigns([a, b])) == 1


def test_graph_nodes_carry_candidate_and_linking_facts():
    a = _cand("a", "sbi-kyc-a.top", [Entity(type="ip", value=CDN.ip), Entity(type="upi_id", value="m@okaxis")], CDN)
    b = _cand("b", "hdfc-kyc-b.top", [Entity(type="ip", value=CDN.ip), Entity(type="upi_id", value="m@okaxis")], CDN)
    g = graph.build_graph([a, b])
    nodes = {n.id: n for n in g.nodes}
    assert nodes["domain:sbi-kyc-a.top"].candidate_id == "a" and nodes["domain:sbi-kyc-a.top"].risk_score == 0.9
    assert nodes[f"ip:{CDN.ip}"].linking is False and nodes[f"ip:{CDN.ip}"].degree == 2
    assert nodes["upi_id:m@okaxis"].linking is True
    assert nodes["asn:AS13335"].label.startswith("AS13335")
    relations = {(e.source, e.target, e.relation) for e in g.edges}
    assert ("domain:sbi-kyc-a.top", "upi_id:m@okaxis", "collects_payments_to") in relations
    assert (f"ip:{CDN.ip}", "asn:AS13335", "in_network") in relations
    assert not any(e.source == e.target for e in g.edges)


def test_graph_endpoint_hides_benign_by_default_and_pivot():
    with TestClient(app) as client:
        g = client.get("/graph").json()
        assert all(n["verdict"] != "benign" for n in g["nodes"] if n.get("candidate_id"))
        hits = client.get("/pivot", params={"type": "upi_id", "value": "rewards.help@okaxis"}).json()
        assert len(hits) == 2 and {h["campaign_id"] for h in hits} == {store.campaigns[0].id}


def test_rdap_registrar_abuse_contacts():
    data = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                              ["email", {}, "text", "abuse@reg.example"], ["tel", {}, "uri", "tel:+1.555"]]]}]}]}
    info = enrichment.parse_rdap(data)
    assert info["abuse_email"] == "abuse@reg.example" and info["abuse_phone"] == "+1.555"


def test_infrastructure_summary_marks_cdn(monkeypatch):
    monkeypatch.undo()  # use the real function with stubbed network helpers
    monkeypatch.setattr(enrichment, "_default_ip_resolver", lambda host: "104.17.75.195")
    monkeypatch.setattr(enrichment, "asn_info", lambda ip: {"asn": "AS13335", "as_name": "Cloudflare",
                                                            "prefix": "104.17.64.0/20"})
    monkeypatch.setattr(enrichment, "hosting_abuse_contacts", lambda ip: ["abuse@cloudflare.com"])
    monkeypatch.setattr(enrichment, "rdap_lookup", lambda d: {"created": None, "registrar": "Reg Inc",
                                                              "abuse_email": "abuse@reg.example"})
    infra = enrichment.infrastructure("sbi-kyc.example")
    assert infra.shared_hosting and infra.hosting_abuse_contacts == ["abuse@cloudflare.com"]
    assert infra.registrar_abuse_email == "abuse@reg.example"


def test_pipeline_attaches_infrastructure_when_fetching(monkeypatch):
    from app.services import fetcher

    monkeypatch.setattr(fetcher, "fetch", lambda url, *a, **k: fetcher.FetchResult(url=url))
    monkeypatch.setattr(enrichment, "enrich", lambda *a, **k: [Entity(type="ip", value=VPS.ip)])
    monkeypatch.setattr(enrichment, "infrastructure", lambda host, ip=None: VPS)
    cand = pipeline.analyze_url("http://sbi-kyc-desk.top", "ct_log", do_fetch=True)
    assert cand.infrastructure == VPS
    assert ("asn", "AS64500") in {(e.type, e.value) for e in cand.entities}
