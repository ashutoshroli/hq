"""Persistence, de-duplication, background jobs and the crawl/feed endpoints."""
import json

import pytest
from fastapi.testclient import TestClient

from app import jobs as jobs_module
from app.main import app
from app.schemas import Candidate, Entity
from app.services import crawler, feeds, ingest, url_features
from app.store import Store, normalize_url, store


def _cand(cid: str, url: str, score: float = 0.9, entities=None) -> Candidate:
    from datetime import UTC, datetime

    host = url_features.host_of(url)
    return Candidate(id=cid, url=url, domain=host, source="user_report", first_seen=datetime.now(UTC),
                     risk_score=score, verdict=url_features.verdict_for(score),
                     entities=[Entity(type="domain", value=host), *(entities or [])])


@pytest.mark.parametrize(("raw", "expected"), [
    ("PhonePe-KYC.xyz", "http://phonepe-kyc.xyz"),
    ("https://Example.com:443/", "https://example.com"),
    ("http://example.com:8080/login?x=1#frag", "http://example.com:8080/login?x=1"),
])
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


def test_registered_domain_handles_multi_label_suffixes():
    assert url_features.registered_domain("netbanking.sbi.co.in") == "sbi.co.in"
    assert url_features.registered_domain("www.bhimupi.org.in") == "bhimupi.org.in"
    assert url_features.registered_domain("185.199.110.153") == "185.199.110.153"


def test_store_persists_across_instances(tmp_path):
    path = str(tmp_path / "shield.db")
    first = Store(path)
    first.add(_cand("a1", "http://paytm-claim.click", entities=[Entity(type="upi_id", value="x@okaxis")]))
    first.add(_cand("a2", "http://paytm-refund.top", entities=[Entity(type="upi_id", value="x@okaxis")]))
    reopened = Store(path)
    assert set(reopened.candidates) == {"a1", "a2"}
    assert len(reopened.campaigns) == 1
    assert reopened.candidates["a1"].campaign_id == reopened.campaigns[0].id


def test_reingesting_same_url_updates_instead_of_duplicating():
    before = len(store.candidates)
    first = store.add(_cand("d1", "http://sbi-kyc-update.top/login"))
    second = store.add(_cand("d2", "HTTP://SBI-KYC-UPDATE.TOP/login#x",
                             entities=[Entity(type="phone", value="9000000001")]))
    assert second.id == first.id
    assert second.sightings == 2 and second.last_seen is not None
    assert {"domain", "phone"} <= {e.type for e in second.entities}
    assert len(store.candidates) == before + 1


def test_campaign_ids_are_stable_when_unrelated_candidates_arrive():
    ids_before = sorted(c.id for c in store.campaigns)
    store.add(_cand("u1", "http://unrelated-axisbank-offer.shop"))
    assert sorted(c.id for c in store.campaigns) == ids_before


def test_benign_candidates_never_join_campaigns():
    shared = [Entity(type="ip", value="198.51.100.9")]
    store.add(_cand("b1", "https://example.org", score=0.0, entities=shared))
    store.add(_cand("b2", "https://example.net", score=0.0, entities=shared))
    assert store.candidates["b1"].campaign_id is None


def test_job_records_progress_and_failures():
    def body(ctx):
        ctx.set_total(2)
        ctx.advance(ok=True, candidate_id="c1")
        ctx.advance(ok=False)

    job = jobs_module.jobs.submit("unit", {}, body)
    assert job.status == "done"
    assert (job.progress.total, job.progress.processed, job.progress.failed) == (2, 2, 1)
    assert job.candidate_ids == ["c1"]


def test_job_failure_is_recorded():
    def body(_ctx):
        raise ValueError("boom")

    job = jobs_module.jobs.submit("unit", {}, body)
    assert job.status == "failed" and "boom" in job.error


def test_batch_endpoint_runs_job_and_is_pollable():
    with TestClient(app) as client:
        r = client.post("/ingest/batch", json={"urls": ["http://phonepe-reward.icu", "http://hdfc-kyc.live"]})
        assert r.status_code == 202
        job = client.get(f"/jobs/{r.json()['job_id']}").json()
        assert job["status"] == "done" and job["progress"]["processed"] == 2
        assert all(cid in store.candidates for cid in job["candidate_ids"])
        assert any(j["id"] == job["id"] for j in client.get("/jobs").json())
        assert client.get("/jobs/does-not-exist").status_code == 404


def test_async_single_url_ingest():
    with TestClient(app) as client:
        r = client.post("/ingest/url", json={"url": "http://gpay-cashback.cfd", "run_async": True})
        assert r.json()["status"] == "done" and r.json()["candidate_ids"]


def test_crawl_job_discovers_and_analyses_ct_hosts():
    raw = json.dumps([{"name_value": "phonepe-kyc-help.xyz\n*.phonepe.com", "common_name": "phonepe-kyc-help.xyz"}])
    job = jobs_module.jobs.submit("crawl_ct", {}, ingest.crawl_job(["phonepe"], 10, fetch_fn=lambda u, p: raw))
    assert job.status == "done" and len(job.candidate_ids) == 1
    cand = store.candidates[job.candidate_ids[0]]
    assert cand.source == "ct_log" and cand.domain == "phonepe-kyc-help.xyz"


def test_crawler_passes_expired_exclusion_to_ct_source():
    seen = {}

    def fake(url, params):
        seen.update(params)
        return "[]"

    crawler.discover_from_ct(["paytm"], fetch_fn=fake)
    assert seen["exclude"] == "expired"


def test_feed_parsing_and_brand_filter():
    text = "# comment\nhttp://paytm-kyc.top/a\n\nhttps://random-shop.com\nhttp://paytm-kyc.top/a\nnot-a-url\n"
    assert feeds.parse_feed(text) == ["http://paytm-kyc.top/a", "https://random-shop.com"]
    assert feeds.fetch_feed("openphish", fetch_fn=lambda u: text) == ["http://paytm-kyc.top/a"]
    assert len(feeds.fetch_feed("openphish", brand_filter=False, fetch_fn=lambda u: text)) == 2
    assert feeds.fetch_feed("unknown") == []


def test_feed_outage_degrades_to_empty():
    def down(_url):
        raise ConnectionError("feed offline")

    assert feeds.fetch_feed("urlhaus", fetch_fn=down) == []


def test_feed_job_ingests_as_feed_source():
    text = "http://icici-netbanking-verify.site/login\n"
    job = jobs_module.jobs.submit("ingest_feed", {}, ingest.feed_job("openphish", True, 10, fetch_fn=lambda u: text))
    assert store.candidates[job.candidate_ids[0]].source == "feed"


def test_candidate_filters():
    with TestClient(app) as client:
        assert {c["brand_matched"] for c in client.get("/candidates?brand=phonepe").json()} == {"phonepe"}
        assert all("sbi" in c["url"] for c in client.get("/candidates?q=sbi").json())
        assert len(client.get("/candidates?limit=2").json()) == 2
        camp = client.get("/campaigns").json()[0]["id"]
        assert all(c["campaign_id"] == camp for c in client.get(f"/candidates?campaign_id={camp}").json())


def test_stats_endpoint():
    with TestClient(app) as client:
        body = client.get("/stats").json()
        assert body["candidates"] == 6 and body["campaigns"] == 2


def test_api_key_protects_mutating_endpoints(monkeypatch):
    monkeypatch.setenv("UPI_SHIELD_API_KEY", "s3cret")
    with TestClient(app) as client:
        assert client.post("/ingest/url", json={"url": "http://x-paytm.top"}).status_code == 401
        ok = client.post("/ingest/url", json={"url": "http://x-paytm.top"}, headers={"X-API-Key": "s3cret"})
        assert ok.status_code == 200
        assert client.get("/candidates").status_code == 200  # reads stay open


def test_ct_hostname_normalisation_drops_org_names_and_emails():
    names = ["*.PhonePe-Help.xyz", "PhonePe Private Limited", "admin@phonepe-help.xyz", "phonepe-help.xyz."]
    assert crawler.normalize_hostnames(names) == ["phonepe-help.xyz"]


def test_ct_postgres_backend_is_preferred(monkeypatch):
    monkeypatch.setattr(crawler, "_pg_query", lambda term: ["paytm-kyc-desk.top", "paytm.com", "Paytm Ltd"])
    monkeypatch.setattr(crawler, "_httpx_fetch", lambda *a, **k: pytest.fail("HTTP fallback must not run"))
    assert crawler.discover_from_ct(["paytm"]) == ["paytm-kyc-desk.top"]


def test_ct_postgres_failure_falls_back_to_http(monkeypatch):
    def pg_down(term):
        raise OSError("connection refused")

    raw = json.dumps([{"name_value": "sbi-yono-rewards.live"}])
    monkeypatch.setattr(crawler, "_pg_query", pg_down)
    monkeypatch.setattr(crawler, "_httpx_fetch", lambda url, params: raw)
    assert crawler.discover_from_ct(["sbi"]) == ["sbi-yono-rewards.live"]


def test_official_brand_domains_are_not_flagged():
    for url in ("https://paytm.bank.in", "https://netbanking.hdfcbank.bank.in", "https://www.paytmbank.com"):
        score, _signals, brand = url_features.score_url(url)
        assert brand is None and score < 0.4, url
