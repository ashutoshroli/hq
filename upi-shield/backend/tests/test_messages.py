"""Gap fixes: URL-less message lures and APK links reaching app analysis."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import casework, clustering, extractor, fetcher, graph, ingest, messages, pipeline
from app.services.fetcher import FetchResult
from app.store import store
from tests import apk_factory

KYC_SMS = ("Dear customer, your SBI account will be blocked today. Complete KYC by paying Rs 10 to "
           "sbi.kyc.help@ybl or call 9876543210. Card 4111111111111111")


# --- Gap A: messages without links --------------------------------------------------

def test_url_less_message_is_stored_with_its_indicators():
    found, ids = ingest.ingest_message(KYC_SMS, "message")
    assert found["urls"] == [] and len(ids) == 1
    cand = store.candidates[ids[0]]
    assert cand.kind == "message" and cand.url.startswith("message://") and cand.domain == "sms"
    assert {("upi_id", "sbi.kyc.help@ybl"), ("phone", "9876543210")} <= {(e.type, e.value) for e in cand.entities}
    assert cand.brand_matched == "sbi" and cand.verdict == "malicious"
    names = {s.name for s in cand.signals}
    assert {"brand_mentioned", "brand_impersonating_upi_handle", "payment_request_to_upi", "kyc_lure",
            "account_threat", "callback_number"} <= names


def test_message_excerpt_masks_card_and_account_numbers():
    excerpt = messages.redact(KYC_SMS)
    assert "4111111111111111" not in excerpt and "XXXXXXXXXXXX1111" in excerpt
    assert "9876543210" in excerpt  # 10-digit contact numbers are evidence, not victim data


def test_same_message_twice_is_one_candidate():
    _, first = ingest.ingest_message(KYC_SMS, "message")
    _, second = ingest.ingest_message("  " + KYC_SMS.upper() + " ", "message")
    assert first == second and store.candidates[first[0]].sightings == 2


def test_message_without_indicators_is_not_stored():
    before = len(store.candidates)
    found, ids = ingest.ingest_message("Your OTP for login is 482913. Do not share it.", "message")
    assert ids == [] and len(store.candidates) == before


def test_benign_payment_message_stays_below_malicious():
    _, ids = ingest.ingest_message("Hi, please send the rent to ravi.k@okhdfcbank by Friday", "message")
    cand = store.candidates[ids[0]]
    assert cand.verdict != "malicious" and cand.brand_matched is None


def test_message_joins_the_campaign_of_a_page_using_the_same_mule_handle():
    _, ids = ingest.ingest_message("Your PhonePe cashback is pending. Pay Rs 1 to rewards.help@okaxis to claim",
                                   "message")
    cand = store.candidates[ids[0]]
    camp = next(c for c in store.campaigns if cand.id in c.candidate_ids)
    assert {"seed1", "seed3"} <= set(camp.candidate_ids)  # seeded pages collecting to the same handle
    assert ("upi_id", "rewards.help@okaxis") in {(e.type, e.value) for e in camp.shared_entities}


def test_two_url_less_messages_sharing_a_number_form_a_campaign():
    first, second = "SBI KYC expired, call 9123456780 today", "HDFC account blocked. Call helpline 9123456780"
    a = messages.message_candidate(first, *_parts(first))
    b = messages.message_candidate(second, *_parts(second))
    camps = clustering.build_campaigns([a, b])
    assert len(camps) == 1 and camps[0].size == 2


def _parts(text):
    found = extractor.extract(text)
    return found, "message", ingest.message_entities(found)


def test_message_candidates_in_graph_reports_and_exports():
    _, ids = ingest.ingest_message("Your PhonePe cashback is pending. Pay Rs 1 to rewards.help@okaxis", "message")
    cand = store.candidates[ids[0]]
    camp = next(c for c in store.campaigns if cand.id in c.candidate_ids)
    members = [store.candidates[i] for i in camp.candidate_ids]
    nodes = {n.id: n for n in graph.build_graph(members).nodes}
    assert nodes[f"message:{cand.id}"].type == "message"
    from app.services import takedown

    assert "SMS lure" in takedown.generate(camp, members, "npci").body
    assert "message://" not in "\n".join(takedown.generate(camp, members, "safe_browsing").body.split("Reported")[0])
    registrar = next(i for i in casework.takedown_plan(camp, members).items if i.recipient == "registrar")
    assert all("message" not in t for t in registrar.targets)
    patterns = [o.get("pattern", "") for o in casework.stix_bundle(camp, members)["objects"]]
    assert not any("message://" in p for p in patterns)


@pytest.mark.parametrize(("text", "expected"), [
    ("Update KYC at sbi-kyc.top/update now", ["http://sbi-kyc.top/update"]),
    ("visit www.phonepe-kyc.in", ["http://www.phonepe-kyc.in"]),
    ("Dear Mr.Sharma, pay to sbi.kyc.help@ybl", []),
    ("see report.pdf, e.g. the attachment", []),
    ("mail me at a.b@gmail.com", []),
])
def test_bare_domains_in_messages(text, expected):
    assert extractor.extract(text)["urls"] == expected


# --- Gap B: APK links reach app analysis -----------------------------------------------

def _fake_apk():
    return apk_factory.build_apk("com.sbi.kyc.update", "SBI YONO KYC",
                                 ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS"],
                                 ["https://sbi-yono-update.top/api/sms"])


@pytest.mark.parametrize(("url", "is_apk"), [
    ("http://sbi-yono-update.top/SBI_YONO.apk", True),
    ("http://x.top/download?file=YONO.apk", True),
    ("http://x.top/app.APK?v=2", True),
    ("http://x.top/apk-guide.html", False),
    ("http://x.top/", False),
])
def test_is_apk_url(url, is_apk):
    assert fetcher.is_apk_url(url) is is_apk


def test_apk_link_in_message_is_analysed_as_an_app(monkeypatch):
    monkeypatch.setattr(fetcher, "download_apk", lambda url: _fake_apk())
    job_ids: list[str] = []
    text = "SBI YONO update required. Install http://sbi-yono-update.top/SBI_YONO.apk and pay to yono.kyc@ybl"
    _found, ids = ingest.ingest_message(text, "message", job_ids=job_ids)
    web = store.candidates[ids[0]]
    assert web.kind == "web" and "apk_download" in {s.name for s in web.signals}
    job = store.get_job(job_ids[0])
    assert job.status == "done"
    app_cand = store.candidates[job.candidate_ids[0]]
    assert app_cand.kind == "app" and app_cand.app.origin_url == "http://sbi-yono-update.top/SBI_YONO.apk"
    # The app carries the message's mule handle and the distribution host, so all three link.
    assert ("upi_id", "yono.kyc@ybl") in {(e.type, e.value) for e in app_cand.entities}
    web_campaign = store.candidates[web.id].campaign_id
    assert web_campaign is not None and web_campaign == store.candidates[app_cand.id].campaign_id


def test_apk_link_via_ingest_url_endpoint(monkeypatch):
    monkeypatch.setattr(fetcher, "download_apk", lambda url: _fake_apk())
    with TestClient(app) as client:
        body = client.post("/ingest/url", json={"url": "http://sbi-yono-update.top/SBI_YONO.apk"}).json()
        assert body["job_ids"] and client.get(f"/jobs/{body['job_ids'][0]}").json()["status"] == "done"
        msg = client.post("/ingest/message", json={"text": "Install http://sbi-yono-update.top/SBI_YONO.apk"}).json()
        assert msg["job_ids"]


def test_unreachable_apk_keeps_the_web_evidence():
    job_ids: list[str] = []
    cand = ingest.analyze_and_store("http://sbi-yono-update.top/SBI_YONO.apk", "message", job_ids=job_ids)
    assert cand.kind == "web" and store.get_job(job_ids[0]).status == "failed"
    assert cand.verdict == "malicious"


def test_link_that_serves_an_apk_without_apk_extension_is_detected():
    url = "http://sbi-yono-update.top/download?id=7"
    served = FetchResult(url=url, final_url=url, status=200, ok=True, content_type=fetcher.APK_CONTENT_TYPE)
    followed: list[str] = []
    cand = pipeline.analyze_url(url, "message", do_fetch=False, fetch_result=served, on_apk_links=followed.extend)
    assert followed == [url] and "apk_download" in {s.name for s in cand.signals}


def test_apk_response_detection():
    assert fetcher.is_apk_response(fetcher.APK_CONTENT_TYPE, b"")
    assert fetcher.is_apk_response("application/octet-stream", b"PK\x03\x04")
    assert not fetcher.is_apk_response("text/html", b"PK\x03\x04")
