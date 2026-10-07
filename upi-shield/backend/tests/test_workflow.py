"""Analyst workflow: review, audit trail, takedown plans and cases, exports, dashboard."""
import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import Entity, InfrastructureSummary
from app.services import casework
from app.store import store


def _first_campaign():
    camp = store.campaigns[0]
    return camp, [store.candidates[i] for i in camp.candidate_ids]


def test_false_positive_review_removes_candidate_from_campaign_and_is_audited():
    camp, members = _first_campaign()
    with TestClient(app) as client:
        target = members[0].id
        r = client.post(f"/candidates/{target}/review",
                        json={"status": "false_positive", "note": "official partner site", "analyst": "asha"})
        assert r.status_code == 200 and r.json()["review_status"] == "false_positive"
        assert store.candidates[target].campaign_id is None
        events = client.get("/audit", params={"target": target}).json()
        assert events[0]["action"] == "candidate.review" and events[0]["actor"] == "asha"
        assert events[0]["detail"] == {"from": "unreviewed", "to": "false_positive", "note": "official partner site"}
        assert client.post("/candidates/missing/review", json={"status": "confirmed"}).status_code == 404


def test_review_survives_reanalysis_of_the_same_url():
    from app.services import ingest

    _camp, members = _first_campaign()
    cid = members[0].id
    with TestClient(app) as client:
        client.post(f"/candidates/{cid}/review", json={"status": "confirmed"})
    again = ingest.analyze_and_store(members[0].url, "user_report")
    assert again.id == cid and again.review_status == "confirmed"


def test_takedown_plan_routes_to_verified_contacts():
    camp, members = _first_campaign()
    infra = InfrastructureSummary(ip="203.0.113.9", asn="AS64500", as_name="Example VPS",
                                  hosting_abuse_contacts=["abuse@vps.example"], registrar="Reg Inc",
                                  registrar_abuse_email="abuse@reg.example")
    members = [m.model_copy(update={"infrastructure": infra}) for m in members]
    plan = casework.takedown_plan(camp, members)
    by = {}
    for item in plan.items:
        by.setdefault(item.recipient, []).append(item)
    assert by["registrar"][0].contacts == ["abuse@reg.example"] and by["registrar"][0].channel == "email"
    assert by["hosting"][0].contacts == ["abuse@vps.example"]
    assert by["npci"][0].targets == ["rewards.help@okaxis"]
    assert by["cert_in"][0].contacts == ["incident@cert-in.org.in"]
    assert "cybercrime_portal" in by and "safe_browsing" in by


def test_plan_uses_platform_abuse_channel_and_admits_missing_contacts():
    camp, members = _first_campaign()
    hosted = members[0].model_copy(update={"domain": "phonepe-kyc.pages.dev", "url": "https://phonepe-kyc.pages.dev/"})
    plan = casework.takedown_plan(camp, [hosted, *members[1:]])
    hosting = next(i for i in plan.items if i.recipient == "hosting")
    assert hosting.contacts == ["https://abuse.cloudflare.com/"] and hosting.channel == "web_form"
    registrar = next(i for i in plan.items if i.recipient == "registrar")
    assert registrar.channel == "lookup_required" and "no RDAP abuse contact" in registrar.rationale
    assert "phonepe-kyc.pages.dev" not in registrar.targets  # platform subdomains go to the platform


def test_brand_contact_only_when_published():
    camp, members = _first_campaign()
    icici = camp.model_copy(update={"brands_targeted": ["icici", "phonepe"]})
    banks = {i.rationale.split()[1]: i for i in casework.takedown_plan(icici, members).items
             if i.recipient == "bank"}
    assert banks["ICICI"].contacts == ["antiphishing@icicibank.com"]
    assert banks["PhonePe"].contacts == [] and banks["PhonePe"].channel == "lookup_required"


def test_takedown_case_lifecycle_with_recheck(monkeypatch):
    camp, _members = _first_campaign()
    with TestClient(app) as client:
        r = client.post("/takedowns", json={"campaign_id": camp.id, "recipient": "safe_browsing", "analyst": "ravi"})
        assert r.status_code == 201
        case = r.json()
        assert case["status"] == "drafted" and case["contact"].startswith("https://safebrowsing")
        assert "Reported URLs" in case["report"]["body"]
        sent = client.patch(f"/takedowns/{case['id']}", json={"status": "sent", "note": "submitted form"}).json()
        assert sent["sent_at"] and "submitted form" in sent["notes"][0]

        monkeypatch.setattr(casework, "probe_url", lambda url: (False, "connection failed"))
        checked = client.post(f"/takedowns/{case['id']}/recheck").json()
        assert checked["status"] == "resolved" and all(not c["live"] for c in checked["checks"])
        assert [c["id"] for c in client.get("/takedowns", params={"status": "resolved"}).json()] == [case["id"]]
        actions = [e["action"] for e in client.get("/audit", params={"target": case["id"]}).json()]
        assert actions == ["takedown.recheck", "takedown.status", "takedown.create"]
        assert client.get("/takedowns/nope").status_code == 404


def test_recheck_keeps_case_open_while_any_target_is_live():
    camp, members = _first_campaign()
    case = casework.apply_status(casework.create_case(camp, members, "safe_browsing"), "sent", None)
    case = casework.recheck(case, prober=lambda url: ("ph0nepe" in url, "HTTP 200" if "ph0nepe" in url else "gone"))
    assert case.status == "sent" and any(c.live for c in case.checks)


def test_exports():
    camp, _ = _first_campaign()
    with TestClient(app) as client:
        md = client.get(f"/campaigns/{camp.id}/export", params={"format": "markdown"})
        assert md.status_code == 200 and md.text.startswith(f"# {camp.name}") and "## Takedown plan" in md.text
        stix = client.get(f"/campaigns/{camp.id}/export", params={"format": "stix"}).json()
        types = {o["type"] for o in stix["objects"]}
        assert stix["type"] == "bundle" and {"campaign", "indicator", "relationship"} <= types
        assert all(o["spec_version"] == "2.1" for o in stix["objects"])
        assert any("x-upi-handle" in o.get("pattern", "") for o in stix["objects"])
        data = client.get(f"/campaigns/{camp.id}/export", params={"format": "json"}).json()
        assert len(data["members"]) == camp.size and data["plan"]["items"]
        z = client.get(f"/campaigns/{camp.id}/export", params={"format": "zip"})
        names = set(zipfile.ZipFile(io.BytesIO(z.content)).namelist())
        assert {"README.md", "campaign.json", "stix-bundle.json", "reports/cert_in.txt"} <= names
        assert json.loads(zipfile.ZipFile(io.BytesIO(z.content)).read("campaign.json"))["campaign"]["id"] == camp.id
        assert client.get(f"/campaigns/{camp.id}/export", params={"format": "pdf"}).status_code == 422


def test_stix_patterns_escape_quotes():
    camp, members = _first_campaign()
    odd = members[0].model_copy(update={"url": "http://x.top/it's"})
    patterns = [o["pattern"] for o in casework.stix_bundle(camp, [odd])["objects"] if o["type"] == "indicator"]
    assert "[url:value = 'http://x.top/it\\'s']" in patterns


def test_dashboard_summary():
    with TestClient(app) as client:
        body = client.get("/dashboard/summary", params={"days": 7}).json()
        assert body["totals"]["flagged"] == 6 and body["totals"]["campaigns"] == 2
        assert len(body["detections_per_day"]) == 7 and sum(d["count"] for d in body["detections_per_day"]) == 6
        assert body["review_queue"][0]["risk_score"] >= body["review_queue"][-1]["risk_score"]
        assert "brand_in_unofficial_domain" in body["top_signals"]


def test_new_recipients_generate_reports():
    camp, members = _first_campaign()
    from app.services import takedown

    members = [members[0].model_copy(update={"entities": [*members[0].entities,
                                                          Entity(type="phone", value="9876543210")]}), *members[1:]]
    phone = Entity(type="phone", value="9876543210")
    camp = camp.model_copy(update={"shared_entities": [*camp.shared_entities, phone]})
    for recipient in ("cybercrime_portal", "telecom"):
        body = takedown.generate(camp, members, recipient).body
        assert "Reported URLs" in body
    assert "9876543210" in takedown.generate(camp, members, "telecom").body
