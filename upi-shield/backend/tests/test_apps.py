"""Fake Android app detection: parsing, impersonation, capabilities, linking, API."""
import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app import jobs as jobs_module
from app.main import app
from app.services import apps, behaviour, clustering, fetcher, ingest, pipeline, takedown
from app.services.fetcher import FetchResult
from app.store import store
from tests import apk_factory

FIXTURES = Path(__file__).parent / "fixtures"
GENUINE_ICON = (FIXTURES / "phonepe_app_icon.png").read_bytes()
TROJAN_PERMS = ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"]
# Synthetic, token-shaped value assembled at runtime so secret scanners do not treat
# the fixture as a leaked credential. It is not a real Telegram bot token.
BOT = "7012345678" + ":" + "AA" + "x" * 33


def _fake_phonepe(**overrides) -> bytes:
    params = {"package": "com.rewards.kyc.update", "label": "PhonePe KYC Update", "permissions": TROJAN_PERMS,
              "strings": ["https://phonepe-kyc-verify.xyz/api/upload", "https://www.googleapis.com/x",
                          "pay to rewards.help@okaxis", BOT, "https://t.me/kyc_support_desk"],
              "icon": GENUINE_ICON}
    params.update(overrides)
    return apk_factory.build_apk(**params)


def test_dex_string_table_round_trip():
    assert apps.dex_strings(apk_factory.dex(["alpha", "https://x.top/a", "ünï"])) == ["alpha", "https://x.top/a", "ünï"]
    assert apps.dex_strings(b"not a dex") == []


def test_parse_apk_reads_manifest_icon_and_strings():
    info = apps.parse_apk(_fake_phonepe())
    assert info.package == "com.rewards.kyc.update" and info.label == "PhonePe KYC Update"
    assert "android.permission.RECEIVE_SMS" in info.permissions and info.has_launcher
    assert info.icon == GENUINE_ICON and BOT in info.strings


@pytest.mark.parametrize("payload", [b"", b"plain text", apk_factory.dex(["x"])])
def test_parse_apk_rejects_invalid_input(payload):
    with pytest.raises(apps.ApkError):
        apps.parse_apk(payload)


def test_indicator_extraction_ignores_platform_hosts_and_constants():
    found = apps.extract_indicators(["https://phonepe-kyc-verify.xyz/api", "https://www.googleapis.com/x",
                                     "https://www.phonepe.com/help", BOT, "8139515620",
                                     "Call our helpline 9876543210", "https://t.me/kyc_support_desk"])
    assert found["hosts"] == ["phonepe-kyc-verify.xyz"]
    assert found["telegram_bots"] == ["7012345678"] and found["telegram"] == ["kyc_support_desk"]
    assert found["phones"] == ["8139515620", "9876543210"]


def test_fake_brand_app_is_malicious_with_evidence():
    cand = apps.analyze_apk(_fake_phonepe(), origin_url="http://phonepe-kyc-verify.xyz/PhonePe.apk")
    names = {s.name for s in cand.signals}
    assert cand.kind == "app" and cand.verdict == "malicious" and cand.brand_matched == "phonepe"
    assert {"brand_impersonating_app", "app_icon_impersonation", "sms_interception",
            "banking_trojan_profile", "telegram_bot_exfiltration", "sideloaded_distribution"} <= names
    values = {(e.type, e.value) for e in cand.entities}
    assert {("domain", "phonepe-kyc-verify.xyz"), ("upi_id", "rewards.help@okaxis"),
            ("telegram", "bot:7012345678")} <= values
    assert cand.app.package == "com.rewards.kyc.update"


def test_icon_alone_attributes_an_unbranded_app():
    resized = io.BytesIO()
    Image.open(io.BytesIO(GENUINE_ICON)).convert("RGBA").resize((96, 96)).save(resized, "PNG")
    cand = apps.analyze_apk(_fake_phonepe(label="Rewards", package="com.gift.rewards", icon=resized.getvalue()))
    assert cand.brand_matched == "phonepe"
    assert "app_icon_impersonation" in {s.name for s in cand.signals}


def test_typosquatted_label_is_detected():
    cand = apps.analyze_apk(_fake_phonepe(label="Phonpe Rewards", package="com.gift.app", icon=None))
    assert cand.brand_matched == "phonepe"
    assert "typosquats" in next(s.detail for s in cand.signals if s.name == "brand_impersonating_app")


def test_capabilities_without_impersonation_stay_below_malicious():
    cand = apps.analyze_apk(apk_factory.build_apk("org.example.smsbackup", "SMS Backup", TROJAN_PERMS))
    assert cand.brand_matched is None and cand.verdict != "malicious"


def test_benign_app_is_benign():
    cand = apps.analyze_apk(apk_factory.build_apk("org.example.notes", "Notes", ["android.permission.INTERNET"]))
    assert cand.verdict == "benign" and cand.risk_score == 0.1  # unsigned test build


def test_official_package_with_foreign_certificate_is_repackaged(monkeypatch):
    refs = {"phonepe": {"apps": [{"package": "com.phonepe.app", "cert_sha256": ["a" * 64]}]}}
    monkeypatch.setattr(apps.visual, "brand_references", lambda: refs)
    cand = apps.analyze_apk(_fake_phonepe(package="com.phonepe.app", label="PhonePe"))
    assert "repackaged_official_app" in {s.name for s in cand.signals}
    assert cand.verdict == "malicious"


def test_official_package_without_known_certificate_is_not_condemned():
    cand = apps.analyze_apk(apk_factory.build_apk("com.phonepe.app", "PhonePe", ["android.permission.INTERNET"]))
    assert "official_package_name" in {s.name for s in cand.signals} and cand.verdict != "malicious"


def test_app_clusters_with_the_phishing_page_it_calls():
    page = pipeline.analyze_url("http://phonepe-kyc-verify.xyz/login", "message")
    app_cand = apps.analyze_apk(_fake_phonepe())
    camps = clustering.build_campaigns([page, app_cand])
    assert len(camps) == 1 and set(camps[0].candidate_ids) == {page.id, app_cand.id}
    assert ("domain", "phonepe-kyc-verify.xyz") in {(e.type, e.value) for e in camps[0].shared_entities}


def test_shared_public_infrastructure_does_not_link():
    a = apps.analyze_apk(_fake_phonepe(strings=["https://bit.ly/x1"]))
    b = apps.analyze_apk(_fake_phonepe(package="com.other.kyc", strings=["https://bit.ly/x2"], icon=None))
    assert clustering.build_campaigns([a, b]) == []


def test_page_offering_apk_is_flagged_and_followed(monkeypatch):
    url = "http://phonepe-kyc-verify.xyz/"
    html = "<title>PhonePe</title><a href='/download/PhonePe-KYC.apk'>Install the KYC app</a>"
    page = FetchResult(url=url, final_url=url, html=html, ok=True)
    assert behaviour.apk_links(page) == ["http://phonepe-kyc-verify.xyz/download/PhonePe-KYC.apk"]
    followed = []
    cand = pipeline.analyze_url(url, "message", do_fetch=False, fetch_result=page, on_apk_links=followed.extend)
    assert "apk_download_offered" in {s.name for s in cand.signals}
    assert followed == ["http://phonepe-kyc-verify.xyz/download/PhonePe-KYC.apk"]


def test_app_url_job_downloads_and_stores(monkeypatch):
    monkeypatch.setattr(fetcher, "download_apk", lambda url: _fake_phonepe())
    job = jobs_module.jobs.submit("ingest_app_url", {}, ingest.app_url_job("http://x.top/a.apk", "message"))
    cand = store.candidates[job.candidate_ids[0]]
    assert job.status == "done" and cand.app.origin_url == "http://x.top/a.apk"


def test_upload_endpoint_and_kind_filter():
    with TestClient(app) as client:
        r = client.post("/ingest/app", files={"file": ("fake.apk", _fake_phonepe(), "application/octet-stream")})
        assert r.status_code == 200
        cid = r.json()["candidate_ids"][0]
        again = client.post("/ingest/app", files={"file": ("fake.apk", _fake_phonepe(), "application/octet-stream")})
        assert again.json()["candidate_ids"] == [cid]  # same file -> same candidate
        assert store.candidates[cid].sightings == 2
        assert [c["id"] for c in client.get("/candidates?kind=app").json()] == [cid]
        bad = client.post("/ingest/app", files={"file": ("x.apk", b"nope", "application/octet-stream")})
        assert bad.status_code == 422


def test_app_store_takedown_report():
    page = store.add(pipeline.analyze_url("http://phonepe-kyc-verify.xyz/login", "message"))
    app_cand = store.add(apps.analyze_apk(_fake_phonepe(), origin_url="http://phonepe-kyc-verify.xyz/a.apk"))
    camp = next(c for c in store.campaigns if app_cand.id in c.candidate_ids)
    members = [store.candidates[i] for i in camp.candidate_ids]
    body = takedown.generate(camp, members, "app_store").body
    assert "com.rewards.kyc.update" in body and app_cand.app.sha256 in body
    assert "distributed from: http://phonepe-kyc-verify.xyz/a.apk" in body
    registrar = takedown.generate(camp, members, "registrar").body
    assert "domain: com.rewards.kyc.update" not in registrar and page.domain in registrar
