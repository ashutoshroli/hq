from fastapi.testclient import TestClient

from app.main import app
from app.services import clustering, extractor, url_features


def test_url_scoring():
    score, signals, brand = url_features.score_url("http://ph0nepe-kyc-verify.xyz/login")
    assert brand == "phonepe" and score >= 0.7
    assert url_features.score_url("https://www.phonepe.com")[0] < 0.4


def test_extractor():
    out = extractor.extract("Claim cashback http://paytm-claim.click pay to rewards@okaxis call 9876543210")
    assert out["urls"] and out["upi_ids"] == ["rewards@okaxis"] and out["phones"] == ["9876543210"]


def test_endpoints():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        camps = client.get("/campaigns").json()
        assert len(camps) == 2
        rep = client.post("/reports/takedown", json={"campaign_id": camps[0]["id"], "recipient": "registrar"})
        assert rep.status_code == 200 and "Reported URLs" in rep.json()["body"]
        r = client.post("/ingest/message", json={"text": "verify now http://sbi-kyc-update.top pay mule@okaxis"})
        assert r.json()["candidate_ids"]
