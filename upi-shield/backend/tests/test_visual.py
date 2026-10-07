"""Offline tests for the visual/structural similarity engine (no network, no real images)."""
from app.services import visual
from app.services.fetcher import FetchResult

CLONE_HTML = """
<html><head><title>PhonePe | Secure UPI Payments</title>
<link rel="icon" href="/favicon.ico"></head>
<body>
<h1>PhonePe UPI</h1>
<p>Login to your PhonePe wallet to make a secure payment and transfer money via UPI.</p>
<form><input name="upi_pin" type="password"></form>
</body></html>
"""

UNRELATED_HTML = """
<html><head><title>Best Recipes 2024</title></head>
<body><h1>Chocolate Cake</h1><p>Mix flour, sugar, cocoa and bake for forty minutes.</p></body></html>
"""


def _result(html, **kw):
    return FetchResult(url="http://example.test", final_url="http://example.test",
                       html=html, ok=True, **kw)


def test_clone_scores_high():
    sim, signals = visual.compare_visual(_result(CLONE_HTML), "phonepe")
    assert sim >= 0.5
    assert any(s.name in ("brand_title_match", "visual_structural_similarity") for s in signals)


def test_unrelated_scores_low():
    sim, _ = visual.compare_visual(_result(UNRELATED_HTML), "phonepe")
    assert sim < 0.3


def test_empty_fetch_result_safe():
    assert visual.compare_visual(_result(""), "phonepe") == (0.0, [])
    assert visual.compare_visual(None, "phonepe") == (0.0, [])


def test_no_brand_returns_zero():
    assert visual.compare_visual(_result(CLONE_HTML), None) == (0.0, [])


def test_favicon_hash_match_is_strong(monkeypatch):
    # Register a known favicon hash for a brand, then a clone that reuses it.
    monkeypatch.setitem(visual.BRAND_INDEX["paytm"], "favicon_hashes", ["deadbeefcafe0001"])
    res = _result("<title>Paytm</title>", favicon_hash="deadbeefcafe0001")
    sim, signals = visual.compare_visual(res, "paytm")
    assert sim == 1.0
    assert any(s.name == "favicon_match" for s in signals)


def test_seeded_brand_favicon_hash_fires_without_injection():
    """A seeded genuine-brand favicon hash must trip favicon_match, so the reuse path
    is reachable from a real fetch (fetcher now computes favicon_hash)."""
    seeded = visual.BRAND_INDEX["phonepe"]["favicon_hashes"]
    assert seeded, "at least one genuine brand favicon hash must be catalogued"
    res = _result("<title>PhonePe</title>", favicon_hash=seeded[0])
    sim, signals = visual.compare_visual(res, "phonepe")
    assert sim == 1.0
    assert any(s.name == "favicon_match" for s in signals)


def test_hamming_similarity_bounds():
    assert visual.hamming_similarity("ffff", "ffff") == 1.0
    assert visual.hamming_similarity("0000", "ffff") == 0.0
    assert visual.hamming_similarity("", "ffff") == 0.0
    assert 0.0 < visual.hamming_similarity("ff00", "ff0f") < 1.0


# --- Screenshot / favicon matching against the committed brand reference library ----

import io  # noqa: E402
from pathlib import Path  # noqa: E402

from PIL import Image, ImageDraw  # noqa: E402

from app.services import imaging, pipeline  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _tampered_clone() -> bytes:
    """A clone kit's copy: re-encoded, slightly cropped, with an injected banner."""
    img = Image.open(io.BytesIO(_bytes("phonepe_home.jpg"))).convert("RGB")
    img = img.crop((10, 6, 630, 394)).resize((1280, 800))
    ImageDraw.Draw(img).rectangle((0, 740, 1280, 800), fill=(200, 30, 30))
    out = io.BytesIO()
    img.save(out, "JPEG", quality=55)
    return out.getvalue()


def _shot_result(url: str, shot: bytes, html: str = "<title>Login</title>", icon: bytes | None = None):
    return FetchResult(url=url, final_url=url, html=html, ok=True, screenshot=shot, favicon_bytes=icon)


def test_reference_library_covers_every_brand():
    from app import brands

    refs = visual.brand_references()
    assert set(brands.BRANDS) <= set(refs)
    assert all(refs[k]["screenshots"] for k in brands.BRANDS)


def test_perceptual_hash_survives_reencoding_and_crop():
    original = imaging.Fingerprint.of(_bytes("phonepe_home.jpg"))
    clone = imaging.Fingerprint.of(_tampered_clone())
    other = imaging.Fingerprint.of(_bytes("unrelated_wikipedia.jpg"))
    assert imaging.layout_similarity(original, clone) >= 0.85
    assert imaging.layout_similarity(original, other) < 0.7


def test_imaging_handles_undecodable_input():
    assert imaging.Fingerprint.of(b"not an image") is None
    assert imaging.phash(b"") is None
    assert imaging.hash_similarity(None, "ff") == 0.0
    assert imaging.palette_similarity(None, [1.0]) == 0.0


def test_screenshot_of_clone_matches_genuine_brand():
    sim, signals = visual.compare_visual(_shot_result("http://phonepe-kyc.xyz", _tampered_clone()), "phonepe")
    assert sim >= visual.SCREENSHOT_STRONG
    assert any(s.name == "visual_screenshot_match" for s in signals)


def test_identify_brand_on_unbranded_domain():
    brand, sim, signals = visual.identify_brand(_shot_result("http://secure-wallet-help.top", _tampered_clone()))
    assert brand == "phonepe" and sim >= visual.SCREENSHOT_STRONG
    assert signals[0].name == "visual_brand_impersonation"


def test_identify_brand_rejects_unrelated_page():
    brand, _sim, signals = visual.identify_brand(_shot_result("http://x.test", _bytes("unrelated_wikipedia.jpg")))
    assert brand is None and signals == []


def test_favicon_perceptual_match_survives_resizing():
    icon = Image.open(io.BytesIO(_bytes("phonepe_favicon.ico"))).convert("RGBA").resize((64, 64))
    out = io.BytesIO()
    icon.save(out, "PNG")
    _sim, signals = visual.compare_visual(_shot_result("http://p.test", b"", icon=out.getvalue()), "phonepe")
    assert any(s.name in ("favicon_match", "favicon_visual_match") for s in signals)


def test_pipeline_attributes_unbranded_clone_by_appearance():
    url = "http://secure-wallet-help.top/verify"
    cand = pipeline.analyze_url(url, "user_report", do_fetch=False, fetch_result=_shot_result(url, _tampered_clone()))
    assert cand.brand_matched == "phonepe"
    assert cand.verdict == "malicious"
    assert {"visual_brand_impersonation", "visual_screenshot_match"} <= {s.name for s in cand.signals}


def test_pipeline_does_not_flag_genuine_brand_site():
    url = "https://www.phonepe.com/"
    cand = pipeline.analyze_url(url, "user_report", do_fetch=False,
                                fetch_result=_shot_result(url, _bytes("phonepe_home.jpg")))
    assert cand.brand_matched is None and cand.verdict == "benign"


def test_evidence_is_stored_and_served(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import fetcher

    monkeypatch.setenv("UPI_SHIELD_EVIDENCE_DIR", str(tmp_path))
    path = fetcher.save_evidence(_bytes("phonepe_home.jpg"), "jpg")
    with TestClient(app) as client:
        resp = client.get(path)
        assert resp.status_code == 200 and resp.content == _bytes("phonepe_home.jpg")
        assert client.get("/evidence/..%2F..%2Fetc%2Fpasswd").status_code == 404
