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
