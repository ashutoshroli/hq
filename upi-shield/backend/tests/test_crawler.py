"""Offline tests for the CT-log crawler. No network: fetch_fn is always stubbed."""
import json

from app.services import crawler

# crt.sh-style response: a mix of lookalike clones and the official domain.
CANNED_CRTSH = json.dumps([
    {"name_value": "phonepe-kyc-verify.xyz\n*.phonepe-kyc-verify.xyz"},
    {"common_name": "secure-phonepe-login.top"},
    {"name_value": "www.phonepe.com"},          # official -> must be ignored
    {"name_value": "unrelated-example.com"},     # no brand -> ignored
])


def test_discover_filters_to_lookalikes():
    def stub_fetch(url, params):
        assert "phonepe" in params["q"]
        return CANNED_CRTSH

    hosts = crawler.discover_from_ct(["phonepe"], fetch_fn=stub_fetch)
    assert "phonepe-kyc-verify.xyz" in hosts
    assert "secure-phonepe-login.top" in hosts
    # Official domain and unrelated host are not returned.
    assert "www.phonepe.com" not in hosts
    assert "phonepe.com" not in hosts
    assert "unrelated-example.com" not in hosts


def test_discover_dedupes_hostnames():
    hosts = crawler.discover_from_ct(["phonepe"], fetch_fn=lambda u, p: CANNED_CRTSH)
    assert len(hosts) == len(set(hosts))


def test_discover_returns_empty_on_network_error():
    def boom(url, params):
        raise RuntimeError("simulated network failure")

    assert crawler.discover_from_ct(["phonepe"], fetch_fn=boom) == []


def test_discover_returns_empty_on_bad_json():
    assert crawler.discover_from_ct(["phonepe"], fetch_fn=lambda u, p: "not json") == []


def test_discover_ignores_blank_terms():
    assert crawler.discover_from_ct(["", "   "], fetch_fn=lambda u, p: CANNED_CRTSH) == []
