"""Tests for the evaluation harness, the /eval/metrics endpoint, and the campaign demo.

All offline/deterministic (no network, no Playwright, no downloads).

Documented floors (achieved on the committed labelled sample, 31 items):
  url_only    precision 1.000  recall 0.750  f1 0.857
  url+visual  precision 1.000  recall 0.875  f1 0.933
  full        precision 1.000  recall 1.000  f1 1.000
The full stage must keep precision AND recall each >= 0.70.
"""
import os

from fastapi.testclient import TestClient

from app.main import app
from eval import campaign_demo, dataset, evaluate

FULL_FLOOR = 0.70


def test_evaluate_returns_real_metrics():
    result = evaluate.evaluate()
    assert result["is_placeholder"] is False
    assert result["sample_size"] > 0
    stages = {s["stage"]: s for s in result["stages"]}
    assert set(stages) == {"url_only", "url+visual", "full"}
    for s in stages.values():
        assert 0.0 <= s["precision"] <= 1.0
        assert 0.0 <= s["recall"] <= 1.0
        assert 0.0 <= s["f1"] <= 1.0


def test_full_stage_meets_floor():
    result = evaluate.evaluate()
    full = next(s for s in result["stages"] if s["stage"] == "full")
    assert full["precision"] >= FULL_FLOOR, full
    assert full["recall"] >= FULL_FLOOR, full


def test_metrics_json_matches_live_evaluate(tmp_path):
    """The committed metrics.json must equal a fresh deterministic evaluate() run."""
    result = evaluate.evaluate()
    stages = {s["stage"]: (s["precision"], s["recall"], s["f1"]) for s in result["stages"]}
    import json
    with open(evaluate.METRICS_PATH, encoding="utf-8") as fh:
        on_disk = json.load(fh)
    assert on_disk["is_placeholder"] is False
    assert on_disk["sample_size"] == result["sample_size"]
    disk_stages = {s["stage"]: (s["precision"], s["recall"], s["f1"]) for s in on_disk["stages"]}
    assert disk_stages == stages


def test_eval_metrics_endpoint_real_when_present():
    assert os.path.exists(evaluate.METRICS_PATH)
    with TestClient(app) as client:
        body = client.get("/eval/metrics").json()
    assert body["is_placeholder"] is False
    assert body["sample_size"] > 0
    assert len(body["stages"]) == 3


def test_eval_metrics_endpoint_graceful_when_absent(monkeypatch):
    """Endpoint must fall back to the placeholder (not error) if the artifact is gone."""
    from app import api
    monkeypatch.setattr(api, "_METRICS_PATH", "/nonexistent/metrics.json")
    with TestClient(app) as client:
        resp = client.get("/eval/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_placeholder"] is True
    assert len(body["stages"]) == 3


def test_full_stage_scores_match_real_pipeline():
    """The full-stage eval score must equal pipeline.analyze_url's risk_score for every
    item, so reported metrics cannot drift from real pipeline behaviour."""
    from app.schemas import Entity
    from app.services import pipeline

    items = dataset.all_items()
    for item in items:
        fr = evaluate._build_fetch_result(item["url"], item.get("page"))
        eval_score = evaluate._score_for_stage(item, "full", fr)
        extra = [Entity(type=e["type"], value=e["value"]) for e in item.get("entities", [])]
        cand = pipeline.analyze_url(item["url"], item["source"], extra_entities=extra,
                                    do_fetch=False, fetch_result=fr)
        assert eval_score == cand.risk_score, (item["url"], eval_score, cand.risk_score)


def test_campaign_demo_discovers_campaigns():
    cands = campaign_demo.build_candidates()
    from app.services import clustering
    campaigns = clustering.build_campaigns(cands)
    assert len(campaigns) >= 1
    # Every discovered campaign is backed by shared infrastructure evidence.
    for camp in campaigns:
        assert camp.size >= 2
        assert camp.shared_entities


# --- real-world benchmark ----------------------------------------------------------

import csv  # noqa: E402

import pytest  # noqa: E402

from app.services import url_features  # noqa: E402


def test_benchmark_file_is_well_formed():
    from eval import evaluate as ev

    with open(ev.BENCHMARK_PATH, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["label"] for r in rows} == {"phishing", "benign"}
    assert {r["split"] for r in rows} == {"dev", "test"}
    hosts = [url_features.host_of(r["url"]) for r in rows]
    assert len(hosts) == len(set(hosts)), "one row per host"
    assert all(r["url"] == f"https://{h}/" for r, h in zip(rows, hosts, strict=True)), "host-level rows only"
    assert all(r["target"] for r in rows if r["label"] == "phishing")


def test_benchmark_split_is_deterministic():
    from eval.build_benchmark import split_for

    assert split_for("example.com") == split_for("example.com")
    assert {split_for(f"host{i}.test") for i in range(50)} == {"dev", "test"}


def test_benchmark_metrics_are_published():
    from eval import evaluate as ev

    result = ev.evaluate()
    by_split = {b["split"]: b for b in result["benchmarks"]}
    assert set(by_split) == {"test", "dev"}
    test = by_split["test"]
    assert test["positives"] >= 20 and test["negatives"] >= 1000
    assert test["tp"] + test["fn"] == test["positives"] and test["fp"] + test["tn"] == test["negatives"]
    # Regression floor for the held-out split; update deliberately when the benchmark is rebuilt.
    assert test["precision"] >= 0.8 and test["recall"] >= 0.7 and test["false_positive_rate"] <= 0.005


def test_wilson_interval_bounds():
    from eval.evaluate import wilson

    lo, hi = wilson(21, 27)
    assert 0 < lo < 21 / 27 < hi < 1
    assert wilson(0, 0) == (0.0, 0.0)


@pytest.mark.parametrize("host", [
    "lesbianstories.com", "famousbirthdays.com", "abhimanu.com", "ausbildung.de", "catholicicing.com",
    "coinsbit.io", "dgpay.eu", "yonomi.cloud", "nic.sbi", "sbiepay.sbi",
])
def test_short_keyword_collisions_are_not_brand_matches(host):
    score, _signals, brand = url_features.score_url(f"https://{host}/")
    assert brand is None or score < 0.7, host


@pytest.mark.parametrize("host", [
    "sbi-kyc.pages.dev", "hdfcmo-e9a29.web.app", "sbibank-kyc.in", "www.netbanking-hdfcbank.com",
    "internetbanking-paytmbank.com", "axisbankkyc.wuaze.com", "hdfcbank.com.dragonflydowser.com",
])
def test_known_phishing_hosts_are_detected(host):
    score, _signals, _brand = url_features.score_url(f"https://{host}/")
    assert score >= 0.7, host
