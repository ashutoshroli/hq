"""Offline, deterministic evaluation of the UPI Shield detection pipeline.

Runs the REAL detection engines over the labelled sample (``eval/dataset.py``) in
three cumulative stage configurations and computes precision / recall / F1 against
the gold labels:

  * url_only    : url_features.score_url + verdict
  * url+visual  : url_only  + visual.compare_visual on the canned page fixture
  * full        : url+visual + behaviour.analyze_behaviour + enrichment.enrich
                  (enrichment uses STUB resolvers derived from the fixture, so the
                   stage is fully offline and deterministic)

A stage predicts "malicious" when its cumulative score crosses the product's
malicious cutoff (``verdict_for`` >= 0.70, see dataset.MALICIOUS_SCORE_THRESHOLD).

Writes the results to ``eval/metrics.json`` (schema-compatible with
``app.schemas.EvalMetrics``, ``is_placeholder=false``) and prints a summary table.

Run: ``python -m eval.evaluate``  (from backend/, with the venv active).
"""
from __future__ import annotations

import csv
import json
import os

from app.schemas import BenchmarkMetrics, Entity, EvalMetrics, StageMetrics
from app.services import enrichment, pipeline, url_features, visual
from app.services.fetcher import FetchResult
from eval import dataset

METRICS_PATH = os.path.join(os.path.dirname(__file__), "metrics.json")
BENCHMARK_PATH = os.path.join(os.path.dirname(__file__), "data", "benchmark.csv")
REPORT_PATH = os.path.join(os.path.dirname(__file__), "benchmark_report.md")
BENCHMARK_DESCRIPTION = (
    "Real-world lookalike hosts: active phishing reported by Phishing.Database and OpenPhish that impersonates "
    "a monitored brand (positives) versus Tranco top-1M domains containing brand keywords plus a random "
    "Tranco top-100k sample (negatives). Host-level, URL features only, offline."
)

STAGES = ("url_only", "url+visual", "full")


def _build_fetch_result(url: str, page: dict | None) -> FetchResult | None:
    """Turn a canned page fixture into an ``ok=True`` FetchResult, or None if absent."""
    if not page:
        return None
    final_url = page.get("final_url") or url
    chain = page.get("redirect_chain") or [url]
    return FetchResult(
        url=url,
        final_url=final_url,
        redirect_chain=list(chain),
        status=page.get("status", 200),
        html=page.get("html", ""),
        forms=list(page.get("forms", [])),
        external_script_srcs=list(page.get("external_script_srcs", [])),
        favicon_href=page.get("favicon_href"),
        favicon_hash=page.get("favicon_hash"),
        ok=True,
    )


def _stub_resolvers(item: dict) -> dict:
    """Build OFFLINE enrichment resolvers from an item's declared entities.

    Returns the ip/cert/registrar/asn that the item 'has' (from its entities list)
    without any network. Items without those entities resolve to None, matching a
    page the crawler could not enrich.
    """
    ents = {(e["type"], e["value"]) for e in item.get("entities", [])}
    ip = next((v for (t, v) in ents if t == "ip"), None)
    cert = next((v for (t, v) in ents if t == "cert_fingerprint"), None)
    registrar = next((v for (t, v) in ents if t == "registrar"), None)
    asn = next((v for (t, v) in ents if t == "asn"), None)
    return {
        "ip": (lambda host, _ip=ip: _ip),
        "asn": (lambda _ipaddr, _asn=asn: _asn),
        "cert": (lambda host, _c=cert: _c),
        "registrar": (lambda host, _r=registrar: _r),
    }


def _full_score_via_pipeline(item: dict, fr: FetchResult | None) -> float:
    """Full-stage score driven through the REAL pipeline (no parallel re-implementation).

    Uses the same offline injection path as campaign_demo: do_fetch=False so no live
    fetch/enrichment network runs, with the canned FetchResult feeding visual +
    behaviour. The pipeline computes risk_score the way production does, so the
    reported metrics cannot drift from pipeline behaviour.
    """
    extra = [Entity(type=e["type"], value=e["value"]) for e in item.get("entities", [])]
    cand = pipeline.analyze_url(item["url"], item["source"], extra_entities=extra,
                                do_fetch=False, fetch_result=fr)
    # Exercise enrichment with stub resolvers to prove the stage is offline-safe
    # end-to-end (entities don't change the score, but this keeps the full offline
    # pipeline covered and matches the stage's documented intent).
    enrichment.enrich(url_features.host_of(item["url"]), fetch_result=fr,
                      resolvers=_stub_resolvers(item))
    return cand.risk_score


def _score_for_stage(item: dict, stage: str, fr: FetchResult | None) -> float:
    """Compute the cumulative risk score for one item under one stage config.

    The ``full`` stage is driven through ``pipeline.analyze_url`` so it cannot diverge
    from real pipeline behaviour. The ``url_only`` / ``url+visual`` stages are partial
    subsets of the pipeline that the public signature does not expose directly, so they
    accumulate the same engine weights the pipeline uses (sum of signal weights, clamped
    to 1.0). ``test_eval`` asserts the inline accumulation agrees with the pipeline.
    """
    if stage == "full":
        return _full_score_via_pipeline(item, fr)

    url = item["url"]
    score0, signals, brand = url_features.score_url(url)
    weights = [s.weight for s in signals]

    if stage == "url+visual" and fr is not None:
        sim, visual_signals = visual.compare_visual(fr, brand)
        weights += [s.weight for s in visual_signals]

    return min(1.0, sum(weights))


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4)


def load_benchmark(path: str = BENCHMARK_PATH) -> list[dict]:
    """In-scope benchmark rows (phishing hosts targeting other organisations excluded)."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return [r for r in csv.DictReader(fh) if r["target"] != "other"]


def evaluate_benchmark(rows: list[dict], split: str, threshold: float) -> tuple[BenchmarkMetrics, dict]:
    tp = fp = fn = tn = 0
    errors: dict[str, list] = {"false_positives": [], "false_negatives": []}
    for row in (r for r in rows if r["split"] == split):
        score, signals, _brand = url_features.score_url(row["url"])
        pred, gold = score >= threshold, row["label"] == "phishing"
        if pred and gold:
            tp += 1
        elif pred:
            fp += 1
            errors["false_positives"].append((row["url"], score, [s.name for s in signals]))
        elif gold:
            fn += 1
            errors["false_negatives"].append((row["url"], score, [s.name for s in signals], row["target"]))
        else:
            tn += 1
    precision, recall, f1 = _prf(tp, fp, fn)
    collected = next((r["collected"] for r in rows), None)
    return BenchmarkMetrics(
        name="real_world_lookalike_hosts", description=BENCHMARK_DESCRIPTION, split=split, stage="url_only",
        threshold=threshold, sample_size=tp + fp + fn + tn, positives=tp + fn, negatives=fp + tn,
        precision=precision, recall=recall, f1=f1, tp=tp, fp=fp, fn=fn, tn=tn,
        false_positive_rate=round(fp / (fp + tn), 4) if (fp + tn) else 0.0, collected=collected,
    ), errors


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if not total:
        return 0.0, 0.0
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / (1 + z * z / total)
    return max(0.0, centre - half), min(1.0, centre + half)


def write_benchmark_report(results: list[tuple[BenchmarkMetrics, dict]]) -> None:
    lines = ["# Real-world benchmark report", "",
             "Generated by `python -m eval.evaluate`. Do not edit by hand.", "", BENCHMARK_DESCRIPTION, "",
             "| split | n | positives | negatives | precision | recall | F1 | FPR |",
             "|---|---|---|---|---|---|---|---|"]
    for m, _ in results:
        lines.append(f"| {m.split} | {m.sample_size} | {m.positives} | {m.negatives} | {m.precision:.3f} | "
                     f"{m.recall:.3f} | {m.f1:.3f} | {m.false_positive_rate:.4f} |")
    lines += ["", "95% Wilson confidence intervals (the positive class is small, so treat point estimates "
              "with caution):", ""]
    for m, _ in results:
        p_lo, p_hi = wilson(m.tp, m.tp + m.fp)
        r_lo, r_hi = wilson(m.tp, m.tp + m.fn)
        lines.append(f"- {m.split}: precision {p_lo:.2f}-{p_hi:.2f}, recall {r_lo:.2f}-{r_hi:.2f}")
    lines += ["", "Some false positives may be genuinely malicious lookalikes that no public feed has reported "
              "yet (for example newly registered brand-keyword domains); they are still counted as errors."]
    for m, errors in results:
        lines += ["", f"## {m.split} errors", "", f"False positives ({m.fp}):", ""]
        lines += [f"- `{u}` score {s:.2f} ({', '.join(n)})" for u, s, n in errors["false_positives"]] or ["- none"]
        lines += ["", f"False negatives ({m.fn}):", ""]
        lines += [f"- `{u}` target {t}, score {s:.2f} ({', '.join(n) or 'no signals'})"
                  for u, s, n, t in errors["false_negatives"]] or ["- none"]
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def evaluate() -> dict:
    """Run all stages over the labelled sample; return an EvalMetrics-compatible dict."""
    items = dataset.all_items()
    threshold = dataset.MALICIOUS_SCORE_THRESHOLD

    # Pre-build FetchResults once (deterministic, no network).
    fetch_results = [_build_fetch_result(it["url"], it.get("page")) for it in items]

    stage_metrics: list[dict] = []
    for stage in STAGES:
        tp = fp = fn = tn = 0
        for item, fr in zip(items, fetch_results, strict=True):
            gold_malicious = item["label"] == "malicious"
            score = _score_for_stage(item, stage, fr)
            pred_malicious = score >= threshold
            if pred_malicious and gold_malicious:
                tp += 1
            elif pred_malicious and not gold_malicious:
                fp += 1
            elif not pred_malicious and gold_malicious:
                fn += 1
            else:
                tn += 1
        precision, recall, f1 = _prf(tp, fp, fn)
        stage_metrics.append({"stage": stage, "precision": precision,
                              "recall": recall, "f1": f1,
                              "tp": tp, "fp": fp, "fn": fn, "tn": tn})

    metrics = EvalMetrics(
        sample_size=len(items),
        is_placeholder=False,
        stages=[StageMetrics(stage=m["stage"], precision=m["precision"],
                             recall=m["recall"], f1=m["f1"]) for m in stage_metrics],
    )
    rows = load_benchmark()
    if rows:
        results = [evaluate_benchmark(rows, split, threshold) for split in ("test", "dev")]
        metrics.benchmarks = [m for m, _ in results]
        write_benchmark_report(results)
    # Return the schema dict plus the confusion-matrix detail for the printed table.
    out = metrics.model_dump()
    out["_detail"] = stage_metrics
    return out


def write_metrics(result: dict) -> None:
    """Persist the EvalMetrics-shaped payload (without _detail) to eval/metrics.json."""
    payload = {k: v for k, v in result.items() if not k.startswith("_")}
    with open(METRICS_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _print_table(result: dict) -> None:
    detail = {d["stage"]: d for d in result.get("_detail", [])}
    print(f"\nUPI Shield evaluation  (sample_size={result['sample_size']}, "
          f"threshold>={dataset.MALICIOUS_SCORE_THRESHOLD})")
    print("-" * 72)
    print(f"{'stage':<12} {'precision':>10} {'recall':>9} {'f1':>8}   "
          f"{'tp':>3} {'fp':>3} {'fn':>3} {'tn':>3}")
    print("-" * 72)
    for stage in STAGES:
        s = next(st for st in result["stages"] if st["stage"] == stage)
        d = detail.get(stage, {})
        print(f"{stage:<12} {s['precision']:>10.3f} {s['recall']:>9.3f} {s['f1']:>8.3f}   "
              f"{d.get('tp', 0):>3} {d.get('fp', 0):>3} {d.get('fn', 0):>3} {d.get('tn', 0):>3}")
    print("-" * 72)
    for b in result.get("benchmarks", []):
        print(f"real-world benchmark [{b['split']}] n={b['sample_size']} (+{b['positives']}/-{b['negatives']}): "
              f"precision={b['precision']:.3f} recall={b['recall']:.3f} f1={b['f1']:.3f} "
              f"fpr={b['false_positive_rate']:.4f}")
    print(f"wrote {METRICS_PATH}")


def main() -> None:
    result = evaluate()
    write_metrics(result)
    _print_table(result)


if __name__ == "__main__":
    main()
