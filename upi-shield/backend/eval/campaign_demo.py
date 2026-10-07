"""Offline, deterministic campaign-clustering demo.

Ingests the labelled phishing items (``eval/dataset.phishing_items``) through the
real analysis pipeline + in-memory store, runs the union-find campaign clustering
over their shared infrastructure entities, then prints:

  * each discovered campaign (brands targeted, size, members)
  * the shared entities that linked the members (the infrastructure-graph evidence)
  * an auto-generated takedown report for one campaign

This demonstrates deliverables (3) infrastructure graph and (4) automated takedown
report, end-to-end, with NO network (canned FetchResults, do_fetch=False) and a
fixed candidate ordering so the output is deterministic.

Run: ``python -m eval.campaign_demo``  (from backend/, with the venv active).
"""
from __future__ import annotations

from datetime import UTC

from app.schemas import Candidate, Entity
from app.services import clustering, pipeline, takedown
from eval import dataset
from eval.evaluate import _build_fetch_result


def build_candidates() -> list[Candidate]:
    """Analyze every phishing item offline and return deterministic Candidate rows.

    Uses the real pipeline (do_fetch=False so no live fetch/enrichment runs) with the
    item's canned FetchResult and declared shared entities, then normalises the
    pipeline's random id/timestamp so the demo output is stable across runs.
    """
    cands: list[Candidate] = []
    for idx, item in enumerate(dataset.phishing_items()):
        fr = _build_fetch_result(item["url"], item.get("page"))
        extra = [Entity(type=e["type"], value=e["value"]) for e in item.get("entities", [])]
        cand = pipeline.analyze_url(item["url"], item["source"], extra_entities=extra,
                                    do_fetch=False, fetch_result=fr)
        # Deterministic id + ordering (replace the random uuid / wall-clock time).
        cand.id = f"eval{idx:02d}"
        cands.append(cand)
    # Stable, monotonically increasing first_seen so clustering ordering is fixed.
    from datetime import datetime, timedelta
    base = datetime(2024, 1, 1, tzinfo=UTC)
    for i, c in enumerate(cands):
        c.first_seen = base + timedelta(minutes=i)
    return cands


def main() -> None:
    cands = build_candidates()
    campaigns = clustering.build_campaigns(cands)
    by_id = {c.id: c for c in cands}

    print("\nUPI Shield campaign-clustering demo")
    print(f"Ingested {len(cands)} labelled phishing candidates "
          f"-> discovered {len(campaigns)} campaign(s).")
    print("=" * 72)

    for camp in campaigns:
        print(f"\n{camp.id}: {camp.name}")
        print(f"  size={camp.size}  brands={', '.join(camp.brands_targeted) or 'n/a'}")
        print("  shared entities (infrastructure graph edges):")
        for e in camp.shared_entities:
            print(f"    - {e.type}: {e.value}")
        print("  members:")
        for cid in camp.candidate_ids:
            m = by_id[cid]
            print(f"    - {m.url}  (risk {m.risk_score:.2f}, verdict {m.verdict})")

    if campaigns:
        target = campaigns[0]
        members = [by_id[i] for i in target.candidate_ids]
        report = takedown.generate(target, members, "cert_in")
        print("\n" + "=" * 72)
        print(f"Auto-generated takedown report for {target.id} (recipient: cert_in)")
        print("=" * 72)
        print(f"Subject: {report.subject}\n")
        print(report.body)


if __name__ == "__main__":
    main()
