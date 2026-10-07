"""Live end-to-end demonstration of the detection pipeline (network required).

1. Discovery  - pulls currently reported phishing URLs that reference monitored brands
                (Phishing.Database + OpenPhish) and, optionally, CT-log lookalikes.
2. Analysis   - renders every page in headless Chromium and runs URL, visual,
                behavioural, evasion and infrastructure analysis (ANALYZE_FETCH on).
3. Clustering - groups the results into campaigns over shared infrastructure.
4. Takedown   - prints the routed takedown plan for the largest campaign.

The run uses its own throwaway database, so it never touches analyst data.

Usage (from backend/):
    python -m eval.live_demo --limit 20 [--ct phonepe] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=20, help="maximum URLs to analyse")
    parser.add_argument("--ct", action="append", default=[], help="also crawl CT logs for this brand keyword")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--json", help="write the full result to this file")
    parser.add_argument("--workdir", help="directory for the demo database and screenshots (default: temporary)")
    args = parser.parse_args(argv)

    workdir = args.workdir or tempfile.mkdtemp(prefix="upi-shield-demo-")
    os.makedirs(workdir, exist_ok=True)
    os.environ.update({"UPI_SHIELD_DB": os.path.join(workdir, "demo.db"), "SEED_DEMO": "0", "ANALYZE_FETCH": "1",
                       "UPI_SHIELD_EVIDENCE_DIR": os.path.join(workdir, "evidence")})

    from app.services import casework, crawler, ingest, pipeline, url_features
    from app.store import store
    from eval import build_benchmark

    pipeline.ANALYZE_FETCH = True
    started = time.time()
    print("1. Discovery")
    urls: list[str] = []
    for name, src in build_benchmark.SOURCES.items():
        try:
            lines = build_benchmark._get(src).decode("utf-8", "ignore").splitlines()
        except Exception as exc:  # noqa: BLE001
            print(f"   {name}: unavailable ({exc})")
            continue
        picked = []
        for line in (raw.strip() for raw in lines):
            if not line or line.startswith("#") or " " in line:
                continue
            url = line if "://" in line else f"https://{line}/"
            if build_benchmark._mentions_brand(url_features.host_of(url)):
                picked.append(url)
        print(f"   {name}: {len(picked)} brand-referencing URLs")
        urls += picked
    for keyword in args.ct:
        hosts = crawler.discover_from_ct([keyword])
        print(f"   crt.sh '{keyword}': {len(hosts)} lookalike hosts")
        urls += [f"https://{h}/" for h in hosts]
    # One URL per host keeps the sample diverse (feeds list many paths of a single kit).
    per_host: dict[str, str] = {}
    for url in urls:
        per_host.setdefault(url_features.host_of(url), url)
    urls = list(per_host.values())[: args.limit]

    print(f"2. Analysis of {len(urls)} URLs (rendered, {args.workers} workers)")
    def analyse(url: str):
        try:
            return ingest.analyze_and_store(url, "feed")
        except Exception as exc:  # noqa: BLE001
            print(f"   ! {url}: {exc}")
            return None
    with ThreadPoolExecutor(args.workers) as pool:
        results = [c for c in pool.map(analyse, urls) if c]
    for c in sorted(results, key=lambda c: -c.risk_score):
        top = ", ".join(s.name for s in sorted(c.signals, key=lambda s: -s.weight)[:3] if s.weight > 0)
        state = {True: "live", False: "down", None: "n/a"}[c.live]
        brand = c.brand_matched or "-"
        print(f"   {c.verdict:<10} {c.risk_score:.2f} {state:<4} brand={brand:<9} {c.url[:58]:<58} {top}")

    store.recluster()
    print(f"3. Clustering: {len(store.campaigns)} campaign(s)")
    for camp in store.campaigns:
        print(f"   {camp.id} size={camp.size} brands={','.join(camp.brands_targeted)} linked by "
              + ", ".join(f"{e.type}={e.value}" for e in camp.shared_entities[:4]))

    plan = None
    if store.campaigns:
        camp = max(store.campaigns, key=lambda c: c.size)
        plan = casework.takedown_plan(camp, [store.candidates[i] for i in camp.candidate_ids])
        print(f"4. Takedown plan for {camp.id}")
        for item in plan.items:
            print(f"   {item.recipient:<17} {item.channel:<15} {', '.join(item.contacts)[:60]:<60} "
                  f"{len(item.targets)} target(s)")
    flagged = sum(c.verdict != "benign" for c in results)
    live = sum(c.live is True for c in results if c.verdict != "benign")
    print(f"Done in {time.time() - started:.0f}s: {flagged}/{len(results)} flagged ({live} still live); "
          f"workspace {workdir}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"candidates": [c.model_dump(mode="json") for c in results],
                       "campaigns": [c.model_dump(mode="json") for c in store.campaigns],
                       "plan": plan.model_dump(mode="json") if plan else None}, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
