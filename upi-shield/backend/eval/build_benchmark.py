"""Build the real-world lookalike-domain benchmark from public sources (network).

The benchmark is evaluated at **host level**: every row is a bare ``https://<host>/``
for both classes. Benign rows come from a popularity list and have no paths, so
evaluating phishing URLs with their paths would let path features separate the classes
for reasons unrelated to detection. Host level is also exactly the decision the
certificate-transparency crawler has to make for a newly certified name.

Positives (label ``phishing``): hosts reported as active phishing by
  * Phishing.Database (github.com/Phishing-Database) - ACTIVE links and domains
  * OpenPhish community feed
  selected when a hostname token (split on non-alphanumerics) starts with a monitored brand
  keyword, or ends with one of five or more characters - e.g. ``phonepe-kyc``,
  ``sbiyono``, ``/upi/``, ``myphonepe``.
  This filter is plain text matching and independent of the detector (which also
  uses homoglyphs, typosquats and visual evidence).

Negatives (label ``benign``): domains from the Tranco top-1M popularity list
  * hard negatives - every Tranco domain containing a brand keyword substring that is
    not reported as phishing (e.g. ``famousbirthdays.com`` contains "sbi")
  * general negatives - a fixed random sample of the Tranco top 100k
  Brand-owned domains from ``app/brands.py`` are excluded so that the catalogue does
  not leak labels into the benchmark.

Target annotation: public feeds label *phishing* but not *which brand* is attacked.
Many keyword hits target other organisations (``upiholdlogin`` targets the Uphold
exchange, ``sbisec`` targets SBI Securities Japan). Every phishing host is annotated
in ``eval/data/benchmark_targets.csv`` with the monitored brand it impersonates; hosts
not listed there are ``other`` and are excluded from the in-scope metrics. The
annotations are hostname-based judgements by the maintainers and are committed so
they can be reviewed.

One URL is kept per host, hosts are split deterministically into ``dev`` and ``test``
halves by hash, and the result is written to ``eval/data/benchmark.csv``. The detector
may only be tuned by looking at ``dev`` errors; ``test`` is the reported number.

Usage (from backend/):  python -m eval.build_benchmark
"""
from __future__ import annotations

import csv
import hashlib
import io
import logging
import random
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

from app import brands
from app.services import url_features

logger = logging.getLogger("build_benchmark")

OUT = Path(__file__).resolve().parent / "data" / "benchmark.csv"
TARGETS = Path(__file__).resolve().parent / "data" / "benchmark_targets.csv"
SOURCES = {
    "phishing_database_links": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                               "phishing-links-ACTIVE.txt",
    "phishing_database_domains": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                                 "phishing-domains-ACTIVE.txt",
    "openphish": "https://openphish.com/feed.txt",
}
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
KEYWORDS = sorted({kw for b in brands.BRANDS.values() for kw in b.keywords} | {"upi", "npci"})
GENERAL_NEGATIVES = 1500
SEED = 20261007


def _get(url: str) -> bytes:
    resp = httpx.get(url, timeout=180.0, follow_redirects=True, headers={"User-Agent": "upi-shield-benchmark/1.0"})
    resp.raise_for_status()
    return resp.content


_TOKEN = re.compile(r"[a-z0-9]+")


def _mentions_brand(text: str) -> bool:
    """A brand keyword at a token boundary (positives)."""
    for token in _TOKEN.findall(text.lower()):
        if len(token) > 40:  # encoded blobs, not words
            continue
        for kw in KEYWORDS:
            # Short keywords ("upi", "sbi") must begin a token; longer ones may also end it.
            if token.startswith(kw) or (len(kw) >= 5 and token.endswith(kw)):
                return True
    return False


def _contains_keyword(text: str) -> bool:
    """Any brand keyword substring (hard negatives: deliberately the loosest filter)."""
    low = text.lower()
    return any(kw in low for kw in KEYWORDS)


def split_for(host: str) -> str:
    return "dev" if int(hashlib.sha256(host.encode()).hexdigest(), 16) % 2 == 0 else "test"


def _official(host: str) -> bool:
    return brands.official_brand_for(url_features.registered_domain(host)) is not None


def build() -> list[dict]:
    rows: dict[str, dict] = {}
    phishing_hosts: set[str] = set()

    for name, url in SOURCES.items():
        try:
            lines = _get(url).decode("utf-8", errors="ignore").splitlines()
        except Exception as exc:  # noqa: BLE001
            logger.warning("source %s unavailable: %s", name, exc)
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or any(ch in line for ch in " ,\"'<>"):
                continue
            target = line if "://" in line else f"http://{line}/"
            host = url_features.host_of(target)
            if not host:
                continue
            phishing_hosts.add(host)
            if host in rows or _official(host) or not _mentions_brand(host):
                continue
            rows[host] = {"url": f"https://{host}/", "label": "phishing", "source": name, "host": host}
        logger.info("%s: %d phishing rows so far", name, len(rows))

    archive = zipfile.ZipFile(io.BytesIO(_get(TRANCO)))
    ranked = [line.split(",", 1)[1].strip() for line in archive.read("top-1m.csv").decode().splitlines() if line]
    hard = [d for d in ranked if _contains_keyword(d) and d not in phishing_hosts and not _official(d)]
    for domain in hard:
        rows.setdefault(domain, {"url": f"https://{domain}/", "label": "benign", "source": "tranco_keyword",
                                 "host": domain})
    pool = [d for d in ranked[:100_000] if d not in rows and d not in phishing_hosts and not _official(d)]
    for domain in random.Random(SEED).sample(pool, GENERAL_NEGATIVES):
        rows[domain] = {"url": f"https://{domain}/", "label": "benign", "source": "tranco_random", "host": domain}

    targets = {r["host"]: r["target"] for r in csv.DictReader(TARGETS.open(encoding="utf-8"))}
    collected = datetime.now(UTC).date().isoformat()
    out = []
    for host in sorted(rows):
        row = rows[host]
        target = targets.get(host, "other") if row["label"] == "phishing" else ""
        out.append({"url": row["url"], "label": row["label"], "target": target, "source": row["source"],
                    "split": split_for(host), "collected": collected})
    return out


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    rows = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["url", "label", "target", "source", "split", "collected"],
                                quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)
    counts: dict[tuple[str, str], int] = {}
    for r in rows:
        counts[(r["label"], r["split"])] = counts.get((r["label"], r["split"]), 0) + 1
    print(f"wrote {len(rows)} rows to {OUT}: {counts}")


if __name__ == "__main__":
    main()
