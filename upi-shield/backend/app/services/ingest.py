"""Ingestion workflows shared by the HTTP API and background jobs.

Each workflow analyses URLs through ``pipeline.analyze_url`` and writes the results
to the store. Job workflows receive a ``JobContext`` and report per-URL progress, so
one unreachable URL never fails the whole job.
"""
from __future__ import annotations

import logging

from app.config import get_settings
from app.jobs import JobContext
from app.schemas import Candidate, Entity, SourceType
from app.services import crawler, extractor, feeds, pipeline
from app.store import store

logger = logging.getLogger(__name__)


def analyze_and_store(url: str, source: SourceType, extra_entities: list[Entity] | None = None) -> Candidate:
    cand = pipeline.analyze_url(url, source, extra_entities=extra_entities)
    return store.add(cand)


def message_entities(found: dict[str, list[str]]) -> list[Entity]:
    """Payment and contact indicators extracted from a message, as linking entities."""
    return ([Entity(type="upi_id", value=u) for u in found.get("upi_ids", [])]
            + [Entity(type="phone", value=p) for p in found.get("phones", [])]
            + [Entity(type="telegram", value=t) for t in found.get("telegram", [])])


def ingest_message(text: str, source: SourceType) -> tuple[dict[str, list[str]], list[str]]:
    """Extract indicators from message text and analyse every URL it contains."""
    found = extractor.extract(text)
    extra = message_entities(found)
    ids = [analyze_and_store(url, source, extra_entities=list(extra)).id for url in found["urls"]]
    return found, ids


def _analyze_urls(ctx: JobContext, urls: list[str], source: SourceType) -> None:
    ctx.set_total(len(urls))
    for url in urls:
        try:
            cand = analyze_and_store(url, source)
            ctx.advance(ok=True, candidate_id=cand.id)
        except Exception:  # noqa: BLE001 - isolate per-URL failures
            logger.exception("ingest: analysis failed for %s", url)
            ctx.advance(ok=False)


def batch_job(urls: list[str], source: SourceType):
    def body(ctx: JobContext) -> None:
        _analyze_urls(ctx, list(dict.fromkeys(urls)), source)
    return body


def crawl_job(keywords: list[str] | None, max_hosts: int | None, fetch_fn=None):
    """Discover lookalike hosts from certificate-transparency logs and analyse them."""
    settings = get_settings()
    terms = keywords or settings.crawl_keywords
    limit = max_hosts or settings.crawl_max_hosts

    def body(ctx: JobContext) -> None:
        hosts = crawler.discover_from_ct(terms, fetch_fn=fetch_fn)[:limit]
        logger.info("crawl: %d lookalike host(s) discovered for %s", len(hosts), terms)
        _analyze_urls(ctx, [f"https://{h}" for h in hosts], "ct_log")
    return body


def feed_job(feed: str, brand_filter: bool, limit: int, fetch_fn=None):
    """Pull a public phishing feed and analyse the (brand-related) URLs it lists."""
    def body(ctx: JobContext) -> None:
        urls = feeds.fetch_feed(feed, brand_filter=brand_filter, limit=limit, fetch_fn=fetch_fn)
        logger.info("feed %s: %d URL(s) selected", feed, len(urls))
        _analyze_urls(ctx, urls, "feed")
    return body
