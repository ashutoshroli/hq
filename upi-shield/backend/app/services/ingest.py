"""Ingestion workflows shared by the HTTP API and background jobs.

Each workflow analyses URLs through ``pipeline.analyze_url`` and writes the results
to the store. Job workflows receive a ``JobContext`` and report per-URL progress, so
one unreachable URL never fails the whole job.
"""
from __future__ import annotations

import logging

from app.config import get_settings
from app.jobs import JobContext
from app.schemas import Candidate, Entity, Signal, SourceType
from app.services import apps, crawler, extractor, feeds, fetcher, messages, pipeline, url_features
from app.store import store

logger = logging.getLogger(__name__)


def queue_app_analysis(apk_url: str, source: SourceType, via: str | None = None,
                       extra_entities: list[Entity] | None = None) -> str:
    """Start a background job that downloads and analyses an APK. Returns the job id."""
    from app.jobs import jobs

    job = jobs.submit("ingest_app_url", {"url": apk_url, "via": via},
                      app_url_job(apk_url, source, extra_entities=extra_entities))
    return job.id


def analyze_and_store(url: str, source: SourceType, extra_entities: list[Entity] | None = None,
                      job_ids: list[str] | None = None) -> Candidate:
    """Analyse a URL and store it. APK links (by path, by content type, or offered on the
    page) are also queued for app analysis; their job ids are appended to ``job_ids``."""
    queued: set[str] = set()

    def follow_apks(links: list[str]) -> None:
        for link in links:
            if link not in queued:
                queued.add(link)
                job_id = queue_app_analysis(link, source, via=url, extra_entities=extra_entities)
                if job_ids is not None:
                    job_ids.append(job_id)

    if fetcher.is_apk_url(url):
        follow_apks([url])  # the link itself is an app; analyse it even when page fetching is off
    cand = pipeline.analyze_url(url, source, extra_entities=extra_entities, on_apk_links=follow_apks)
    if fetcher.is_apk_url(url) and not any(s.name == "apk_download" for s in cand.signals):
        cand.signals.append(Signal(name="apk_download", weight=0.2,
                                   detail="Link points directly at an Android app (.apk) outside Google Play"))
        cand.risk_score = round(min(1.0, sum(s.weight for s in cand.signals)), 3)
        cand.verdict = url_features.verdict_for(cand.risk_score)
    return store.add(cand)


def analyze_app_and_store(data: bytes, source: SourceType, origin_url: str | None = None) -> Candidate:
    # The candidate URL embeds the APK hash, so re-submitting the same file updates it.
    return store.add(apps.analyze_apk(data, source=source, origin_url=origin_url))


def app_url_job(url: str, source: SourceType, extra_entities: list[Entity] | None = None):
    """Download an APK and analyse it."""
    def body(ctx: JobContext) -> None:
        ctx.set_total(1)
        data = fetcher.download_apk(url)
        cand = apps.analyze_apk(data, source=source, origin_url=url, extra_entities=extra_entities)
        ctx.advance(ok=True, candidate_id=store.add(cand).id)
    return body


def message_entities(found: dict[str, list[str]]) -> list[Entity]:
    """Payment and contact indicators extracted from a message, as linking entities."""
    return ([Entity(type="upi_id", value=u) for u in found.get("upi_ids", [])]
            + [Entity(type="phone", value=p) for p in found.get("phones", [])]
            + [Entity(type="telegram", value=t) for t in found.get("telegram", [])])


def ingest_message(text: str, source: SourceType,
                   job_ids: list[str] | None = None) -> tuple[dict[str, list[str]], list[str]]:
    """Extract indicators from message text and analyse what it contains.

    URLs are analysed as web candidates (APK links additionally as apps) carrying the
    message's payment and contact indicators. A message with no URL but with UPI
    handles, phone numbers or Telegram handles is stored as a ``message`` candidate so
    those indicators still reach the graph and campaign clustering.
    """
    found = extractor.extract(text)
    extra = message_entities(found)
    ids = [analyze_and_store(url, source, extra_entities=list(extra), job_ids=job_ids).id for url in found["urls"]]
    if not found["urls"] and extra:
        ids.append(store.add(messages.message_candidate(text, found, source, list(extra))).id)
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
