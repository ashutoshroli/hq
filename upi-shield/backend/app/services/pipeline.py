"""Orchestrates analysis stages. Add stages here as you build them:
   DONE fetcher (httpx DOM + redirect chain; optional Playwright screenshot) -> best-effort
   DONE visual similarity (lightweight pHash/structural vs brand index) -> sets visual_similarity, adds signals
   DONE behaviour (UPI PIN/OTP fields, cross-domain form action, obfuscated JS)
   DONE enrichment (DNS/IP/ASN/WHOIS/cert) -> more Entity rows (behind the fetch/enrich flag)
"""
import logging
import os
import uuid
from datetime import datetime, timezone

from app.schemas import Candidate, Entity, Signal, SourceType
from app.services import behaviour, enrichment, fetcher, url_features, visual

logger = logging.getLogger(__name__)

# Best-effort page fetch is OPT-IN. It defaults to OFF so offline/CI tests stay
# deterministic (no network). Enable at runtime with ANALYZE_FETCH=1 or per-call.
ANALYZE_FETCH = os.getenv("ANALYZE_FETCH", "").lower() in {"1", "true", "yes", "on"}


def analyze_url(url: str, source: SourceType, extra_entities: list[Entity] | None = None,
                do_fetch: bool | None = None, fetch_result=None) -> Candidate:
    _score, signals, brand = url_features.score_url(url)
    host = url_features.host_of(url)
    entities = [Entity(type="domain", value=host)] + (extra_entities or [])
    screenshot_url: str | None = None
    visual_similarity: float | None = None

    # `fetch_result` lets callers (and tests) inject a canned FetchResult directly;
    # otherwise a best-effort fetch runs only when enabled (default off => offline tests).
    should_fetch = ANALYZE_FETCH if do_fetch is None else do_fetch
    result = fetch_result
    if result is None and should_fetch:
        result = fetcher.fetch(url)  # never raises; typed-empty on failure

    if result is not None and getattr(result, "ok", False):
        if len(result.redirect_chain) > 1:
            signals.append(Signal(
                name="redirect_chain", weight=0.1,
                detail="Redirects through %d hops: %s" % (
                    len(result.redirect_chain), " -> ".join(result.redirect_chain)),
            ))
        if result.favicon_hash:
            entities.append(Entity(type="favicon_hash", value=result.favicon_hash))
        # screenshot_url is set only when a renderer captured one (Playwright path).
        screenshot_url = getattr(result, "screenshot_url", None)

        # Visual similarity vs the matched brand (lightweight pHash/structural).
        sim, visual_signals = visual.compare_visual(result, brand)
        if sim > 0 or visual_signals:
            visual_similarity = sim
            signals.extend(visual_signals)

        # Behavioural phishing tells from the fetched DOM.
        signals.extend(behaviour.analyze_behaviour(result))

    # Infrastructure enrichment runs behind the SAME fetch/enrich flag so offline
    # tests stay deterministic (default off => lexical-only, no network). It is
    # best-effort and never raises; merge its entities deduped by (type, value).
    if should_fetch:
        seen = {(e.type, e.value) for e in entities}
        for e in enrichment.enrich(host, fetch_result=result):
            key = (e.type, e.value)
            if key not in seen:
                seen.add(key)
                entities.append(e)

    # risk_score = clamped sum of all signal weights; verdict recomputed from it.
    score = min(1.0, sum(s.weight for s in signals))

    return Candidate(
        id=uuid.uuid4().hex[:8], url=url, domain=host, source=source,
        first_seen=datetime.now(timezone.utc), risk_score=round(score, 3),
        verdict=url_features.verdict_for(score), brand_matched=brand,
        visual_similarity=visual_similarity,
        signals=signals, entities=entities, screenshot_url=screenshot_url,
    )
