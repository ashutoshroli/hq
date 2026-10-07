"""Orchestrates the analysis stages for one URL.

1. URL features      - lexical scoring, always on, no network.
2. Fetch             - headless-Chromium render with screenshot (HTTP fallback).
3. Visual            - brand identification from the screenshot/favicon, then
                       similarity against the genuine brand's references.
4. Behaviour         - credential-harvesting DOM tells.
5. Enrichment        - IP/ASN/certificate/registrar/analytics linking entities.

Stages 2-5 run only when fetching is enabled (``ANALYZE_FETCH`` or ``do_fetch``) or
when the caller injects a ``fetch_result``; the default path stays offline.
"""
import logging
import os
import uuid
from datetime import UTC, datetime

from app import brands
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
        final_host = url_features.host_of(result.final_url or url)
        final_reg = url_features.registered_domain(final_host)
        start_reg = url_features.registered_domain(host)
        owner = brands.official_brand_for(final_reg)

        if result.favicon_hash:
            entities.append(Entity(type="favicon_hash", value=result.favicon_hash))
        # screenshot_url is set only when a renderer captured one (Playwright path).
        screenshot_url = getattr(result, "screenshot_url", None)

        if owner is not None:
            # The page is served from a domain the brand owns: genuine infrastructure.
            # Content-based tells (minified JS, card product pages, login forms) are
            # expected there and must not count against it.
            signals.append(Signal(name="official_brand_domain", weight=0.0,
                                  detail=f"Final page is served from {final_reg}, owned by {owner}"))
        else:
            if final_reg != start_reg and len(result.redirect_chain) > 1:
                signals.append(Signal(
                    name="cross_site_redirect", weight=0.1,
                    detail=f"Redirects across sites through {len(result.redirect_chain)} hops: "
                           + " -> ".join(result.redirect_chain),
                ))

            # A clone on a domain that does not mention any brand is still identifiable
            # by what it looks like.
            if brand is None:
                seen_brand, _seen_sim, id_signals = visual.identify_brand(result)
                if seen_brand:
                    brand = seen_brand
                    signals.extend(id_signals)

            # Visual similarity vs the matched brand (screenshot, favicon, structure).
            sim, visual_signals = visual.compare_visual(result, brand)
            if sim > 0 or visual_signals:
                visual_similarity = sim
                signals.extend(visual_signals)

            # Behavioural phishing tells from the fetched DOM.
            signals.extend(behaviour.analyze_behaviour(result, impersonating=brand is not None))

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
        first_seen=datetime.now(UTC), risk_score=round(score, 3),
        verdict=url_features.verdict_for(score), brand_matched=brand,
        visual_similarity=visual_similarity,
        signals=signals, entities=entities, screenshot_url=screenshot_url,
    )
