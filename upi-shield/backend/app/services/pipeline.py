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
from app.services import behaviour, enrichment, evasion, fetcher, url_features, visual

logger = logging.getLogger(__name__)

# Best-effort page fetch is OPT-IN. It defaults to OFF so offline/CI tests stay
# deterministic (no network). Enable at runtime with ANALYZE_FETCH=1 or per-call.
ANALYZE_FETCH = os.getenv("ANALYZE_FETCH", "").lower() in {"1", "true", "yes", "on"}


def _probes(url: str) -> dict:
    """Extra fetches used for cloaking detection: a mobile browser and a search crawler."""
    return {"mobile": fetcher.probe(url, fetcher.MOBILE_UA), "crawler": fetcher.probe(url, fetcher.CRAWLER_UA)}


def analyze_url(url: str, source: SourceType, extra_entities: list[Entity] | None = None,
                do_fetch: bool | None = None, fetch_result=None, probes: dict | None = None,
                on_apk_links=None) -> Candidate:
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
        if result.ok:
            probes = probes if probes is not None else _probes(url)
    probes = probes or {}

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
                # Short links and redirectors hide the landing page: score it too.
                _s, final_signals, final_brand = url_features.score_url(result.final_url)
                known = {sig.name for sig in signals}
                signals.extend(Signal(name=f"landing_{sig.name}", weight=sig.weight,
                                      detail=f"Landing page {final_host}: {sig.detail}")
                               for sig in final_signals if sig.name not in known)
                brand = brand or final_brand
                if final_host:
                    entities.append(Entity(type="domain", value=final_host))

            challenge = evasion.bot_challenge(result)
            if challenge:
                signals.append(challenge)
            cloaking = evasion.detect_cloaking(probes.get("mobile") or result, probes.get("crawler"),
                                               lambda u: url_features.registered_domain(url_features.host_of(u)))

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

            # Behavioural phishing tells from the fetched DOM. Kits that target phones
            # may only show the harvesting form to mobile browsers, so the mobile view
            # is inspected as well.
            behaviour_signals = behaviour.analyze_behaviour(result, impersonating=brand is not None)
            mobile = probes.get("mobile")
            if mobile is not None and getattr(mobile, "ok", False):
                seen = {sig.name for sig in behaviour_signals}
                behaviour_signals += [
                    sig.model_copy(update={"detail": sig.detail + " (mobile view only)"})
                    for sig in behaviour.analyze_behaviour(mobile, impersonating=brand is not None)
                    if sig.name not in seen]
            signals.extend(behaviour_signals)
            if on_apk_links is not None:
                links = behaviour.apk_links(result) or behaviour.apk_links(probes.get("mobile"))
                if links:
                    on_apk_links(links)

            # Many legitimate sites also refuse spoofed crawler requests, so cloaking only
            # counts fully when the page impersonates a brand or collects credentials.
            if cloaking:
                phishing_context = brand is not None or any(
                    sig.name in ("credential_input_fields", "cross_domain_form_action") for sig in behaviour_signals)
                if not phishing_context:
                    cloaking = cloaking.model_copy(update={
                        "weight": 0.0, "detail": cloaking.detail + " (no phishing context; informational)"})
                signals.append(cloaking)

    # Infrastructure enrichment runs behind the SAME fetch/enrich flag so offline
    # tests stay deterministic (default off => lexical-only, no network). It is
    # best-effort and never raises; merge its entities deduped by (type, value).
    if should_fetch:
        if brands.official_brand_for(url_features.registered_domain(host)) is None:
            age = evasion.domain_age_signal(enrichment.domain_created(url_features.registered_domain(host)))
            if age:
                signals.append(age)
        seen = {(e.type, e.value) for e in entities}
        for e in enrichment.enrich(host, fetch_result=result):
            key = (e.type, e.value)
            if key not in seen:
                seen.add(key)
                entities.append(e)

    infra = None
    if should_fetch:
        infra = enrichment.infrastructure(host, next((e.value for e in entities if e.type == "ip"), None))
        if infra and infra.asn and not any(e.type == "asn" for e in entities):
            entities.append(Entity(type="asn", value=infra.asn))

    # risk_score = clamped sum of all signal weights; verdict recomputed from it.
    score = min(1.0, sum(s.weight for s in signals))

    return Candidate(
        id=uuid.uuid4().hex[:8], url=url, domain=host, source=source,
        first_seen=datetime.now(UTC), risk_score=round(score, 3),
        verdict=url_features.verdict_for(score), brand_matched=brand,
        visual_similarity=visual_similarity,
        signals=signals, entities=entities, screenshot_url=screenshot_url, infrastructure=infra,
    )
