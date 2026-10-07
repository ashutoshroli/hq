"""Orchestrates analysis stages. Add stages here as you build them:
   DONE fetcher (httpx DOM + redirect chain; optional Playwright screenshot) -> best-effort
   TODO visual similarity (CLIP/pHash vs brand index)  -> sets visual_similarity, adds signal
   TODO behaviour (UPI PIN/OTP fields, cross-domain form action, obfuscated JS)
   TODO enrichment (DNS/IP/ASN/WHOIS/cert) -> more Entity rows
"""
import logging
import os
import uuid
from datetime import datetime, timezone

from app.schemas import Candidate, Entity, Signal, SourceType
from app.services import fetcher, url_features

logger = logging.getLogger(__name__)

# Best-effort page fetch is OPT-IN. It defaults to OFF so offline/CI tests stay
# deterministic (no network). Enable at runtime with ANALYZE_FETCH=1 or per-call.
ANALYZE_FETCH = os.getenv("ANALYZE_FETCH", "").lower() in {"1", "true", "yes", "on"}


def analyze_url(url: str, source: SourceType, extra_entities: list[Entity] | None = None,
                do_fetch: bool | None = None) -> Candidate:
    score, signals, brand = url_features.score_url(url)
    host = url_features.host_of(url)
    entities = [Entity(type="domain", value=host)] + (extra_entities or [])
    screenshot_url: str | None = None

    should_fetch = ANALYZE_FETCH if do_fetch is None else do_fetch
    if should_fetch:
        result = fetcher.fetch(url)  # never raises; typed-empty on failure
        if result.ok:
            if len(result.redirect_chain) > 1:
                signals.append(Signal(
                    name="redirect_chain", weight=0.1,
                    detail="Redirects through %d hops: %s" % (
                        len(result.redirect_chain), " -> ".join(result.redirect_chain)),
                ))
            score = min(1.0, score + sum(s.weight for s in signals if s.name == "redirect_chain"))
            if result.favicon_hash:
                entities.append(Entity(type="favicon_hash", value=result.favicon_hash))
            # screenshot_url is set only when a renderer captured one (Playwright path).
            screenshot_url = getattr(result, "screenshot_url", None)

    return Candidate(
        id=uuid.uuid4().hex[:8], url=url, domain=host, source=source,
        first_seen=datetime.now(timezone.utc), risk_score=round(score, 3),
        verdict=url_features.verdict_for(score), brand_matched=brand,
        signals=signals, entities=entities, screenshot_url=screenshot_url,
    )
