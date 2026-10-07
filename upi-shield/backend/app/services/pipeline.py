"""Orchestrates analysis stages. Add stages here as you build them:
   TODO fetcher (Playwright screenshot + DOM + redirect chain)
   TODO visual similarity (CLIP/pHash vs brand index)  -> sets visual_similarity, adds signal
   TODO behaviour (UPI PIN/OTP fields, cross-domain form action, obfuscated JS)
   TODO enrichment (DNS/IP/ASN/WHOIS/cert) -> more Entity rows
"""
import uuid
from datetime import datetime, timezone

from app.schemas import Candidate, Entity, SourceType
from app.services import url_features


def analyze_url(url: str, source: SourceType, extra_entities: list[Entity] | None = None) -> Candidate:
    score, signals, brand = url_features.score_url(url)
    host = url_features.host_of(url)
    entities = [Entity(type="domain", value=host)] + (extra_entities or [])
    return Candidate(
        id=uuid.uuid4().hex[:8], url=url, domain=host, source=source,
        first_seen=datetime.now(timezone.utc), risk_score=round(score, 3),
        verdict=url_features.verdict_for(score), brand_matched=brand,
        signals=signals, entities=entities,
    )
