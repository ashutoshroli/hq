"""Campaign clustering: union-find over shared infrastructure entities.

Campaign ids are stable: each campaign is named after a hash of its anchor member
(the earliest-seen candidate), so ids do not shift when unrelated candidates are
ingested. Candidates with a ``benign`` verdict never take part in clustering.
"""
import hashlib
from collections import defaultdict

from app.schemas import Campaign, Candidate, Entity

LINKING = {"ip", "asn", "cert_fingerprint", "upi_id", "phone", "telegram", "favicon_hash", "analytics_id", "registrar",
           "domain", "package_name", "apk_sha256", "signing_cert"}
# WEAK types are shared by many unrelated sites (a registrar/ASN can host thousands),
# so they alone must NOT merge candidates; they only reinforce links from strong types.
WEAK = {"registrar", "asn"}

# Widely shared values that would merge unrelated campaigns.
# The AOSP "testkey" certificate signs a large share of unrelated sideloaded malware.
SHARED_SIGNING_CERTS = {"a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc"}


# Entity types whose values are shared by every customer of a CDN / shared-hosting network.
_SHARED_ON_CDN = {"ip", "cert_fingerprint"}


def entity_links(entity: Entity, cand: Candidate | None = None) -> bool:
    """Whether an entity links candidates *strongly* (merges campaigns on its own)."""
    if not _is_linking(entity) or entity.type in WEAK:
        return False
    infra = getattr(cand, "infrastructure", None)
    return not (infra is not None and infra.shared_hosting and entity.type in _SHARED_ON_CDN)


def _is_linking(entity: Entity) -> bool:
    """Whether an entity value is specific enough to tie two candidates to one operator.

    A ``domain`` links a phishing page to an app that calls it, or two URLs on one host,
    but URL shorteners, bare hosting-platform domains and brand-owned domains are
    shared by everyone and never link.
    """
    if entity.type not in LINKING:
        return False
    if entity.type == "domain":
        from app import brands
        from app.services import evasion, url_features

        host = entity.value.lower()
        reg = url_features.registered_domain(host)
        return not (evasion.is_shortener(host) or host in evasion.FREE_HOSTING_SUFFIXES
                    or brands.official_brand_for(reg) is not None)
    if entity.type == "signing_cert":
        return entity.value.lower() not in SHARED_SIGNING_CERTS
    return True


def campaign_id_for(anchor: Candidate) -> str:
    return "camp-" + hashlib.sha1(anchor.id.encode("utf-8")).hexdigest()[:8]


def build_campaigns(cands: list[Candidate]) -> list[Campaign]:
    cands = [c for c in cands if c.verdict != "benign"]
    parent = {c.id: c.id for c in cands}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    # STRONG types (LINKING minus WEAK) actually merge candidates via union-find.
    # WEAK types (registrar, asn) never merge alone but are still recorded as shared
    # evidence so a campaign formed by a strong type can surface them for analysts.
    by_entity: dict[tuple[str, str], list[str]] = defaultdict(list)       # strong, drives union-find
    by_shared: dict[tuple[str, str], list[str]] = defaultdict(list)       # all LINKING, for evidence
    for c in cands:
        for e in c.entities:
            if _is_linking(e):
                key = (e.type, e.value.lower() if e.type == "domain" else e.value)
                if c.id not in by_shared[key]:
                    by_shared[key].append(c.id)
                if entity_links(e, c) and c.id not in by_entity[key]:
                    by_entity[key].append(c.id)
    for ids in by_entity.values():
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])

    groups: dict[str, list[Candidate]] = defaultdict(list)
    for c in cands:
        groups[find(c.id)].append(c)

    campaigns: list[Campaign] = []
    clusters = [sorted(g, key=lambda m: (m.first_seen, m.id)) for g in groups.values() if len(g) >= 2]
    for members in sorted(clusters, key=lambda g: (g[0].first_seen, g[0].id)):
        ids = {m.id for m in members}
        shared = [Entity(type=t, value=v) for (t, v), who in by_shared.items() if len(set(who) & ids) >= 2]
        brands = sorted({m.brand_matched for m in members if m.brand_matched})
        campaigns.append(Campaign(
            id=campaign_id_for(members[0]),
            name="Campaign targeting " + (", ".join(brands) if brands else "unknown brand"),
            first_seen=min(m.first_seen for m in members),
            last_seen=max(m.last_seen or m.first_seen for m in members),
            size=len(members), brands_targeted=brands,
            candidate_ids=sorted(ids), shared_entities=shared,
        ))
    return campaigns
