"""Campaign clustering: union-find over shared infrastructure entities."""
from collections import defaultdict

from app.schemas import Campaign, Candidate, Entity

# 'domain' is unique per candidate, so it never links anything; others are shared infrastructure.
LINKING = {"ip", "asn", "cert_fingerprint", "upi_id", "phone", "telegram", "favicon_hash", "analytics_id", "registrar"}
# WEAK types are shared by many unrelated sites (a registrar/ASN can host thousands),
# so they alone must NOT merge candidates; they only reinforce links from strong types.
WEAK = {"registrar", "asn"}


def build_campaigns(cands: list[Candidate]) -> list[Campaign]:
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
            if e.type in LINKING:
                by_shared[(e.type, e.value)].append(c.id)
                if e.type not in WEAK:
                    by_entity[(e.type, e.value)].append(c.id)
    for ids in by_entity.values():
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])

    groups: dict[str, list[Candidate]] = defaultdict(list)
    for c in cands:
        groups[find(c.id)].append(c)

    campaigns: list[Campaign] = []
    for members in sorted((g for g in groups.values() if len(g) >= 2), key=lambda g: min(m.first_seen for m in g)):
        ids = {m.id for m in members}
        shared = [Entity(type=t, value=v) for (t, v), who in by_shared.items() if len(set(who) & ids) >= 2]
        brands = sorted({m.brand_matched for m in members if m.brand_matched})
        campaigns.append(Campaign(
            id=f"camp-{len(campaigns) + 1}",
            name="Campaign targeting " + (", ".join(brands) if brands else "unknown brand"),
            first_seen=min(m.first_seen for m in members),
            last_seen=max(m.first_seen for m in members),
            size=len(members), brands_targeted=brands,
            candidate_ids=sorted(ids), shared_entities=shared,
        ))
    return campaigns
