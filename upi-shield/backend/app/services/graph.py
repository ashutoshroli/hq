"""Infrastructure graph: candidates (sites and apps) linked to the infrastructure they use.

Node ids keep the original contract (``"<type>:<value>"``; a web candidate is
``domain:<host>``, an app is ``package_name:<package>``). Edges carry a relation that
describes how the candidate uses the entity, and every entity node says whether it
actually links candidates under the clustering rules (``linking``) - shared CDN IPs,
shorteners and brand domains are drawn but marked non-linking, so analysts see why two
sites were *not* merged.
"""
from __future__ import annotations

from collections import defaultdict

from app.schemas import Candidate, GraphEdge, GraphNode, GraphResponse
from app.services import clustering

RELATIONS = {
    "ip": "hosted_on", "asn": "in_network", "cert_fingerprint": "serves_certificate", "registrar": "registered_with",
    "upi_id": "collects_payments_to", "phone": "lists_contact", "telegram": "uses_telegram",
    "favicon_hash": "shares_asset", "analytics_id": "shares_tracking_id", "domain": "communicates_with",
    "package_name": "app_package", "apk_sha256": "app_build", "signing_cert": "signed_with",
}


def candidate_node_id(c: Candidate) -> str:
    return f"package_name:{c.app.package}" if c.kind == "app" and c.app else f"domain:{c.domain}"


def build_graph(cands: list[Candidate]) -> GraphResponse:
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str], GraphEdge] = {}
    users: dict[str, set[str]] = defaultdict(set)

    for c in cands:
        cid = candidate_node_id(c)
        nodes[cid] = GraphNode(id=cid, type="app" if c.kind == "app" else "domain", label=c.domain,
                               campaign_id=c.campaign_id, candidate_id=c.id, risk_score=c.risk_score,
                               verdict=c.verdict, brand=c.brand_matched, kind=c.kind)
    for c in cands:
        cid = candidate_node_id(c)
        for e in c.entities:
            nid = f"{e.type}:{e.value}"
            if nid == cid:
                continue
            linking = clustering.entity_links(e, c)
            node = nodes.get(nid)
            if node is None:
                nodes[nid] = GraphNode(id=nid, type=e.type, label=e.value, campaign_id=c.campaign_id,
                                       linking=linking)
            elif node.candidate_id is None:
                node.linking = bool(node.linking) and linking
            relation = RELATIONS.get(e.type, "uses")
            if e.type == "domain" and nid in nodes and nodes[nid].candidate_id and c.kind == "web":
                relation = "redirects_to"
            edges.setdefault((cid, nid, relation), GraphEdge(source=cid, target=nid, relation=relation))
            users[nid].add(c.id)
        infra = c.infrastructure
        if infra and infra.ip and infra.asn:
            ip_id, asn_id = f"ip:{infra.ip}", f"asn:{infra.asn}"
            label = f"{infra.asn} {infra.as_name or ''}".strip()
            nodes.setdefault(asn_id, GraphNode(id=asn_id, type="asn", label=label, linking=False))
            if ip_id in nodes:
                edges.setdefault((ip_id, asn_id, "in_network"), GraphEdge(source=ip_id, target=asn_id,
                                                                         relation="in_network"))
    for nid, who in users.items():
        nodes[nid].degree = len(who)
    return GraphResponse(nodes=list(nodes.values()), edges=list(edges.values()))


def pivot(cands: list[Candidate], entity_type: str, value: str) -> list[Candidate]:
    """Every candidate that uses a given entity (analyst pivot)."""
    needle = value.lower() if entity_type == "domain" else value
    return [c for c in cands if any(e.type == entity_type and (e.value.lower() if entity_type == "domain"
                                                               else e.value) == needle for e in c.entities)]
