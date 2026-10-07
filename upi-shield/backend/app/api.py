import json
import logging
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from app.schemas import (Campaign, Candidate, EvalMetrics, GraphEdge, GraphNode, GraphResponse,
                         IngestMessageRequest, IngestResponse, IngestUrlRequest, StageMetrics,
                         TakedownReport, TakedownRequest, Entity)
from app.seed import seed
from app.services import extractor, pipeline, takedown
from app.store import store

logger = logging.getLogger(__name__)
router = APIRouter()

# eval/evaluate.py writes real precision/recall here (backend/eval/metrics.json).
# /eval/metrics loads it when present and falls back to a placeholder otherwise.
_METRICS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "eval", "metrics.json")

_PLACEHOLDER_METRICS = EvalMetrics(sample_size=0, is_placeholder=True, stages=[
    StageMetrics(stage="url_only", precision=0.0, recall=0.0, f1=0.0),
    StageMetrics(stage="url+visual", precision=0.0, recall=0.0, f1=0.0),
    StageMetrics(stage="full", precision=0.0, recall=0.0, f1=0.0),
])


@router.get("/health")
def health():
    return {"status": "ok", "candidates": len(store.candidates), "campaigns": len(store.campaigns)}


@router.post("/ingest/url", response_model=IngestResponse)
def ingest_url(req: IngestUrlRequest):
    cand = pipeline.analyze_url(req.url, req.source)
    store.add(cand)
    return IngestResponse(job_id=uuid.uuid4().hex[:8], status="done", candidate_ids=[cand.id])


@router.post("/ingest/message", response_model=IngestResponse)
def ingest_message(req: IngestMessageRequest):
    found = extractor.extract(req.text)
    extra = [Entity(type="upi_id", value=u) for u in found["upi_ids"]] + \
            [Entity(type="phone", value=p) for p in found["phones"]] + \
            [Entity(type="telegram", value=t) for t in found.get("telegram", [])]
    ids = []
    for url in found["urls"]:
        cand = pipeline.analyze_url(url, req.source, extra_entities=list(extra))
        store.add(cand)
        ids.append(cand.id)
    return IngestResponse(job_id=uuid.uuid4().hex[:8], status="done", candidate_ids=ids, extracted=found)


@router.get("/candidates", response_model=list[Candidate])
def list_candidates(min_score: float = Query(0, ge=0, le=1), verdict: str | None = None, limit: int = 100):
    items = [c for c in store.candidates.values()
             if c.risk_score >= min_score and (verdict is None or c.verdict == verdict)]
    return sorted(items, key=lambda c: c.risk_score, reverse=True)[:limit]


@router.get("/candidates/{cid}", response_model=Candidate)
def get_candidate(cid: str):
    if cid not in store.candidates:
        raise HTTPException(404, "candidate not found")
    return store.candidates[cid]


@router.get("/campaigns", response_model=list[Campaign])
def list_campaigns():
    return store.campaigns


@router.get("/campaigns/{camp_id}", response_model=Campaign)
def get_campaign(camp_id: str):
    for c in store.campaigns:
        if c.id == camp_id:
            return c
    raise HTTPException(404, "campaign not found")


@router.get("/graph", response_model=GraphResponse)
def graph(campaign_id: str | None = None):
    cands = [c for c in store.candidates.values() if campaign_id is None or c.campaign_id == campaign_id]
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    for c in cands:
        for e in c.entities:
            nid = f"{e.type}:{e.value}"
            nodes.setdefault(nid, GraphNode(id=nid, type=e.type, label=e.value, campaign_id=c.campaign_id))
            if e.type != "domain":
                edges.append(GraphEdge(source=f"domain:{c.domain}", target=nid, relation="uses"))
    return GraphResponse(nodes=list(nodes.values()), edges=edges)


@router.post("/reports/takedown", response_model=TakedownReport)
def takedown_report(req: TakedownRequest):
    camp = next((c for c in store.campaigns if c.id == req.campaign_id), None)
    if camp is None:
        raise HTTPException(404, "campaign not found")
    members = [store.candidates[i] for i in camp.candidate_ids]
    return takedown.generate(camp, members, req.recipient)


@router.get("/eval/metrics", response_model=EvalMetrics)
def eval_metrics():
    """Return real metrics from eval/metrics.json when present (is_placeholder=false),
    otherwise a placeholder (is_placeholder=true) so the dashboard never errors.
    Regenerate the artifact with `python -m eval.evaluate`."""
    try:
        if os.path.exists(_METRICS_PATH):
            with open(_METRICS_PATH, encoding="utf-8") as fh:
                return EvalMetrics(**json.load(fh))
    except Exception as exc:  # noqa: BLE001 - never let a bad artifact break the endpoint
        logger.warning("eval_metrics: failed to load %s: %s", _METRICS_PATH, exc)
    return _PLACEHOLDER_METRICS


@router.post("/admin/seed")
def seed_demo():
    seed()
    return {"candidates": len(store.candidates), "campaigns": len(store.campaigns)}
