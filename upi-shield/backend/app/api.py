import json
import logging
import os
import re
import uuid

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse

from app.config import get_settings
from app.jobs import jobs
from app.schemas import (
    Campaign,
    Candidate,
    CrawlRequest,
    EvalMetrics,
    GraphEdge,
    GraphNode,
    GraphResponse,
    IngestAppUrlRequest,
    IngestBatchRequest,
    IngestFeedRequest,
    IngestMessageRequest,
    IngestResponse,
    IngestUrlRequest,
    Job,
    StageMetrics,
    TakedownReport,
    TakedownRequest,
)
from app.seed import seed
from app.services import apps, ingest, takedown
from app.store import store

logger = logging.getLogger(__name__)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Protect mutating endpoints when UPI_SHIELD_API_KEY is configured (no-op otherwise)."""
    expected = get_settings().api_key
    if expected and x_api_key != expected:
        raise HTTPException(401, "missing or invalid X-API-Key header")


router = APIRouter()
write = [Depends(require_api_key)]

# eval/evaluate.py writes real precision/recall here (backend/eval/metrics.json).
# /eval/metrics loads it when present and falls back to a placeholder otherwise.
_METRICS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "eval", "metrics.json")

_PLACEHOLDER_METRICS = EvalMetrics(sample_size=0, is_placeholder=True, stages=[
    StageMetrics(stage="url_only", precision=0.0, recall=0.0, f1=0.0),
    StageMetrics(stage="url+visual", precision=0.0, recall=0.0, f1=0.0),
    StageMetrics(stage="full", precision=0.0, recall=0.0, f1=0.0),
])


def _job_response(job: Job) -> IngestResponse:
    return IngestResponse(job_id=job.id, status=job.status, candidate_ids=job.candidate_ids)


# --- health -----------------------------------------------------------------------

@router.get("/health", tags=["system"])
def health():
    return {"status": "ok", "candidates": len(store.candidates), "campaigns": len(store.campaigns)}


@router.get("/stats", tags=["system"])
def stats():
    """Aggregate counts for dashboard overview tiles."""
    return store.stats()


# --- ingestion -----------------------------------------------------------------------

@router.post("/ingest/url", response_model=IngestResponse, dependencies=write, tags=["ingestion"])
def ingest_url(req: IngestUrlRequest):
    """Analyse one reported URL. Set ``run_async`` to queue it as a background job."""
    if req.run_async:
        return _job_response(jobs.submit("ingest_url", {"url": req.url, "source": req.source},
                                         ingest.batch_job([req.url], req.source)))
    cand = ingest.analyze_and_store(req.url, req.source)
    return IngestResponse(job_id=uuid.uuid4().hex[:8], status="done", candidate_ids=[cand.id])


@router.post("/ingest/message", response_model=IngestResponse, dependencies=write, tags=["ingestion"])
def ingest_message(req: IngestMessageRequest):
    """Extract URLs, UPI handles, phone numbers and Telegram handles from SMS/WhatsApp text."""
    found, ids = ingest.ingest_message(req.text, req.source)
    return IngestResponse(job_id=uuid.uuid4().hex[:8], status="done", candidate_ids=ids, extracted=found)


@router.post("/ingest/batch", response_model=IngestResponse, status_code=202, dependencies=write,
             tags=["ingestion"])
def ingest_batch(req: IngestBatchRequest):
    """Queue a list of URLs (e.g. an analyst upload) for background analysis."""
    job = jobs.submit("ingest_batch", {"count": len(req.urls), "source": req.source},
                      ingest.batch_job(req.urls, req.source))
    return _job_response(job)


@router.post("/ingest/feed", response_model=IngestResponse, status_code=202, dependencies=write,
             tags=["ingestion"])
def ingest_feed(req: IngestFeedRequest):
    """Pull a public phishing feed (OpenPhish / URLhaus) and analyse brand-related URLs."""
    job = jobs.submit("ingest_feed", req.model_dump(), ingest.feed_job(req.feed, req.brand_filter, req.limit))
    return _job_response(job)


@router.post("/ingest/app", response_model=IngestResponse, dependencies=write, tags=["ingestion"])
async def ingest_app(file: UploadFile = File(..., description="Android APK"),
                     source: str = Form("user_report")):
    """Statically analyse an uploaded APK (fake banking / UPI app detection)."""
    if source not in ("ct_log", "message", "user_report", "feed"):
        raise HTTPException(422, "invalid source")
    data = await file.read(apps.MAX_APK_BYTES + 1)
    try:
        cand = ingest.analyze_app_and_store(data, source)
    except apps.ApkError as exc:
        raise HTTPException(422, str(exc)) from exc
    return IngestResponse(job_id=uuid.uuid4().hex[:8], status="done", candidate_ids=[cand.id])


@router.post("/ingest/app/url", response_model=IngestResponse, status_code=202, dependencies=write,
             tags=["ingestion"])
def ingest_app_url(req: IngestAppUrlRequest):
    """Download an APK from a URL (e.g. one pushed by a phishing page) and analyse it."""
    return _job_response(jobs.submit("ingest_app_url", req.model_dump(), ingest.app_url_job(req.url, req.source)))


@router.post("/crawl/ct", response_model=IngestResponse, status_code=202, dependencies=write, tags=["ingestion"])
def crawl_ct(req: CrawlRequest):
    """Discover brand-lookalike hosts from certificate-transparency logs and analyse them."""
    job = jobs.submit("crawl_ct", req.model_dump(), ingest.crawl_job(req.keywords, req.max_hosts))
    return _job_response(job)


@router.get("/jobs", response_model=list[Job], tags=["ingestion"])
def list_jobs(limit: int = Query(50, ge=1, le=500)):
    return store.list_jobs(limit)


@router.get("/jobs/{job_id}", response_model=Job, tags=["ingestion"])
def get_job(job_id: str):
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job


# --- candidates & campaigns ---------------------------------------------------------

@router.get("/candidates", response_model=list[Candidate], tags=["analysis"])
def list_candidates(min_score: float = Query(0, ge=0, le=1), verdict: str | None = None,
                    kind: str | None = Query(None, description="web or app"),
                    brand: str | None = None, source: str | None = None, campaign_id: str | None = None,
                    q: str | None = Query(None, description="Substring match on URL or domain"),
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    needle = (q or "").lower()
    items = [c for c in store.candidates.values()
             if c.risk_score >= min_score
             and (verdict is None or c.verdict == verdict)
             and (kind is None or c.kind == kind)
             and (brand is None or c.brand_matched == brand)
             and (source is None or c.source == source)
             and (campaign_id is None or c.campaign_id == campaign_id)
             and (not needle or needle in c.url.lower() or needle in c.domain.lower())]
    items.sort(key=lambda c: (c.risk_score, c.first_seen), reverse=True)
    return items[offset:offset + limit]


@router.get("/candidates/{cid}", response_model=Candidate, tags=["analysis"])
def get_candidate(cid: str):
    if cid not in store.candidates:
        raise HTTPException(404, "candidate not found")
    return store.candidates[cid]


@router.get("/campaigns", response_model=list[Campaign], tags=["analysis"])
def list_campaigns():
    return store.campaigns


@router.get("/campaigns/{camp_id}", response_model=Campaign, tags=["analysis"])
def get_campaign(camp_id: str):
    for c in store.campaigns:
        if c.id == camp_id:
            return c
    raise HTTPException(404, "campaign not found")


@router.get("/graph", response_model=GraphResponse, tags=["analysis"])
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


# --- reporting ----------------------------------------------------------------------

@router.post("/reports/takedown", response_model=TakedownReport, dependencies=write, tags=["reporting"])
def takedown_report(req: TakedownRequest):
    camp = next((c for c in store.campaigns if c.id == req.campaign_id), None)
    if camp is None:
        raise HTTPException(404, "campaign not found")
    members = [store.candidates[i] for i in camp.candidate_ids]
    return takedown.generate(camp, members, req.recipient)


@router.get("/eval/metrics", response_model=EvalMetrics, tags=["reporting"])
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


_EVIDENCE_NAME = re.compile(r"[0-9a-f]{24}\.(png|jpg|html)")


@router.get("/evidence/{name}", tags=["reporting"], response_class=FileResponse)
def get_evidence(name: str):
    """Serve a captured evidence artefact (e.g. a page screenshot) by content hash."""
    if not _EVIDENCE_NAME.fullmatch(name):
        raise HTTPException(404, "evidence not found")
    path = os.path.join(get_settings().evidence_dir, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "evidence not found")
    return FileResponse(path)


# --- administration -----------------------------------------------------------------

@router.post("/admin/seed", dependencies=write, tags=["system"])
def seed_demo():
    """Reset the store to the demo dataset (two campaigns)."""
    seed()
    return {"candidates": len(store.candidates), "campaigns": len(store.campaigns)}
