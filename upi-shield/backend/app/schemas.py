"""API contract. Agree on these with the frontend teammate and avoid renaming fields later."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SourceType = Literal["ct_log", "message", "user_report", "feed"]
Verdict = Literal["malicious", "suspicious", "benign"]
EntityType = Literal[
    "domain", "ip", "asn", "cert_fingerprint", "registrar",
    "upi_id", "phone", "telegram", "favicon_hash", "analytics_id",
]
Recipient = Literal["registrar", "hosting", "bank", "npci", "cert_in", "safe_browsing"]


class Entity(BaseModel):
    type: EntityType
    value: str


class Signal(BaseModel):
    """One piece of evidence behind a score, shown to analysts as 'why'."""
    name: str
    weight: float
    detail: str


class Candidate(BaseModel):
    id: str
    url: str
    domain: str
    source: SourceType
    first_seen: datetime
    risk_score: float = Field(ge=0, le=1)
    verdict: Verdict
    brand_matched: str | None = None
    visual_similarity: float | None = Field(default=None, ge=0, le=1)  # filled by visual engine
    screenshot_url: str | None = None
    signals: list[Signal] = []
    entities: list[Entity] = []
    campaign_id: str | None = None
    # Additive fields (v0.2). Optional so existing clients are unaffected.
    last_seen: datetime | None = None  # most recent sighting of the same normalised URL
    sightings: int = 1  # how many times the URL was ingested from any source


class IngestUrlRequest(BaseModel):
    url: str
    source: SourceType = "user_report"
    # When true the analysis runs as a background job and the response returns immediately.
    run_async: bool = False


class IngestMessageRequest(BaseModel):
    text: str
    source: SourceType = "message"


JobStatus = Literal["queued", "running", "done", "failed"]


class IngestResponse(BaseModel):
    job_id: str
    status: JobStatus
    candidate_ids: list[str]
    extracted: dict[str, list[str]] = {}  # urls, upi_ids, phones found in the message


class IngestBatchRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=1000)
    source: SourceType = "feed"


FeedName = Literal["openphish", "urlhaus"]


class IngestFeedRequest(BaseModel):
    feed: FeedName = "openphish"
    # Keep only URLs that reference a monitored payment brand (recommended for public feeds).
    brand_filter: bool = True
    limit: int = Field(default=200, ge=1, le=5000)


class CrawlRequest(BaseModel):
    # Brand keywords to search in certificate-transparency logs. Defaults to CRAWL_KEYWORDS.
    keywords: list[str] | None = None
    max_hosts: int | None = Field(default=None, ge=1, le=5000)


class JobProgress(BaseModel):
    total: int = 0
    processed: int = 0
    failed: int = 0


class Job(BaseModel):
    id: str
    kind: str
    status: JobStatus
    params: dict = {}
    progress: JobProgress = JobProgress()
    candidate_ids: list[str] = []
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class Campaign(BaseModel):
    id: str
    name: str
    first_seen: datetime
    last_seen: datetime
    size: int
    brands_targeted: list[str]
    candidate_ids: list[str]
    shared_entities: list[Entity]  # the evidence that links the members


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    campaign_id: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class TakedownRequest(BaseModel):
    campaign_id: str
    recipient: Recipient


class TakedownReport(BaseModel):
    campaign_id: str
    recipient: Recipient
    generated_at: datetime
    subject: str
    body: str


class StageMetrics(BaseModel):
    stage: str
    precision: float
    recall: float
    f1: float


class EvalMetrics(BaseModel):
    sample_size: int
    is_placeholder: bool  # True until eval/evaluate.py writes real numbers
    stages: list[StageMetrics]
