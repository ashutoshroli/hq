"""API contract. Agree on these with the frontend teammate and avoid renaming fields later."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SourceType = Literal["ct_log", "message", "user_report", "feed"]
Verdict = Literal["malicious", "suspicious", "benign"]
EntityType = Literal[
    "domain", "ip", "asn", "cert_fingerprint", "registrar",
    "upi_id", "phone", "telegram", "favicon_hash", "analytics_id",
    "package_name", "apk_sha256", "signing_cert",
]
Recipient = Literal["registrar", "hosting", "bank", "npci", "cert_in", "safe_browsing", "app_store",
                    "cybercrime_portal", "telecom"]
CandidateKind = Literal["web", "app", "message"]
ReviewStatus = Literal["unreviewed", "confirmed", "false_positive", "escalated"]
TakedownStatus = Literal["drafted", "sent", "acknowledged", "resolved", "rejected"]


class Entity(BaseModel):
    type: EntityType
    value: str


class Signal(BaseModel):
    """One piece of evidence behind a score, shown to analysts as 'why'."""
    name: str
    weight: float
    detail: str


class AppSummary(BaseModel):
    """Static-analysis facts for an Android app candidate (``kind == "app"``)."""
    package: str
    label: str
    version: str | None = None
    sha256: str
    permissions: list[str] = []
    cert_sha256: list[str] = []
    origin_url: str | None = None  # where the APK was downloaded from, when known


class InfrastructureSummary(BaseModel):
    """Hosting and registration facts used for takedown routing (filled when enrichment runs)."""
    ip: str | None = None
    asn: str | None = None  # e.g. "AS13335"
    as_name: str | None = None
    prefix: str | None = None
    shared_hosting: bool = False  # CDN / shared-hosting network: the IP is not operator-specific
    hosting_abuse_contacts: list[str] = []
    registrar: str | None = None
    registrar_abuse_email: str | None = None
    registrar_abuse_phone: str | None = None
    registered_on: datetime | None = None


class MessageSummary(BaseModel):
    """A URL-less lure (``kind == "message"``): its masked excerpt and extracted indicators."""
    sha256: str
    excerpt: str
    upi_ids: list[str] = []
    phones: list[str] = []
    telegram: list[str] = []


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
    kind: CandidateKind = "web"  # "app" for Android APK candidates (url is android://<package>)
    app: AppSummary | None = None
    message: MessageSummary | None = None
    infrastructure: InfrastructureSummary | None = None
    # Liveness at the last analysis: True = serving content, False = taken down / error
    # page, None = not fetched. Lets analysts prioritise live threats.
    live: bool | None = None
    # Analyst review (v0.2). False positives are excluded from campaigns and reports.
    review_status: ReviewStatus = "unreviewed"
    review_note: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None


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
    job_ids: list[str] = []  # background jobs started by this request (e.g. APK analysis)


class IngestAppUrlRequest(BaseModel):
    url: str  # direct link to an APK, e.g. one offered by a phishing page
    source: SourceType = "user_report"


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
    # Additive (v0.2): candidate facts on site/app nodes, linking facts on entity nodes.
    candidate_id: str | None = None
    kind: CandidateKind | None = None
    risk_score: float | None = None
    verdict: Verdict | None = None
    brand: str | None = None
    linking: bool | None = None  # entity nodes: whether this value can tie candidates together
    degree: int | None = None  # entity nodes: number of candidates using it


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


class BenchmarkMetrics(BaseModel):
    """Precision/recall on an external, real-world labelled sample."""
    name: str
    description: str
    split: str  # "test" is the held-out number; "dev" was used for tuning
    stage: str
    threshold: float
    sample_size: int
    positives: int
    negatives: int
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    tn: int
    false_positive_rate: float
    collected: str | None = None


class EvalMetrics(BaseModel):
    sample_size: int
    is_placeholder: bool  # True until eval/evaluate.py writes real numbers
    stages: list[StageMetrics]  # controlled fixture sample (page-level, all stages)
    benchmarks: list[BenchmarkMetrics] = []  # real-world samples (additive, v0.2)


class ReviewRequest(BaseModel):
    status: ReviewStatus
    note: str | None = Field(default=None, max_length=2000)
    analyst: str = Field(default="analyst", max_length=120)


class AuditEvent(BaseModel):
    id: str
    at: datetime
    actor: str
    action: str  # e.g. "candidate.review", "takedown.create", "takedown.status"
    target: str  # id of the affected candidate / campaign / takedown
    detail: dict = {}


class TakedownPlanItem(BaseModel):
    recipient: Recipient
    channel: str  # "email", "web_form" or "phone"
    contacts: list[str]
    targets: list[str]  # what this recipient is asked to act on
    rationale: str


class TakedownPlan(BaseModel):
    campaign_id: str
    generated_at: datetime
    items: list[TakedownPlanItem]


class TakedownCreateRequest(BaseModel):
    campaign_id: str
    recipient: Recipient
    contact: str | None = None  # defaults to the first contact in the takedown plan
    # Restrict the case to these plan targets (e.g. one brand's URLs); defaults to all.
    targets: list[str] | None = None
    analyst: str = Field(default="analyst", max_length=120)


class TakedownUpdateRequest(BaseModel):
    status: TakedownStatus
    note: str | None = Field(default=None, max_length=2000)
    analyst: str = Field(default="analyst", max_length=120)


class TargetCheck(BaseModel):
    target: str
    checked_at: datetime
    live: bool
    detail: str


class TakedownCase(BaseModel):
    id: str
    campaign_id: str
    recipient: Recipient
    contact: str | None = None
    status: TakedownStatus = "drafted"
    targets: list[str] = []
    report: TakedownReport
    created_at: datetime
    updated_at: datetime
    sent_at: datetime | None = None
    resolved_at: datetime | None = None
    checks: list[TargetCheck] = []
    notes: list[str] = []
