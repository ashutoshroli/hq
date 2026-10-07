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


class IngestUrlRequest(BaseModel):
    url: str
    source: SourceType = "user_report"


class IngestMessageRequest(BaseModel):
    text: str
    source: SourceType = "message"


class IngestResponse(BaseModel):
    job_id: str
    status: Literal["done", "running", "failed"]
    candidate_ids: list[str]
    extracted: dict[str, list[str]] = {}  # urls, upi_ids, phones found in the message


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
