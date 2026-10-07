// Mirrors the backend API contract in upi-shield/backend/app/schemas.py.

export type SourceType = "ct_log" | "message" | "user_report" | "feed";
export type Verdict = "malicious" | "suspicious" | "benign";
export type CandidateKind = "web" | "app" | "message";
export type ReviewStatus = "unreviewed" | "confirmed" | "false_positive" | "escalated";
export type JobStatus = "queued" | "running" | "done" | "failed";
export type TakedownStatus = "drafted" | "sent" | "acknowledged" | "resolved" | "rejected";
export type Recipient =
  | "registrar"
  | "hosting"
  | "bank"
  | "npci"
  | "cert_in"
  | "safe_browsing"
  | "app_store"
  | "cybercrime_portal"
  | "telecom";

export interface Entity {
  type: string;
  value: string;
}

export interface Signal {
  name: string;
  weight: number;
  detail: string;
}

export interface AppSummary {
  package: string;
  label: string;
  version: string | null;
  sha256: string;
  permissions: string[];
  cert_sha256: string[];
  origin_url: string | null;
}

export interface MessageSummary {
  sha256: string;
  excerpt: string;
  upi_ids: string[];
  phones: string[];
  telegram: string[];
}

export interface InfrastructureSummary {
  ip: string | null;
  asn: string | null;
  as_name: string | null;
  prefix: string | null;
  shared_hosting: boolean;
  hosting_abuse_contacts: string[];
  registrar: string | null;
  registrar_abuse_email: string | null;
  registrar_abuse_phone: string | null;
  registered_on: string | null;
}

export interface Candidate {
  id: string;
  url: string;
  domain: string;
  source: SourceType;
  first_seen: string;
  last_seen: string | null;
  sightings: number;
  risk_score: number;
  verdict: Verdict;
  brand_matched: string | null;
  visual_similarity: number | null;
  screenshot_url: string | null;
  signals: Signal[];
  entities: Entity[];
  campaign_id: string | null;
  kind: CandidateKind;
  app: AppSummary | null;
  message: MessageSummary | null;
  infrastructure: InfrastructureSummary | null;
  live: boolean | null;
  review_status: ReviewStatus;
  review_note: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

export interface Campaign {
  id: string;
  name: string;
  first_seen: string;
  last_seen: string;
  size: number;
  brands_targeted: string[];
  candidate_ids: string[];
  shared_entities: Entity[];
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  campaign_id: string | null;
  candidate_id: string | null;
  kind: CandidateKind | null;
  risk_score: number | null;
  verdict: Verdict | null;
  brand: string | null;
  linking: boolean | null;
  degree: number | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface IngestResponse {
  job_id: string;
  status: JobStatus;
  candidate_ids: string[];
  extracted: Record<string, string[]>;
  job_ids: string[];
}

export interface Job {
  id: string;
  kind: string;
  status: JobStatus;
  params: Record<string, unknown>;
  progress: { total: number; processed: number; failed: number };
  candidate_ids: string[];
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface TakedownReport {
  campaign_id: string;
  recipient: Recipient;
  generated_at: string;
  subject: string;
  body: string;
}

export interface TakedownPlanItem {
  recipient: Recipient;
  channel: string;
  contacts: string[];
  targets: string[];
  rationale: string;
}

export interface TakedownPlan {
  campaign_id: string;
  generated_at: string;
  items: TakedownPlanItem[];
}

export interface TargetCheck {
  target: string;
  checked_at: string;
  live: boolean;
  detail: string;
}

export interface TakedownCase {
  id: string;
  campaign_id: string;
  recipient: Recipient;
  contact: string | null;
  status: TakedownStatus;
  targets: string[];
  report: TakedownReport;
  created_at: string;
  updated_at: string;
  sent_at: string | null;
  resolved_at: string | null;
  checks: TargetCheck[];
  notes: string[];
}

export interface AuditEvent {
  id: string;
  at: string;
  actor: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
}

export interface StageMetrics {
  stage: string;
  precision: number;
  recall: number;
  f1: number;
}

export interface BenchmarkMetrics {
  name: string;
  description: string;
  split: string;
  stage: string;
  threshold: number;
  sample_size: number;
  positives: number;
  negatives: number;
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  false_positive_rate: number;
  collected: string | null;
}

export interface EvalMetrics {
  sample_size: number;
  is_placeholder: boolean;
  stages: StageMetrics[];
  benchmarks: BenchmarkMetrics[];
}

export interface DashboardSummary {
  generated_at: string;
  totals: {
    candidates: number;
    flagged: number;
    campaigns: number;
    apps: number;
    messages: number;
    live: number;
    offline: number;
  };
  verdicts: Partial<Record<Verdict, number>>;
  review: Partial<Record<ReviewStatus, number>>;
  sources: Partial<Record<SourceType, number>>;
  brands: Record<string, number>;
  top_signals: Record<string, number>;
  detections_per_day: { date: string; count: number }[];
  takedowns: {
    by_status: Partial<Record<TakedownStatus, number>>;
    open: number;
    median_hours_to_resolution: number | null;
  };
  review_queue: { id: string; url: string; risk_score: number; brand: string | null }[];
}

export interface CandidateFilters {
  min_score?: number;
  verdict?: Verdict;
  brand?: string;
  source?: SourceType;
  campaign_id?: string;
  kind?: CandidateKind;
  live?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
}
