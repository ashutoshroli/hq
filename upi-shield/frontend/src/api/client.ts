import type {
  AuditEvent,
  Campaign,
  Candidate,
  CandidateFilters,
  DashboardSummary,
  EvalMetrics,
  GraphResponse,
  IngestResponse,
  Job,
  Recipient,
  ReviewStatus,
  SourceType,
  TakedownCase,
  TakedownPlan,
  TakedownReport,
  TakedownStatus,
} from "./types";

/** Base path of the backend API; Vite (dev) and nginx (prod) proxy it to FastAPI. */
export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "/api";

const API_KEY_STORAGE = "upi-shield.api-key";
const ANALYST_STORAGE = "upi-shield.analyst";

export const settings = {
  getApiKey: (): string => localStorage.getItem(API_KEY_STORAGE) ?? "",
  setApiKey: (value: string) =>
    value ? localStorage.setItem(API_KEY_STORAGE, value) : localStorage.removeItem(API_KEY_STORAGE),
  getAnalyst: (): string => localStorage.getItem(ANALYST_STORAGE) ?? "analyst",
  setAnalyst: (value: string) => localStorage.setItem(ANALYST_STORAGE, value || "analyst"),
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function query(params: object = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const key = settings.getApiKey();
  if (key) headers.set("X-API-Key", key);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the UPI Shield API. Check that the backend is running.");
  }
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* keep the status line */
    }
    if (response.status === 401) message = "This action needs a valid API key. Add it in Settings.";
    throw new ApiError(response.status, message);
  }
  const type = response.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? response.json() : response.text()) as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export const api = {
  health: () => request<{ status: string; candidates: number; campaigns: number }>("/health"),
  summary: (days = 14) => request<DashboardSummary>(`/dashboard/summary${query({ days })}`),

  candidates: (filters: CandidateFilters = {}) => request<Candidate[]>(`/candidates${query(filters)}`),
  candidate: (id: string) => request<Candidate>(`/candidates/${encodeURIComponent(id)}`),
  review: (id: string, status: ReviewStatus, note?: string) =>
    post<Candidate>(`/candidates/${encodeURIComponent(id)}/review`, {
      status,
      note: note || null,
      analyst: settings.getAnalyst(),
    }),
  audit: (target?: string) => request<AuditEvent[]>(`/audit${query({ target })}`),

  campaigns: () => request<Campaign[]>("/campaigns"),
  campaign: (id: string) => request<Campaign>(`/campaigns/${encodeURIComponent(id)}`),
  graph: (campaignId?: string, includeBenign = false) =>
    request<GraphResponse>(`/graph${query({ campaign_id: campaignId, include_benign: includeBenign || undefined })}`),
  pivot: (type: string, value: string) => request<Candidate[]>(`/pivot${query({ type, value })}`),

  ingestUrl: (url: string, source: SourceType = "user_report") =>
    post<IngestResponse>("/ingest/url", { url, source }),
  ingestMessage: (text: string, source: SourceType = "message") =>
    post<IngestResponse>("/ingest/message", { text, source }),
  ingestBatch: (urls: string[], source: SourceType = "feed") => post<IngestResponse>("/ingest/batch", { urls, source }),
  ingestFeed: (feed: "openphish" | "urlhaus", limit: number, brandFilter = true) =>
    post<IngestResponse>("/ingest/feed", { feed, limit, brand_filter: brandFilter }),
  ingestAppUrl: (url: string) => post<IngestResponse>("/ingest/app/url", { url }),
  uploadApp: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<IngestResponse>("/ingest/app", { method: "POST", body: form });
  },
  crawl: (keywords: string[], maxHosts?: number) =>
    post<IngestResponse>("/crawl/ct", { keywords: keywords.length ? keywords : null, max_hosts: maxHosts ?? null }),
  jobs: (limit = 50) => request<Job[]>(`/jobs${query({ limit })}`),
  job: (id: string) => request<Job>(`/jobs/${encodeURIComponent(id)}`),

  takedownReport: (campaignId: string, recipient: Recipient) =>
    post<TakedownReport>("/reports/takedown", { campaign_id: campaignId, recipient }),
  takedownPlan: (campaignId: string) =>
    request<TakedownPlan>(`/campaigns/${encodeURIComponent(campaignId)}/takedown-plan`),
  takedowns: (campaignId?: string) => request<TakedownCase[]>(`/takedowns${query({ campaign_id: campaignId })}`),
  createTakedown: (campaignId: string, recipient: Recipient, contact?: string, targets?: string[]) =>
    post<TakedownCase>("/takedowns", {
      campaign_id: campaignId,
      recipient,
      contact: contact || null,
      targets: targets?.length ? targets : null,
      analyst: settings.getAnalyst(),
    }),
  updateTakedown: (id: string, status: TakedownStatus, note?: string) =>
    request<TakedownCase>(`/takedowns/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status, note: note || null, analyst: settings.getAnalyst() }),
    }),
  recheckTakedown: (id: string) => post<TakedownCase>(`/takedowns/${encodeURIComponent(id)}/recheck`),
  exportUrl: (campaignId: string, format: "markdown" | "json" | "stix" | "zip") =>
    `${API_BASE}/campaigns/${encodeURIComponent(campaignId)}/export${query({ format })}`,
  evidenceUrl: (path: string) => `${API_BASE}${path}`,

  metrics: () => request<EvalMetrics>("/eval/metrics"),
  seedDemo: () => post<{ candidates: number; campaigns: number }>("/admin/seed"),
};
