import type { DashboardSummary } from "../api/types";

export const summary: DashboardSummary = {
  generated_at: "2026-10-07T10:00:00Z",
  totals: { candidates: 8, flagged: 6, campaigns: 2, apps: 1, messages: 1, live: 3, offline: 2 },
  verdicts: { malicious: 4, suspicious: 2, benign: 2 },
  review: { unreviewed: 5, confirmed: 1 },
  sources: { ct_log: 3, message: 2, user_report: 1 },
  brands: { phonepe: 3, sbi: 2, paytm: 1 },
  top_signals: { brand_in_unofficial_domain: 6, lure_keywords: 4 },
  detections_per_day: [
    { date: "2026-10-06", count: 2 },
    { date: "2026-10-07", count: 4 },
  ],
  takedowns: { by_status: { sent: 1 }, open: 1, median_hours_to_resolution: null },
  review_queue: [{ id: "seed1", url: "http://phonepe-kyc-verify.xyz/login", risk_score: 0.92, brand: "phonepe" }],
};

/** Stub ``fetch`` with a map of path prefix -> JSON body (longest prefix wins). */
export function mockApi(routes: Record<string, unknown>, status = 200) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const key = Object.keys(routes)
      .filter((prefix) => url.startsWith(`/api${prefix}`))
      .sort((a, b) => b.length - a.length)[0];
    if (key === undefined) return new Response(JSON.stringify({ detail: "Not found" }), { status: 404 });
    return new Response(JSON.stringify(routes[key]), { status, headers: { "content-type": "application/json" } });
  };
  globalThis.fetch = fetchMock as typeof fetch;
  return calls;
}

import type { Candidate, Job } from "../api/types";

export function candidate(overrides: Partial<Candidate> = {}): Candidate {
  return {
    id: "seed1",
    url: "http://phonepe-kyc-verify.xyz/login",
    domain: "phonepe-kyc-verify.xyz",
    source: "ct_log",
    first_seen: "2026-10-07T09:00:00Z",
    last_seen: null,
    sightings: 1,
    risk_score: 0.92,
    verdict: "malicious",
    brand_matched: "phonepe",
    visual_similarity: 0.97,
    screenshot_url: "/evidence/0123456789abcdef01234567.png",
    signals: [
      { name: "brand_in_unofficial_domain", weight: 0.5, detail: "'phonepe' appears in phonepe-kyc-verify.xyz" },
      { name: "official_brand_domain", weight: 0, detail: "informational" },
      { name: "lure_keywords", weight: 0.2, detail: "Contains: verify, kyc" },
    ],
    entities: [
      { type: "domain", value: "phonepe-kyc-verify.xyz" },
      { type: "upi_id", value: "rewards.help@okaxis" },
    ],
    campaign_id: "camp-1",
    kind: "web",
    app: null,
    message: null,
    infrastructure: null,
    live: true,
    review_status: "unreviewed",
    review_note: null,
    reviewed_by: null,
    reviewed_at: null,
    ...overrides,
  };
}

export function job(overrides: Partial<Job> = {}): Job {
  return {
    id: "job1",
    kind: "ingest_batch",
    status: "running",
    params: { count: 4 },
    progress: { total: 4, processed: 1, failed: 0 },
    candidate_ids: [],
    error: null,
    created_at: "2026-10-07T09:00:00Z",
    started_at: "2026-10-07T09:00:01Z",
    finished_at: null,
    ...overrides,
  };
}
