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
