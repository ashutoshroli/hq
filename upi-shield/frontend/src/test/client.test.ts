import { describe, expect, it } from "vitest";

import { ApiError, api, settings } from "../api/client";
import { mockApi } from "./fixtures";

describe("API client", () => {
  it("sends the API key and analyst name with reviews", async () => {
    settings.setApiKey("s3cret");
    settings.setAnalyst("asha");
    const calls = mockApi({ "/candidates/seed1/review": { id: "seed1" } });
    await api.review("seed1", "confirmed", "checked");
    const [call] = calls;
    expect(call?.url).toBe("/api/candidates/seed1/review");
    expect(new Headers(call?.init?.headers).get("X-API-Key")).toBe("s3cret");
    expect(JSON.parse(String(call?.init?.body))).toEqual({ status: "confirmed", note: "checked", analyst: "asha" });
  });

  it("builds query strings without empty filters", async () => {
    const calls = mockApi({ "/candidates": [] });
    await api.candidates({ verdict: "malicious", q: "", limit: 20 });
    expect(calls[0]?.url).toBe("/api/candidates?verdict=malicious&limit=20");
  });

  it("explains authentication failures", async () => {
    mockApi({ "/takedowns": { detail: "missing or invalid X-API-Key header" } }, 401);
    await expect(api.createTakedown("camp-1", "registrar")).rejects.toThrow(/API key/);
  });

  it("reports an unreachable backend clearly", async () => {
    globalThis.fetch = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;
    const error = await api.health().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).message).toMatch(/Cannot reach/);
  });
});
