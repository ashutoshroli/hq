import { describe, expect, it } from "vitest";

import { assetLabel, brandName, humanize, percent, timeAgo } from "../lib/format";

describe("format helpers", () => {
  it("humanizes signal names", () => {
    expect(humanize("brand_in_unofficial_domain")).toBe("Brand in unofficial domain");
  });

  it("names brands and falls back to the key", () => {
    expect(brandName("hdfc")).toBe("HDFC Bank");
    expect(brandName("newbank")).toBe("newbank");
    expect(brandName(null)).toBe("Unknown brand");
  });

  it("formats percentages and missing values", () => {
    expect(percent(0.875, 1)).toBe("87.5%");
    expect(percent(null)).toBe("—");
  });

  it("describes elapsed time", () => {
    const now = new Date("2026-10-07T12:00:00Z");
    expect(timeAgo("2026-10-07T11:59:30Z", now)).toBe("just now");
    expect(timeAgo("2026-10-07T09:00:00Z", now)).toBe("3 hours ago");
    expect(timeAgo("2026-10-06T12:00:00Z", now)).toBe("1 day ago");
  });

  it("labels apps and messages by their content", () => {
    expect(assetLabel({ kind: "web", url: "http://x.top" })).toBe("http://x.top");
    expect(assetLabel({ kind: "app", url: "android://a", app: { label: "Fake", package: "com.f" } })).toBe(
      "Fake (com.f)",
    );
    expect(assetLabel({ kind: "message", url: "message://1", message: { excerpt: "Pay now" } })).toBe("“Pay now”");
  });
});
