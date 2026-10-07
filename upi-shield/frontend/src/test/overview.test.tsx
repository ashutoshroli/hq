import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import { mockApi, summary } from "./fixtures";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("Overview page", () => {
  it("shows totals, breakdowns and the review queue", async () => {
    mockApi({ "/dashboard/summary": summary, "/health": { status: "ok", candidates: 8, campaigns: 2 } });
    renderAt("/");
    const flagged = (await screen.findByText("Threats flagged")).closest(".stat") as HTMLElement;
    expect(within(flagged).getByText("6")).toBeInTheDocument();
    expect(within(flagged).getByText("of 8 analysed")).toBeInTheDocument();
    const brands = screen.getByRole("heading", { name: "Brands targeted" }).closest(".card") as HTMLElement;
    expect(within(brands).getByText("PhonePe")).toBeInTheDocument();
    expect(within(brands).getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Brand in unofficial domain")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /phonepe-kyc-verify\.xyz/ })).toHaveAttribute("href", "/detections/seed1");
    expect(await screen.findByText("API connected")).toBeInTheDocument();
  });

  it("offers a retry when the API is down", async () => {
    globalThis.fetch = (async () => {
      throw new TypeError("offline");
    }) as typeof fetch;
    renderAt("/");
    expect(await screen.findByRole("alert")).toHaveTextContent(/Cannot reach/);
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("shows a not-found page for unknown routes", async () => {
    mockApi({ "/health": { status: "ok", candidates: 0, campaigns: 0 } });
    renderAt("/nope");
    expect(await screen.findByText("Page not found")).toBeInTheDocument();
  });
});
