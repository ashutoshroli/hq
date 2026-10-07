import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { DetectionDetailPage } from "../pages/DetectionDetailPage";
import { DetectionsPage } from "../pages/DetectionsPage";
import { candidate, mockApi } from "./fixtures";

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.search}</output>;
}

function renderList(path = "/detections") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/detections" element={<><DetectionsPage /><LocationProbe /></>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Detections list", () => {
  it("lists detections with their verdict, review and status", async () => {
    const app = candidate({ id: "a1", kind: "app", url: "android://com.f", domain: "com.f",
      app: { package: "com.f", label: "Fake YONO", version: "1", sha256: "ab", permissions: [], cert_sha256: [], origin_url: null } });
    mockApi({ "/candidates": [candidate(), app] });
    renderList();
    const link = await screen.findByRole("link", { name: "http://phonepe-kyc-verify.xyz/login" });
    expect(link).toHaveAttribute("href", "/detections/seed1");
    expect(screen.getByRole("link", { name: "Fake YONO (com.f)" })).toBeInTheDocument();
    const row = link.closest("tr") as HTMLElement;
    expect(within(row).getByText("Malicious")).toBeInTheDocument();
    expect(within(row).getByText("Not reviewed")).toBeInTheDocument();
    expect(within(row).getByText("Live")).toBeInTheDocument();
  });

  it("passes URL filters to the API and updates them from the controls", async () => {
    const calls = mockApi({ "/candidates": [candidate()] });
    renderList("/detections?review=unreviewed");
    await screen.findByRole("link", { name: /phonepe-kyc-verify/ });
    expect(calls[0]?.url).toContain("review=unreviewed");
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText("Verdict"), "malicious");
    expect(screen.getByTestId("location")).toHaveTextContent("verdict=malicious");
    expect(calls.at(-1)?.url).toContain("verdict=malicious");
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByTestId("location")).toHaveTextContent("");
  });

  it("explains an empty result", async () => {
    mockApi({ "/candidates": [] });
    renderList("/detections?brand=sbi");
    expect(await screen.findByText("No detections match these filters")).toBeInTheDocument();
  });
});

function renderDetail(id = "seed1") {
  return render(
    <MemoryRouter initialEntries={[`/detections/${id}`]}>
      <Routes>
        <Route path="/detections/:id" element={<DetectionDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Detection detail", () => {
  it("shows evidence ordered by weight, the screenshot and campaign link", async () => {
    mockApi({ "/candidates/seed1": candidate(), "/audit": [] });
    renderDetail();
    expect(await screen.findByRole("heading", { name: "phonepe-kyc-verify.xyz" })).toBeInTheDocument();
    const evidence = screen.getAllByRole("listitem").filter((li) => li.closest(".evidence"));
    expect(evidence[0]).toHaveTextContent("Brand in unofficial domain");
    expect(evidence.at(-1)).toHaveTextContent("info");
    expect(screen.getByRole("img", { name: /Screenshot of phonepe-kyc-verify\.xyz/ })).toHaveAttribute(
      "src", "/api/evidence/0123456789abcdef01234567.png");
    expect(screen.getByRole("link", { name: "View campaign" })).toHaveAttribute("href", "/campaigns/camp-1");
  });

  it("records a review with a note and refreshes the status", async () => {
    const calls = mockApi({
      "/candidates/seed1/review": candidate({ review_status: "false_positive", reviewed_by: "analyst", review_note: "partner" }),
      "/candidates/seed1": candidate(),
      "/audit": [],
    });
    renderDetail();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Note (optional)"), "partner");
    await user.click(screen.getByRole("button", { name: "Mark as false positive" }));
    expect(await screen.findByText("False positive")).toBeInTheDocument();
    const review = calls.find((c) => c.url.endsWith("/review"));
    expect(JSON.parse(String(review?.init?.body))).toMatchObject({ status: "false_positive", note: "partner" });
    expect(screen.queryByRole("button", { name: "Mark as false positive" })).not.toBeInTheDocument();
  });

  it("finds other detections that share an indicator", async () => {
    mockApi({
      "/candidates/seed1": candidate(),
      "/audit": [],
      "/pivot": [candidate(), candidate({ id: "seed3", url: "http://paytm-cashback-claim.click" })],
    });
    renderDetail();
    await userEvent.setup().click(await screen.findByRole("button", { name: "rewards.help@okaxis" }));
    expect(await screen.findByRole("link", { name: "http://paytm-cashback-claim.click" })).toHaveAttribute(
      "href", "/detections/seed3");
  });

  it("handles a missing detection", async () => {
    mockApi({});
    globalThis.fetch = (async () => new Response(JSON.stringify({ detail: "candidate not found" }), { status: 404 })) as typeof fetch;
    renderDetail("nope");
    expect(await screen.findByText("Detection not found")).toBeInTheDocument();
  });
});
