import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { IngestPage } from "../pages/IngestPage";
import { JobsPage } from "../pages/JobsPage";
import { job, mockApi } from "./fixtures";

const page = () =>
  render(
    <MemoryRouter>
      <IngestPage />
    </MemoryRouter>,
  );

describe("Report page", () => {
  it("checks a single link and links to the result", async () => {
    const calls = mockApi({ "/ingest/url": { job_id: "j", status: "done", candidate_ids: ["c1"], extracted: {}, job_ids: [] } });
    page();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Suspicious link"), "http://sbi-kyc.top");
    await user.click(screen.getByRole("button", { name: "Check link" }));
    expect(await screen.findByRole("link", { name: "view result 1" })).toHaveAttribute("href", "/detections/c1");
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({ url: "http://sbi-kyc.top", source: "user_report" });
  });

  it("shows what was extracted from a message and APK follow-ups", async () => {
    mockApi({
      "/ingest/message": {
        job_id: "j", status: "done", candidate_ids: ["m1"], job_ids: ["app-job"],
        extracted: { urls: [], upi_ids: ["sbi.kyc@ybl"], phones: ["9876543210"], telegram: [] },
      },
    });
    page();
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "SMS / WhatsApp" }));
    await user.type(screen.getByLabelText("Message text"), "Pay Rs 10 to sbi.kyc@ybl");
    await user.click(screen.getByRole("button", { name: "Analyse message" }));
    expect(await screen.findByText("sbi.kyc@ybl")).toBeInTheDocument();
    expect(screen.getByText(/An Android app link was found/)).toBeInTheDocument();
  });

  it("counts bulk links and reports API errors", async () => {
    mockApi({ "/ingest/batch": { detail: "missing or invalid X-API-Key header" } }, 401);
    page();
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Many links" }));
    await user.type(screen.getByLabelText("Links"), "http://a.top\nhttp://b.top");
    expect(screen.getByText(/2 detected/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check 2 links" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/API key/);
  });
});

describe("Jobs page", () => {
  it("shows progress, failures and results", async () => {
    mockApi({
      "/jobs": [
        job(),
        job({ id: "j2", kind: "ingest_app_url", status: "failed", params: { url: "http://x.top/a.apk" },
          error: "ConnectError: Name or service not known", progress: { total: 1, processed: 0, failed: 0 } }),
        job({ id: "j3", kind: "crawl_ct", status: "done", params: { keywords: ["phonepe"] }, candidate_ids: ["c9"],
          progress: { total: 1, processed: 1, failed: 0 } }),
      ],
    });
    render(
      <MemoryRouter initialEntries={["/jobs?highlight=j3"]}>
        <JobsPage />
      </MemoryRouter>,
    );
    expect(await screen.findByText("Check many links")).toBeInTheDocument();
    expect(screen.getByText("1/4")).toBeInTheDocument();
    expect(screen.getByText(/Name or service not known/)).toBeInTheDocument();
    const result = screen.getByRole("link", { name: "View result" });
    expect(result).toHaveAttribute("href", "/detections/c9");
    expect(result.closest("tr")).toHaveClass("row-highlight");
  });
});
