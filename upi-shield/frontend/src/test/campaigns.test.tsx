import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Campaign, GraphResponse, TakedownCase, TakedownPlan } from "../api/types";
import { toElements } from "../components/GraphView";
import { CampaignDetailPage } from "../pages/CampaignDetailPage";
import { CampaignsPage } from "../pages/CampaignsPage";
import { EvaluationPage } from "../pages/EvaluationPage";
import { candidate, mockApi } from "./fixtures";

// Cytoscape needs a real canvas; tests check the data passed to it instead.
const cyMock = vi.hoisted(() => ({ calls: [] as unknown[] }));
vi.mock("cytoscape", () => ({
  default: (options: unknown) => {
    cyMock.calls.push(options);
    return { on: () => undefined, destroy: () => undefined, fit: () => undefined };
  },
}));

const campaign: Campaign = {
  id: "camp-1",
  name: "Campaign targeting paytm, phonepe",
  first_seen: "2026-10-07T05:00:00Z",
  last_seen: "2026-10-07T10:00:00Z",
  size: 2,
  brands_targeted: ["paytm", "phonepe"],
  candidate_ids: ["seed1", "seed3"],
  shared_entities: [
    { type: "upi_id", value: "rewards.help@okaxis" },
    { type: "registrar", value: "GoDaddy" },
  ],
};

const graph: GraphResponse = {
  nodes: [
    { id: "domain:phonepe-kyc-verify.xyz", type: "domain", label: "phonepe-kyc-verify.xyz", campaign_id: "camp-1",
      candidate_id: "seed1", kind: "web", risk_score: 0.92, verdict: "malicious", brand: "phonepe", linking: null, degree: null },
    { id: "upi_id:rewards.help@okaxis", type: "upi_id", label: "rewards.help@okaxis", campaign_id: "camp-1",
      candidate_id: null, kind: null, risk_score: null, verdict: null, brand: null, linking: true, degree: 2 },
    { id: "ip:104.17.1.1", type: "ip", label: "104.17.1.1", campaign_id: "camp-1",
      candidate_id: null, kind: null, risk_score: null, verdict: null, brand: null, linking: false, degree: 2 },
  ],
  edges: [
    { source: "domain:phonepe-kyc-verify.xyz", target: "upi_id:rewards.help@okaxis", relation: "collects_payments_to" },
    { source: "domain:phonepe-kyc-verify.xyz", target: "missing", relation: "uses" },
  ],
};

const plan: TakedownPlan = {
  campaign_id: "camp-1",
  generated_at: "2026-10-07T10:00:00Z",
  items: [
    { recipient: "registrar", channel: "email", contacts: ["abuse@reg.example"], targets: ["phonepe-kyc-verify.xyz"],
      rationale: "Suspend the domain registrations held at Reg Inc" },
    { recipient: "bank", channel: "lookup_required", contacts: [], targets: ["http://phonepe-kyc-verify.xyz/login"],
      rationale: "Notify PhonePe (no published phishing-report address verified)" },
  ],
};

function takedownCase(overrides: Partial<TakedownCase> = {}): TakedownCase {
  return {
    id: "td-1", campaign_id: "camp-1", recipient: "registrar", contact: "abuse@reg.example", status: "drafted",
    targets: ["phonepe-kyc-verify.xyz"],
    report: { campaign_id: "camp-1", recipient: "registrar", generated_at: "2026-10-07T10:00:00Z",
      subject: "Phishing takedown request", body: "Please suspend the domains listed below." },
    created_at: "2026-10-07T10:00:00Z", updated_at: "2026-10-07T10:00:00Z", sent_at: null, resolved_at: null,
    checks: [], notes: [], ...overrides,
  };
}

beforeEach(() => {
  cyMock.calls.length = 0;
});

describe("Graph data", () => {
  it("styles assets by verdict, marks non-linking indicators and drops dangling edges", () => {
    const elements = toElements(graph);
    const asset = elements.find((e) => e.data.id === "domain:phonepe-kyc-verify.xyz");
    expect(asset?.data.color).toBe("#c62828");
    expect(asset?.classes).toContain("asset");
    expect(elements.find((e) => e.data.id === "ip:104.17.1.1")?.classes).toContain("non-linking");
    expect(elements.filter((e) => e.data.source)).toHaveLength(1);
  });
});

describe("Campaigns list", () => {
  it("shows each campaign with its brands and strong links only", async () => {
    mockApi({ "/campaigns": [campaign] });
    render(<MemoryRouter><CampaignsPage /></MemoryRouter>);
    const card = (await screen.findByRole("heading", { name: "Paytm, PhonePe" })).closest("a") as HTMLElement;
    expect(card).toHaveAttribute("href", "/campaigns/camp-1");
    expect(within(card).getByText("2 assets")).toBeInTheDocument();
    expect(within(card).getByText("rewards.help@okaxis")).toBeInTheDocument();
    expect(within(card).queryByText("GoDaddy")).not.toBeInTheDocument();
  });

  it("loads the infrastructure map on request", async () => {
    mockApi({ "/campaigns": [campaign], "/graph": graph });
    render(<MemoryRouter><CampaignsPage /></MemoryRouter>);
    await userEvent.setup().click(await screen.findByRole("button", { name: "Show infrastructure map" }));
    expect(await screen.findByRole("img", { name: /1 assets and 2 shared indicators/ })).toBeInTheDocument();
    expect(cyMock.calls).toHaveLength(1);
  });
});

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={["/campaigns/camp-1"]}>
      <Routes><Route path="/campaigns/:id" element={<CampaignDetailPage />} /></Routes>
    </MemoryRouter>,
  );
}

describe("Campaign detail", () => {
  it("shows links, members, the takedown plan and exports", async () => {
    mockApi({
      "/campaigns/camp-1/takedown-plan": plan, "/campaigns/camp-1": campaign, "/takedowns": [],
      "/candidates": [candidate(), candidate({ id: "seed3", url: "http://paytm-cashback-claim.click", live: false })],
      "/graph": graph,
    });
    renderDetail();
    expect(await screen.findByRole("heading", { name: "Campaign targeting Paytm, PhonePe" })).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "http://paytm-cashback-claim.click" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "STIX 2.1" })).toHaveAttribute("href", "/api/campaigns/camp-1/export?format=stix");
    expect(await screen.findByText("Domain registrar")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "abuse@reg.example" })).toHaveAttribute("href", "mailto:abuse@reg.example");
    expect(screen.getByText("Contact needed")).toBeInTheDocument();
  });

  it("starts a takedown and moves it through its lifecycle", async () => {
    const routes: Record<string, unknown> = {
      "/campaigns/camp-1/takedown-plan": plan, "/campaigns/camp-1": campaign, "/takedowns": [],
      "/candidates": [candidate()], "/graph": graph,
    };
    const calls = mockApi(routes);
    renderDetail();
    const user = userEvent.setup();
    routes["/takedowns"] = [takedownCase()];
    await user.click((await screen.findAllByRole("button", { name: "Start takedown" }))[0]!);
    const create = calls.find((c) => c.url === "/api/takedowns" && c.init?.method === "POST");
    expect(JSON.parse(String(create?.init?.body))).toMatchObject({ campaign_id: "camp-1", recipient: "registrar",
      contact: "abuse@reg.example", targets: ["phonepe-kyc-verify.xyz"] });
    expect(await screen.findByText("Please suspend the domains listed below.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open in e-mail" }).getAttribute("href")).toMatch(/^mailto:abuse@reg\.example\?subject=/);

    routes["/takedowns/td-1"] = takedownCase({ status: "sent" });
    routes["/takedowns"] = [takedownCase({ status: "sent" })];
    await user.click(screen.getByRole("button", { name: "Mark sent" }));
    expect(await screen.findByRole("button", { name: "Check if still live" })).toBeInTheDocument();
    expect(calls.some((c) => c.url === "/api/takedowns/td-1" && c.init?.method === "PATCH")).toBe(true);

    routes["/takedowns/td-1/recheck"] = takedownCase({ status: "resolved",
      checks: [{ target: "http://phonepe-kyc-verify.xyz/", checked_at: "2026-10-07T11:00:00Z", live: false, detail: "gone" }] });
    routes["/takedowns"] = [routes["/takedowns/td-1/recheck"]];
    await user.click(screen.getByRole("button", { name: "Check if still live" }));
    expect(await screen.findByText(/all targets offline/)).toBeInTheDocument();
  });

  it("explains a campaign that no longer exists", async () => {
    globalThis.fetch = (async () => new Response(JSON.stringify({ detail: "campaign not found" }), { status: 404 })) as typeof fetch;
    renderDetail();
    expect(await screen.findByText("Campaign not found")).toBeInTheDocument();
  });
});

describe("Accuracy page", () => {
  it("leads with the held-out benchmark in plain language", async () => {
    mockApi({
      "/eval/metrics": {
        sample_size: 31, is_placeholder: false,
        stages: [{ stage: "full", precision: 1, recall: 1, f1: 1 }],
        benchmarks: [
          { name: "real", description: "Real-world lookalike hosts.", split: "test", stage: "url_only", threshold: 0.7,
            sample_size: 1360, positives: 27, negatives: 1333, precision: 0.875, recall: 0.7778, f1: 0.8235,
            tp: 21, fp: 3, fn: 6, tn: 1330, false_positive_rate: 0.0023, collected: "2026-10-07" },
        ],
      },
    });
    render(<MemoryRouter><EvaluationPage /></MemoryRouter>);
    const precision = (await screen.findByText("Precision", { selector: ".stat-label" })).closest(".stat") as HTMLElement;
    expect(within(precision).getByText("87.5%")).toBeInTheDocument();
    expect(screen.getByText("21 of 27 phishing hosts were caught")).toBeInTheDocument();
    expect(screen.getByText("Test (reported)")).toBeInTheDocument();
    expect(screen.getByText(/Full pipeline/)).toBeInTheDocument();
  });
});

describe("Takedown plan matching", () => {
  it("ties a case to the plan item with the same recipient and targets", async () => {
    const { matchesPlanItem } = await import("../pages/CampaignDetailPage");
    const phonepe = { recipient: "bank" as const, channel: "lookup_required", contacts: [], rationale: "",
      targets: ["http://phonepe-kyc-verify.xyz/login"] };
    const paytm = { ...phonepe, targets: ["http://paytm-cashback-claim.click"] };
    const started = takedownCase({ recipient: "bank", contact: null, targets: ["http://phonepe-kyc-verify.xyz/login"] });
    expect(matchesPlanItem(started, phonepe)).toBe(true);
    expect(matchesPlanItem(started, paytm)).toBe(false);
  });
});
