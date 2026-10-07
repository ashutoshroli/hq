import { Route, Routes } from "react-router-dom";

import { Layout, type NavItem } from "./components/Layout";
import { CampaignDetailPage } from "./pages/CampaignDetailPage";
import { CampaignsPage } from "./pages/CampaignsPage";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";
import { DetectionsPage } from "./pages/DetectionsPage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { IngestPage } from "./pages/IngestPage";
import { JobsPage } from "./pages/JobsPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Overview", icon: "overview", description: "Threat totals, trends and the review queue" },
  { to: "/detections", label: "Detections", icon: "detections", description: "All analysed sites, apps and messages" },
  { to: "/campaigns", label: "Campaigns", icon: "campaigns", description: "Linked operations, graph and takedowns" },
  { to: "/ingest", label: "Report", icon: "ingest", description: "Submit a link, message or app, or start discovery" },
  { to: "/jobs", label: "Jobs", icon: "jobs", description: "Progress of background runs" },
  { to: "/evaluation", label: "Accuracy", icon: "evaluation", description: "Precision and recall on labelled samples" },
  { to: "/settings", label: "Settings", icon: "settings", description: "Analyst name, API key and demo data" },
];

export function App() {
  return (
    <Routes>
      <Route element={<Layout items={NAV_ITEMS} />}>
        <Route index element={<OverviewPage />} />
        <Route path="detections" element={<DetectionsPage />} />
        <Route path="detections/:id" element={<DetectionDetailPage />} />
        <Route path="campaigns" element={<CampaignsPage />} />
        <Route path="campaigns/:id" element={<CampaignDetailPage />} />
        <Route path="ingest" element={<IngestPage />} />
        <Route path="evaluation" element={<EvaluationPage />} />
        <Route path="jobs" element={<JobsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
