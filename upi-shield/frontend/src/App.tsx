import { Route, Routes } from "react-router-dom";

import { Layout, type NavItem } from "./components/Layout";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Overview", icon: "overview", description: "Threat totals, trends and the review queue" },
  { to: "/settings", label: "Settings", icon: "settings", description: "Analyst name, API key and demo data" },
];

export function App() {
  return (
    <Routes>
      <Route element={<Layout items={NAV_ITEMS} />}>
        <Route index element={<OverviewPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
