import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { api } from "../api/client";
import { Icon, type IconName } from "./icons";
import { useApi } from "../lib/useApi";

export interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  description: string;
}

export function Layout({ items }: { items: NavItem[] }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const health = useApi(() => api.health(), [], 30_000);
  const current = items.find((i) => (i.to === "/" ? location.pathname === "/" : location.pathname.startsWith(i.to)));

  return (
    <div className={`shell ${menuOpen ? "menu-open" : ""}`}>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Main navigation">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={28} height={28} />
          <div>
            <strong>UPI Shield</strong>
            <span>Fraud detection</span>
          </div>
        </div>
        <nav>
          {items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
              onClick={() => setMenuOpen(false)}
              title={item.description}
            >
              <span className="nav-icon">
                <Icon name={item.icon} />
              </span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className={`status-dot ${health.error ? "down" : health.data ? "up" : ""}`} aria-hidden="true" />
          {health.error ? "API unreachable" : health.data ? "API connected" : "Connecting…"}
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <button
            type="button"
            className="menu-button"
            aria-label="Open navigation"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((open) => !open)}
          >
            <Icon name="menu" size={22} />
          </button>
          <span className="topbar-title">{current?.label ?? "UPI Shield"}</span>
          {health.data && (
            <span className="topbar-meta muted">
              {health.data.candidates} detections · {health.data.campaigns} campaigns
            </span>
          )}
        </header>
        <main id="main" className="content">
          <Outlet />
        </main>
      </div>
      {menuOpen && <div className="backdrop" onClick={() => setMenuOpen(false)} aria-hidden="true" />}
    </div>
  );
}
