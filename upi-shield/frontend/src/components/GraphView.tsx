import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";

import type { GraphResponse } from "../api/types";
import { humanize } from "../lib/format";

const ENTITY_COLORS: Record<string, string> = {
  upi_id: "#7c3aed",
  phone: "#db2777",
  telegram: "#0891b2",
  ip: "#475569",
  asn: "#94a3b8",
  cert_fingerprint: "#64748b",
  registrar: "#94a3b8",
  favicon_hash: "#ca8a04",
  analytics_id: "#ea580c",
  domain: "#0ea5e9",
  package_name: "#16a34a",
  apk_sha256: "#16a34a",
  signing_cert: "#15803d",
};

const VERDICT_COLORS: Record<string, string> = { malicious: "#c62828", suspicious: "#e08a00", benign: "#1b7f4b" };

const LEGEND: [string, string][] = [
  ["Malicious asset", VERDICT_COLORS.malicious!],
  ["Suspicious asset", VERDICT_COLORS.suspicious!],
  ["UPI handle", ENTITY_COLORS.upi_id!],
  ["Phone number", ENTITY_COLORS.phone!],
  ["Hosting / network", ENTITY_COLORS.ip!],
  ["Shared asset (favicon, analytics)", ENTITY_COLORS.favicon_hash!],
  ["App package / certificate", ENTITY_COLORS.package_name!],
];

function truncate(text: string, max = 26): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function toElements(graph: GraphResponse): ElementDefinition[] {
  const ids = new Set(graph.nodes.map((n) => n.id));
  const nodes: ElementDefinition[] = graph.nodes.map((n) => {
    const isAsset = n.candidate_id !== null;
    return {
      data: {
        id: n.id,
        label: truncate(n.label),
        fullLabel: n.label,
        type: n.type,
        candidateId: n.candidate_id ?? "",
        color: isAsset ? VERDICT_COLORS[n.verdict ?? "suspicious"] : ENTITY_COLORS[n.type] ?? "#94a3b8",
        size: isAsset ? 34 : 14 + Math.min(14, (n.degree ?? 1) * 3),
        shape: n.kind === "app" ? "round-rectangle" : n.kind === "message" ? "diamond" : "ellipse",
      },
      classes: [isAsset ? "asset" : "entity", n.linking === false ? "non-linking" : ""].join(" "),
    };
  });
  const edges: ElementDefinition[] = graph.edges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, relation: humanize(e.relation) } }));
  return [...nodes, ...edges];
}

/**
 * Interactive infrastructure graph. Large nodes are websites, apps and messages
 * (coloured by verdict); small nodes are the indicators they share. Dashed, faded
 * indicators are shared by unrelated parties (CDN IPs, registrars) and do not link
 * campaigns. Clicking an asset opens its detection.
 */
export function GraphView({ graph, onOpenCandidate, height = 460 }: {
  graph: GraphResponse;
  onOpenCandidate?: (candidateId: string) => void;
  height?: number;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [hover, setHover] = useState<string>();
  const elements = useMemo(() => toElements(graph), [graph]);
  const openRef = useRef(onOpenCandidate);

  useEffect(() => {
    openRef.current = onOpenCandidate;
  });

  useEffect(() => {
    if (!container.current) return;
    const instance = cytoscape({
      container: container.current,
      elements,
      wheelSensitivity: 0.3,
      minZoom: 0.2,
      maxZoom: 3,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            width: "data(size)",
            height: "data(size)",
            shape: "data(shape)" as never,
            label: "data(label)",
            "font-size": 10,
            color: "#1c2333",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.8,
            "text-background-padding": "2px",
          },
        },
        { selector: "node.asset", style: { "font-size": 11, "font-weight": "bold", "border-width": 3, "border-color": "#ffffff" } },
        { selector: "node.non-linking", style: { opacity: 0.45, "border-style": "dashed", "border-width": 1, "border-color": "#475569" } },
        { selector: "edge", style: { width: 1.5, "line-color": "#cbd5e1", "curve-style": "bezier" } },
        { selector: "node:selected", style: { "border-width": 4, "border-color": "#4f46e5" } },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, padding: 20 },
    });
    instance.on("tap", "node.asset", (event) => {
      const id = event.target.data("candidateId") as string;
      if (id) openRef.current?.(id);
    });
    instance.on("mouseover", "node", (event) => {
      const data = event.target.data();
      setHover(`${humanize(data.type)}: ${data.fullLabel}`);
    });
    instance.on("mouseout", "node", () => setHover(undefined));
    cy.current = instance;
    return () => {
      instance.destroy();
      cy.current = null;
    };
  }, [elements]);

  const assets = graph.nodes.filter((n) => n.candidate_id).length;
  const indicators = graph.nodes.length - assets;

  return (
    <div className="graph">
      <div className="graph-toolbar row">
        <span className="muted">
          {assets} asset{assets === 1 ? "" : "s"} · {indicators} indicator{indicators === 1 ? "" : "s"}
        </span>
        <span className="graph-hover" aria-live="polite">{hover ?? "Hover a node for details; click a large node to open it."}</span>
        <button type="button" className="btn btn-small" onClick={() => cy.current?.fit(undefined, 20)}>
          Fit to view
        </button>
      </div>
      <div
        ref={container}
        className="graph-canvas"
        style={{ height }}
        role="img"
        aria-label={`Infrastructure graph with ${assets} assets and ${indicators} shared indicators`}
      />
      <ul className="graph-legend" aria-label="Legend">
        {LEGEND.map(([label, color]) => (
          <li key={label}>
            <span className="legend-dot" style={{ background: color }} />
            {label}
          </li>
        ))}
        <li>
          <span className="legend-dot legend-faded" />
          Shared by unrelated sites (does not link)
        </li>
      </ul>
    </div>
  );
}
