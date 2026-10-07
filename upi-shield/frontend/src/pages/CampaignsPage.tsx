import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { Campaign } from "../api/types";
import { LazyGraphView as GraphView } from "../components/LazyGraphView";
import { Badge, Card, EmptyState, ErrorBanner, PageHeader, Spinner } from "../components/ui";
import { brandName, dateTime, entityLabel, timeAgo } from "../lib/format";
import { useApi } from "../lib/useApi";

function CampaignCard({ campaign }: { campaign: Campaign }) {
  const strong = campaign.shared_entities.filter((e) => !["registrar", "asn"].includes(e.type));
  return (
    <Link to={`/campaigns/${campaign.id}`} className="campaign-card card">
      <div className="campaign-card-head">
        <h2>{campaign.brands_targeted.length ? campaign.brands_targeted.map(brandName).join(", ") : "Unknown brand"}</h2>
        <Badge tone="accent">{campaign.size} assets</Badge>
      </div>
      <p className="muted">
        Active {timeAgo(campaign.last_seen)} · first seen {dateTime(campaign.first_seen)}
      </p>
      <div>
        <span className="muted small-caps">Linked by</span>
        <ul className="chips">
          {strong.slice(0, 4).map((e) => (
            <li key={`${e.type}:${e.value}`}>
              <span className="chip chip-static" title={entityLabel(e.type)}>
                {e.value}
              </span>
            </li>
          ))}
          {strong.length > 4 && <li className="muted">+{strong.length - 4} more</li>}
        </ul>
      </div>
    </Link>
  );
}

export function CampaignsPage() {
  const navigate = useNavigate();
  const [showMap, setShowMap] = useState(false);
  const campaigns = useApi(() => api.campaigns(), []);
  const graph = useApi(() => (showMap ? api.graph() : Promise.resolve(undefined)), [showMap]);

  return (
    <>
      <PageHeader
        title="Campaigns"
        subtitle="Groups of sites, apps and messages run by the same operators, linked by shared UPI handles, phone numbers, hosting and assets."
        actions={
          <button type="button" className="btn" aria-pressed={showMap} onClick={() => setShowMap((v) => !v)}>
            {showMap ? "Hide infrastructure map" : "Show infrastructure map"}
          </button>
        }
      />
      {showMap && (
        <Card title="Infrastructure map (all flagged assets)">
          {graph.error && <ErrorBanner message={graph.error} onRetry={graph.reload} />}
          {graph.data ? (
            <GraphView graph={graph.data} onOpenCandidate={(id) => navigate(`/detections/${id}`)} height={520} />
          ) : (
            !graph.error && <Spinner label="Building the map…" />
          )}
        </Card>
      )}
      {campaigns.error && <ErrorBanner message={campaigns.error} onRetry={campaigns.reload} />}
      {!campaigns.data && !campaigns.error && <Spinner />}
      {campaigns.data?.length === 0 && (
        <Card>
          <EmptyState title="No campaigns yet">
            Campaigns form automatically when two or more detections share infrastructure such as a UPI handle or phone number.
          </EmptyState>
        </Card>
      )}
      {campaigns.data && campaigns.data.length > 0 && (
        <div className="campaign-grid">
          {[...campaigns.data]
            .sort((a, b) => b.last_seen.localeCompare(a.last_seen))
            .map((c) => (
              <CampaignCard key={c.id} campaign={c} />
            ))}
        </div>
      )}
    </>
  );
}
