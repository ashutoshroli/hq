import { Link } from "react-router-dom";

import { api } from "../api/client";
import { BarList, DailyChart } from "../components/charts";
import { Card, EmptyState, ErrorBanner, PageHeader, ScoreBar, Spinner, StatCard } from "../components/ui";
import { SOURCE_LABELS, TAKEDOWN_LABELS, brandName, humanize } from "../lib/format";
import { useApi } from "../lib/useApi";

export function OverviewPage() {
  const { data, error, loading, reload } = useApi(() => api.summary(14), [], 60_000);

  if (error && !data) return <ErrorBanner message={error} onRetry={reload} />;
  if (!data) return <Spinner label="Loading the overview…" />;

  const { totals, takedowns } = data;
  const unreviewed = data.review.unreviewed ?? 0;
  const sla = takedowns.median_hours_to_resolution;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Fake payment pages, apps and messages detected across all sources."
        actions={
          <button type="button" className="btn" onClick={reload} disabled={loading}>
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        }
      />

      <div className="stats">
        <StatCard label="Threats flagged" value={totals.flagged} hint={`of ${totals.candidates} analysed`} tone="danger" />
        <StatCard label="Campaigns" value={totals.campaigns} hint="linked by shared infrastructure" tone="accent" />
        {totals.live + totals.offline > 0 ? (
          <StatCard
            label="Still live"
            value={totals.live}
            hint={`${totals.offline} already offline`}
            tone={totals.live ? "warning" : "success"}
          />
        ) : (
          <StatCard label="Still live" value="—" hint="not checked yet; enable live fetching" />
        )}
        <StatCard label="Awaiting review" value={unreviewed} hint="analyst decisions pending" tone="info" />
        <StatCard
          label="Open takedowns"
          value={takedowns.open}
          hint={sla === null ? "no resolved cases yet" : `median ${sla} h to resolve`}
          tone={takedowns.open ? "info" : "neutral"}
        />
      </div>

      <div className="grid grid-2">
        <Card title="Detections in the last 14 days">
          <DailyChart points={data.detections_per_day} />
        </Card>
        <Card
          title="Needs review"
          actions={
            <Link className="link" to="/detections?review=unreviewed">
              View all
            </Link>
          }
        >
          {data.review_queue.length === 0 ? (
            <EmptyState title="All caught up">Every flagged item has been reviewed.</EmptyState>
          ) : (
            <ul className="queue">
              {data.review_queue.map((item) => (
                <li key={item.id}>
                  <Link to={`/detections/${item.id}`} className="queue-link">
                    <span className="queue-url" title={item.url}>
                      {item.url.startsWith("message://") ? "Message lure" : item.url}
                    </span>
                    <span className="queue-meta">
                      <span className="muted">{brandName(item.brand)}</span>
                      <ScoreBar value={item.risk_score} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid grid-3">
        <Card title="Brands targeted">
          <BarList items={data.brands} formatLabel={brandName} />
        </Card>
        <Card title="Where threats were found">
          <BarList items={data.sources} formatLabel={(k) => SOURCE_LABELS[k as keyof typeof SOURCE_LABELS] ?? k} />
        </Card>
        <Card title="Most common evidence">
          <BarList items={data.top_signals} formatLabel={humanize} />
        </Card>
      </div>

      <Card title="Takedown progress">
        {Object.keys(takedowns.by_status).length === 0 ? (
          <EmptyState title="No takedown requests yet">
            Open a campaign to see who to contact and start a takedown.
          </EmptyState>
        ) : (
          <BarList
            items={takedowns.by_status as Record<string, number>}
            formatLabel={(k) => TAKEDOWN_LABELS[k as keyof typeof TAKEDOWN_LABELS] ?? k}
          />
        )}
      </Card>
    </>
  );
}
