import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type { Job, JobStatus } from "../api/types";
import { Badge, Card, EmptyState, ErrorBanner, PageHeader, Spinner } from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { useApi } from "../lib/useApi";

const KIND_LABELS: Record<string, string> = {
  ingest_url: "Check link",
  ingest_batch: "Check many links",
  ingest_feed: "Import threat feed",
  ingest_app_url: "Analyse Android app",
  crawl_ct: "Search certificate logs",
};

const STATUS_TONE: Record<JobStatus, "neutral" | "info" | "success" | "danger"> = {
  queued: "neutral",
  running: "info",
  done: "success",
  failed: "danger",
};

function describe(job: Job): string {
  const p = job.params;
  if (typeof p.url === "string") return p.url;
  if (typeof p.feed === "string") return `${p.feed} (up to ${String(p.limit ?? "")})`;
  if (Array.isArray(p.keywords) && p.keywords.length) return `Keywords: ${p.keywords.join(", ")}`;
  if (p.scheduled) return "Scheduled run";
  if (typeof p.count === "number") return `${p.count} links`;
  return "";
}

function Progress({ job }: { job: Job }) {
  const { total, processed, failed } = job.progress;
  const pct = total ? Math.round((processed / total) * 100) : job.status === "done" ? 100 : 0;
  return (
    <div className="progress" aria-label={`${processed} of ${total} processed`}>
      <div className="progress-track">
        <div className={`progress-fill ${job.status === "failed" ? "failed" : ""}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="muted">
        {total ? `${processed}/${total}` : job.status === "running" ? "starting…" : "—"}
        {failed > 0 && ` · ${failed} failed`}
      </span>
    </div>
  );
}

export function JobsPage() {
  const [params] = useSearchParams();
  const highlight = params.get("highlight");
  const { data, error, reload } = useApi(() => api.jobs(100), [], 3000);

  return (
    <>
      <PageHeader
        title="Background jobs"
        subtitle="Discovery runs and bulk checks. This page refreshes automatically."
        actions={<Link className="btn" to="/ingest">Start a new run</Link>}
      />
      {error && !data && <ErrorBanner message={error} onRetry={reload} />}
      {!data && !error && <Spinner />}
      {data && data.length === 0 && (
        <Card>
          <EmptyState title="No jobs yet">Bulk checks, feed imports and certificate searches appear here.</EmptyState>
        </Card>
      )}
      {data && data.length > 0 && (
        <div className="card table-card">
          <div className="table-scroll">
            <table className="table table-stack">
              <thead>
                <tr>
                  <th scope="col">Job</th>
                  <th scope="col">Status</th>
                  <th scope="col">Progress</th>
                  <th scope="col">Results</th>
                  <th scope="col">Started</th>
                </tr>
              </thead>
              <tbody>
                {data.map((job) => (
                  <tr key={job.id} className={job.id === highlight ? "row-highlight" : ""}>
                    <td>
                      <strong>{KIND_LABELS[job.kind] ?? job.kind}</strong>
                      <div className="muted mono">{describe(job)}</div>
                      {job.error && <div className="error-text">{job.error}</div>}
                    </td>
                    <td data-label="Status"><Badge tone={STATUS_TONE[job.status]}>{job.status}</Badge></td>
                    <td data-label="Progress"><Progress job={job} /></td>
                    <td data-label="Results">
                      {job.candidate_ids.length === 0 ? (
                        <span className="muted">—</span>
                      ) : job.candidate_ids.length === 1 ? (
                        <Link className="link" to={`/detections/${job.candidate_ids[0]}`}>View result</Link>
                      ) : (
                        <span>{job.candidate_ids.length} detections</span>
                      )}
                    </td>
                    <td data-label="Started" className="nowrap muted" title={dateTime(job.created_at)}>{timeAgo(job.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
