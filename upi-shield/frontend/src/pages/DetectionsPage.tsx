import { type FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type { CandidateFilters, CandidateKind, ReviewStatus, SourceType, Verdict } from "../api/types";
import {
  EmptyState,
  ErrorBanner,
  KindBadge,
  LiveBadge,
  PageHeader,
  ReviewBadge,
  ScoreBar,
  Spinner,
  VerdictBadge,
} from "../components/ui";
import {
  BRAND_NAMES,
  KIND_LABELS,
  REVIEW_LABELS,
  SOURCE_LABELS,
  VERDICT_LABELS,
  assetLabel,
  brandName,
  timeAgo,
} from "../lib/format";
import { useApi } from "../lib/useApi";

const PAGE_SIZE = 25;
const BRAND_OPTIONS = Object.entries(BRAND_NAMES).filter(([key]) => key !== "googlepay");

/** Reads the filters from the URL so every view can be bookmarked and shared. */
function filtersFrom(params: URLSearchParams): CandidateFilters {
  const live = params.get("live");
  return {
    q: params.get("q") ?? undefined,
    verdict: (params.get("verdict") as Verdict) || undefined,
    kind: (params.get("kind") as CandidateKind) || undefined,
    brand: params.get("brand") ?? undefined,
    source: (params.get("source") as SourceType) || undefined,
    review: (params.get("review") as ReviewStatus) || undefined,
    live: live === "true" ? true : live === "false" ? false : undefined,
    campaign_id: params.get("campaign_id") ?? undefined,
  };
}

function Select({ label, name, value, options, onChange }: {
  label: string;
  name: string;
  value: string;
  options: [string, string][];
  onChange: (name: string, value: string) => void;
}) {
  return (
    <label className="filter">
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(name, e.target.value)}>
        <option value="">All</option>
        {options.map(([key, text]) => (
          <option key={key} value={key}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}

export function DetectionsPage() {
  const [params, setParams] = useSearchParams();
  const filters = filtersFrom(params);
  const page = Math.max(0, Number(params.get("page") ?? 0) || 0);
  const [search, setSearch] = useState(filters.q ?? "");

  const { data, error, loading, reload } = useApi(
    () => api.candidates({ ...filters, limit: PAGE_SIZE + 1, offset: page * PAGE_SIZE }),
    [params.toString()],
  );

  function update(name: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    next.delete("page");
    setParams(next);
  }

  function goToPage(next: number) {
    const updated = new URLSearchParams(params);
    if (next > 0) updated.set("page", String(next));
    else updated.delete("page");
    setParams(updated);
  }

  function submitSearch(event: FormEvent) {
    event.preventDefault();
    update("q", search.trim());
  }

  const rows = data?.slice(0, PAGE_SIZE) ?? [];
  const hasMore = (data?.length ?? 0) > PAGE_SIZE;
  const active = [...params.keys()].filter((k) => k !== "page").length;

  return (
    <>
      <PageHeader
        title="Detections"
        subtitle="Every analysed website, Android app and message, highest risk first."
        actions={
          <Link className="btn btn-primary" to="/ingest">
            Report something
          </Link>
        }
      />

      <div className="card filters">
        <form className="filter filter-search" onSubmit={submitSearch} role="search">
          <span>Search</span>
          <input
            type="search"
            placeholder="Domain or URL contains…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search detections"
          />
        </form>
        <Select label="Verdict" name="verdict" value={filters.verdict ?? ""} onChange={update}
          options={Object.entries(VERDICT_LABELS)} />
        <Select label="Type" name="kind" value={filters.kind ?? ""} onChange={update}
          options={Object.entries(KIND_LABELS)} />
        <Select label="Brand" name="brand" value={filters.brand ?? ""} onChange={update} options={BRAND_OPTIONS} />
        <Select label="Source" name="source" value={filters.source ?? ""} onChange={update}
          options={Object.entries(SOURCE_LABELS)} />
        <Select label="Review" name="review" value={filters.review ?? ""} onChange={update}
          options={Object.entries(REVIEW_LABELS)} />
        <Select label="Status" name="live" value={params.get("live") ?? ""} onChange={update}
          options={[["true", "Live"], ["false", "Offline"]]} />
        {active > 0 && (
          <button type="button" className="btn btn-small" onClick={() => { setSearch(""); setParams({}); }}>
            Clear filters
          </button>
        )}
      </div>

      {error && <ErrorBanner message={error} onRetry={reload} />}
      {!data && !error && <Spinner />}
      {data && rows.length === 0 && (
        <div className="card">
          <EmptyState title="No detections match these filters">
            {active ? "Try removing a filter." : "Report a URL, message or app to get started."}
          </EmptyState>
        </div>
      )}

      {rows.length > 0 && (
        <div className={`card table-card ${loading ? "is-loading" : ""}`}>
          <div className="table-scroll">
            <table className="table table-stack">
              <thead>
                <tr>
                  <th scope="col">Asset</th>
                  <th scope="col">Brand</th>
                  <th scope="col">Risk</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Review</th>
                  <th scope="col">Status</th>
                  <th scope="col">First seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.id}>
                    <td className="asset-cell">
                      <Link to={`/detections/${c.id}`} className="asset-link" title={c.url}>
                        {assetLabel(c)}
                      </Link>
                      <div className="row asset-meta">
                        <KindBadge kind={c.kind} />
                        <span className="muted">{SOURCE_LABELS[c.source]}</span>
                        {c.campaign_id && <span className="muted">· in campaign</span>}
                      </div>
                    </td>
                    <td data-label="Brand" className="nowrap">{c.brand_matched ? brandName(c.brand_matched) : <span className="muted">—</span>}</td>
                    <td data-label="Risk"><ScoreBar value={c.risk_score} /></td>
                    <td data-label="Verdict"><VerdictBadge verdict={c.verdict} /></td>
                    <td data-label="Review"><ReviewBadge status={c.review_status} /></td>
                    <td data-label="Status"><LiveBadge live={c.live} /></td>
                    <td data-label="First seen" className="nowrap muted" title={c.first_seen}>{timeAgo(c.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <footer className="pager">
            <span className="muted">
              Showing {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + rows.length}
            </span>
            <div className="row">
              <button type="button" className="btn btn-small" disabled={page === 0} onClick={() => goToPage(page - 1)}>
                Previous
              </button>
              <button type="button" className="btn btn-small" disabled={!hasMore} onClick={() => goToPage(page + 1)}>
                Next
              </button>
            </div>
          </footer>
        </div>
      )}
    </>
  );
}
