import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { Candidate, TakedownCase, TakedownPlanItem, TakedownStatus } from "../api/types";
import { LazyGraphView as GraphView } from "../components/LazyGraphView";
import {
  Badge,
  Card,
  EmptyState,
  ErrorBanner,
  KindBadge,
  LiveBadge,
  PageHeader,
  ReviewBadge,
  ScoreBar,
  Spinner,
  StatCard,
  TakedownBadge,
  VerdictBadge,
} from "../components/ui";
import {
  RECIPIENT_LABELS,
  TAKEDOWN_LABELS,
  assetLabel,
  brandName,
  dateTime,
  entityLabel,
  humanize,
  timeAgo,
} from "../lib/format";
import { useApi } from "../lib/useApi";

const NEXT_STATUSES: Record<TakedownStatus, TakedownStatus[]> = {
  drafted: ["sent"],
  sent: ["acknowledged", "resolved", "rejected"],
  acknowledged: ["resolved", "rejected"],
  resolved: [],
  rejected: ["sent"],
};

/** A case belongs to a plan item when it targets the same recipient, contact and assets. */
export function matchesPlanItem(item: TakedownCase, planItem: TakedownPlanItem): boolean {
  if (item.recipient !== planItem.recipient) return false;
  if (planItem.contacts[0] && item.contact !== planItem.contacts[0]) return false;
  const targets = new Set(item.targets);
  return planItem.targets.length === 0 || planItem.targets.some((t) => targets.has(t));
}

function ContactLink({ contact }: { contact: string }) {
  if (contact.includes("@") && !contact.includes(" ")) {
    return <a className="link" href={`mailto:${contact}`}>{contact}</a>;
  }
  if (contact.startsWith("http")) {
    let host = contact;
    try {
      host = new URL(contact).host;
    } catch {
      /* show the raw value */
    }
    return <a className="link" href={contact} target="_blank" rel="noreferrer">{host}</a>;
  }
  return <span>{contact}</span>;
}

function PlanItem({ item, existing, onStart }: {
  item: TakedownPlanItem;
  existing?: TakedownCase;
  onStart: (item: TakedownPlanItem) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  return (
    <li className="plan-item">
      <div className="plan-main">
        <div className="row">
          <strong>{RECIPIENT_LABELS[item.recipient] ?? item.recipient}</strong>
          {item.channel === "lookup_required" ? (
            <Badge tone="warning" title="No verified contact on record">Contact needed</Badge>
          ) : (
            <Badge tone="info">{humanize(item.channel)}</Badge>
          )}
        </div>
        <p className="muted">{item.rationale}</p>
        {item.contacts.length > 0 && (
          <p className="plan-contacts">
            {item.contacts.map((c, i) => (
              <span key={c}>{i > 0 && " · "}<ContactLink contact={c} /></span>
            ))}
          </p>
        )}
        <button type="button" className="link-button" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Show"} {item.targets.length} target{item.targets.length === 1 ? "" : "s"}
        </button>
        {open && (
          <ul className="target-list">
            {item.targets.map((t) => <li key={t} className="mono">{t}</li>)}
          </ul>
        )}
      </div>
      <div className="plan-action">
        {existing ? (
          <TakedownBadge status={existing.status} />
        ) : (
          <button type="button" className="btn btn-primary btn-small" disabled={busy}
            onClick={async () => { setBusy(true); try { await onStart(item); } finally { setBusy(false); } }}>
            {busy ? "Starting…" : "Start takedown"}
          </button>
        )}
      </div>
    </li>
  );
}

function CaseCard({ item, onChanged }: { item: TakedownCase; onChanged: (c: TakedownCase) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [showReport, setShowReport] = useState(item.status === "drafted");
  const [copied, setCopied] = useState(false);
  const lastCheck = item.checks.at(-1);
  const liveNow = lastCheck ? item.checks.filter((c) => c.checked_at === lastCheck.checked_at && c.live).length : null;

  async function run(action: () => Promise<TakedownCase>) {
    setBusy(true);
    setError(undefined);
    try {
      onChanged(await action());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    await navigator.clipboard?.writeText(`${item.report.subject}\n\n${item.report.body}`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  const mailto = item.contact?.includes("@")
    ? `mailto:${item.contact}?subject=${encodeURIComponent(item.report.subject)}&body=${encodeURIComponent(item.report.body)}`
    : undefined;

  return (
    <li className="case card">
      <div className="case-head">
        <div>
          <strong>{RECIPIENT_LABELS[item.recipient] ?? item.recipient}</strong>
          <div className="muted">
            {item.contact ? <ContactLink contact={item.contact} /> : "No contact"} · updated {timeAgo(item.updated_at)}
          </div>
        </div>
        <TakedownBadge status={item.status} />
      </div>
      {lastCheck && (
        <p className={liveNow ? "alert alert-info" : "alert alert-success"}>
          Last check {dateTime(lastCheck.checked_at)}: {liveNow ? `${liveNow} target(s) still live` : "all targets offline"}.
        </p>
      )}
      <div className="row case-actions">
        {mailto && item.status === "drafted" && <a className="btn btn-small" href={mailto}>Open in e-mail</a>}
        <button type="button" className="btn btn-small" onClick={() => setShowReport((v) => !v)} aria-expanded={showReport}>
          {showReport ? "Hide report" : "View report"}
        </button>
        {NEXT_STATUSES[item.status].map((status) => (
          <button key={status} type="button" className="btn btn-small" disabled={busy}
            onClick={() => {
              const note = status === "rejected" ? window.prompt("Reason for rejection (optional)") ?? undefined : undefined;
              void run(() => api.updateTakedown(item.id, status, note));
            }}>
            Mark {TAKEDOWN_LABELS[status].toLowerCase()}
          </button>
        ))}
        {["sent", "acknowledged"].includes(item.status) && (
          <button type="button" className="btn btn-small" disabled={busy} onClick={() => run(() => api.recheckTakedown(item.id))}>
            {busy ? "Checking…" : "Check if still live"}
          </button>
        )}
      </div>
      {error && <ErrorBanner message={error} />}
      {showReport && (
        <div className="report">
          <div className="row report-head">
            <strong>{item.report.subject}</strong>
            <button type="button" className="btn btn-small" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
          </div>
          <pre>{item.report.body}</pre>
        </div>
      )}
      {item.notes.length > 0 && (
        <ul className="timeline">{item.notes.map((n) => <li key={n} className="muted">{n}</li>)}</ul>
      )}
    </li>
  );
}

function Members({ members }: { members: Candidate[] }) {
  return (
    <div className="table-scroll">
      <table className="table table-stack">
        <thead>
          <tr><th scope="col">Asset</th><th scope="col">Risk</th><th scope="col">Verdict</th><th scope="col">Review</th><th scope="col">Status</th></tr>
        </thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.id}>
              <td className="asset-cell">
                <Link className="asset-link" to={`/detections/${m.id}`} title={m.url}>{assetLabel(m)}</Link>
                <div className="row asset-meta"><KindBadge kind={m.kind} /><span className="muted">{brandName(m.brand_matched)}</span></div>
              </td>
              <td data-label="Risk"><ScoreBar value={m.risk_score} /></td>
              <td data-label="Verdict"><VerdictBadge verdict={m.verdict} /></td>
              <td data-label="Review"><ReviewBadge status={m.review_status} /></td>
              <td data-label="Status"><LiveBadge live={m.live} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CampaignDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const campaign = useApi(() => api.campaign(id), [id]);
  const members = useApi(() => api.candidates({ campaign_id: id, limit: 1000 }), [id]);
  const graph = useApi(() => api.graph(id), [id]);
  const plan = useApi(() => api.takedownPlan(id), [id]);
  const cases = useApi(() => api.takedowns(id), [id]);
  const [startError, setStartError] = useState<string>();

  if (campaign.error) {
    return campaign.error.includes("not found") ? (
      <EmptyState title="Campaign not found">
        It may have changed after a review. <Link className="link" to="/campaigns">Back to campaigns</Link>
      </EmptyState>
    ) : (
      <ErrorBanner message={campaign.error} onRetry={campaign.reload} />
    );
  }
  if (!campaign.data) return <Spinner />;
  const c = campaign.data;
  const list = members.data ?? [];
  const caseList = cases.data ?? [];
  const live = list.filter((m) => m.live).length;
  const checked = list.some((m) => m.live !== null);

  async function start(item: TakedownPlanItem) {
    setStartError(undefined);
    try {
      await api.createTakedown(id, item.recipient, item.contacts[0], item.targets);
      cases.reload();
    } catch (err) {
      setStartError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <nav className="breadcrumbs" aria-label="Breadcrumb">
        <Link to="/campaigns">Campaigns</Link> / <span>{c.id}</span>
      </nav>
      <PageHeader
        title={c.brands_targeted.length ? `Campaign targeting ${c.brands_targeted.map(brandName).join(", ")}` : c.name}
        subtitle={`First seen ${dateTime(c.first_seen)} · last activity ${timeAgo(c.last_seen)}`}
        actions={
          <div className="row">
            <span className="muted">Export:</span>
            {(["markdown", "stix", "json", "zip"] as const).map((format) => (
              <a key={format} className="btn btn-small" href={api.exportUrl(c.id, format)} download>
                {{ markdown: "Dossier", stix: "STIX 2.1", json: "JSON", zip: "Evidence ZIP" }[format]}
              </a>
            ))}
          </div>
        }
      />

      <div className="stats">
        <StatCard label="Assets" value={c.size}
          hint={`${list.filter((m) => m.kind === "web").length} sites · ${list.filter((m) => m.kind === "app").length} apps · ${list.filter((m) => m.kind === "message").length} messages`} />
        {checked ? (
          <StatCard label="Still live" value={live} hint={`${list.filter((m) => m.live === false).length} offline`}
            tone={live ? "warning" : "success"} />
        ) : (
          <StatCard label="Still live" value="—" hint="not checked yet" />
        )}
        <StatCard label="Linking indicators" value={c.shared_entities.length} tone="accent" />
        <StatCard label="Takedowns" value={caseList.length}
          hint={`${caseList.filter((t) => t.status === "resolved").length} resolved`} tone="info" />
      </div>

      <Card title="How these assets are linked">
        <ul className="chips">
          {c.shared_entities.map((e) => (
            <li key={`${e.type}:${e.value}`}>
              <span className="chip chip-static" title={entityLabel(e.type)}>
                <span className="muted">{entityLabel(e.type)}:</span> {e.value}
              </span>
            </li>
          ))}
        </ul>
        <div className="graph-wrap">
          {graph.data ? (
            <GraphView graph={graph.data} onOpenCandidate={(cid) => navigate(`/detections/${cid}`)} />
          ) : graph.error ? <ErrorBanner message={graph.error} onRetry={graph.reload} /> : <Spinner />}
        </div>
      </Card>

      <Card title="Assets in this campaign" className="table-card-wrap">
        {members.data ? <Members members={list} /> : <Spinner />}
      </Card>

      <div className="grid grid-2 align-start">
        <Card title="Takedown plan">
          <p className="muted">Who can act on each part of this campaign. Contacts come from registration and hosting records and from the brands' own published channels.</p>
          {startError && <ErrorBanner message={startError} />}
          {plan.error && <ErrorBanner message={plan.error} onRetry={plan.reload} />}
          {plan.data ? (
            <ul className="plan">
              {plan.data.items.map((item, i) => (
                <PlanItem key={`${item.recipient}-${i}`} item={item}
                  existing={caseList.find((t) => matchesPlanItem(t, item))}
                  onStart={start} />
              ))}
            </ul>
          ) : !plan.error && <Spinner />}
        </Card>
        <Card title="Takedown requests">
          {caseList.length === 0 ? (
            <EmptyState title="No takedowns started">Use “Start takedown” in the plan to draft a request.</EmptyState>
          ) : (
            <ul className="cases">
              {[...caseList].reverse().map((t) => (
                <CaseCard key={t.id} item={t} onChanged={() => cases.reload()} />
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
