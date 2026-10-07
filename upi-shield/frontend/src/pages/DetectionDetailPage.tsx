import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { Candidate, Entity, ReviewStatus } from "../api/types";
import {
  Badge,
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  KindBadge,
  LiveBadge,
  PageHeader,
  ReviewBadge,
  ScoreBar,
  Spinner,
  VerdictBadge,
} from "../components/ui";
import { REVIEW_LABELS, SOURCE_LABELS, assetLabel, brandName, dateTime, humanize, percent } from "../lib/format";
import { useApi } from "../lib/useApi";

const ENTITY_LABELS: Record<string, string> = {
  domain: "Domains",
  ip: "IP addresses",
  asn: "Networks (ASN)",
  cert_fingerprint: "TLS certificates",
  registrar: "Registrars",
  upi_id: "UPI handles",
  phone: "Phone numbers",
  telegram: "Telegram",
  favicon_hash: "Favicon / icon hashes",
  analytics_id: "Analytics IDs",
  package_name: "App packages",
  apk_sha256: "APK hashes",
  signing_cert: "Signing certificates",
};

const REVIEW_ACTIONS: { status: ReviewStatus; label: string; className: string; help: string }[] = [
  { status: "confirmed", label: "Confirm threat", className: "btn-primary", help: "Keep it in campaigns and reports" },
  { status: "false_positive", label: "Mark as false positive", className: "", help: "Remove it from campaigns and reports" },
  { status: "escalated", label: "Escalate", className: "", help: "Flag for a senior analyst" },
];

function ReviewPanel({ candidate, onReviewed }: { candidate: Candidate; onReviewed: (c: Candidate) => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function review(status: ReviewStatus) {
    setBusy(true);
    setError(undefined);
    try {
      onReviewed(await api.review(candidate.id, status, note.trim()));
      setNote("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Analyst review">
      <p className="row">
        Current status: <ReviewBadge status={candidate.review_status} />
        {candidate.reviewed_by && (
          <span className="muted">
            by {candidate.reviewed_by}, {dateTime(candidate.reviewed_at)}
          </span>
        )}
      </p>
      {candidate.review_note && <blockquote className="note">{candidate.review_note}</blockquote>}
      <Field label="Note (optional)" hint="Saved with your decision in the audit trail.">
        {(props) => <textarea {...props} value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={2000} />}
      </Field>
      <div className="form-actions review-actions">
        {REVIEW_ACTIONS.filter((a) => a.status !== candidate.review_status).map((action) => (
          <button key={action.status} type="button" className={`btn ${action.className}`} disabled={busy}
            title={action.help} onClick={() => review(action.status)}>
            {action.label}
          </button>
        ))}
      </div>
      {error && <ErrorBanner message={error} />}
    </Card>
  );
}

function EvidenceList({ candidate }: { candidate: Candidate }) {
  const signals = [...candidate.signals].sort((a, b) => b.weight - a.weight);
  if (!signals.length) return <p className="muted">No evidence was recorded.</p>;
  return (
    <ul className="evidence">
      {signals.map((s, i) => (
        <li key={`${s.name}-${i}`} className={s.weight === 0 ? "evidence-info" : ""}>
          <div className="evidence-head">
            <strong>{humanize(s.name)}</strong>
            {s.weight > 0 ? <Badge tone="danger">+{s.weight.toFixed(2)}</Badge> : <Badge>info</Badge>}
          </div>
          <p>{s.detail}</p>
        </li>
      ))}
    </ul>
  );
}

function RelatedDrawer({ entity, selfId, onClose }: { entity: Entity; selfId: string; onClose: () => void }) {
  const { data, error } = useApi(() => api.pivot(entity.type, entity.value), [entity.type, entity.value]);
  const others = data?.filter((c) => c.id !== selfId) ?? [];
  return (
    <div className="pivot" role="region" aria-label="Related detections">
      <div className="row pivot-head">
        <strong>
          Also using <span className="mono">{entity.value}</span>
        </strong>
        <button type="button" className="btn btn-small" onClick={onClose}>
          Close
        </button>
      </div>
      {error && <ErrorBanner message={error} />}
      {!data && !error && <Spinner />}
      {data && others.length === 0 && <p className="muted">No other detection uses this value.</p>}
      <ul className="pivot-list">
        {others.map((c) => (
          <li key={c.id}>
            <Link to={`/detections/${c.id}`} className="link">
              {assetLabel(c)}
            </Link>{" "}
            <VerdictBadge verdict={c.verdict} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function Infrastructure({ candidate }: { candidate: Candidate }) {
  const [pivot, setPivot] = useState<Entity>();
  const groups = new Map<string, string[]>();
  for (const e of candidate.entities) {
    if (e.type === "domain" && e.value === candidate.domain) continue;
    groups.set(e.type, [...(groups.get(e.type) ?? []), e.value]);
  }
  const infra = candidate.infrastructure;
  return (
    <Card title="Infrastructure">
      {infra && (
        <dl className="details">
          {infra.ip && (<><dt>Hosting</dt><dd>{infra.ip} {infra.asn && `· ${infra.asn} ${infra.as_name ?? ""}`}
            {infra.shared_hosting && <> <Badge tone="info" title="Shared IPs do not link campaigns">CDN / shared</Badge></>}</dd></>)}
          {infra.registrar && (<><dt>Registrar</dt><dd>{infra.registrar}</dd></>)}
          {infra.registered_on && (<><dt>Registered</dt><dd>{dateTime(infra.registered_on)}</dd></>)}
          {(infra.registrar_abuse_email || infra.hosting_abuse_contacts.length > 0) && (
            <><dt>Abuse contacts</dt><dd>{[infra.registrar_abuse_email, ...infra.hosting_abuse_contacts].filter(Boolean).join(", ")}</dd></>
          )}
        </dl>
      )}
      {groups.size === 0 ? (
        <p className="muted">No linking indicators yet. Enable live fetching to enrich detections.</p>
      ) : (
        <div className="entity-groups">
          {[...groups.entries()].map(([type, values]) => (
            <div key={type}>
              <h3>{ENTITY_LABELS[type] ?? humanize(type)}</h3>
              <ul className="chips">
                {values.map((value) => (
                  <li key={value}>
                    <button type="button" className="chip" title="Find other detections using this"
                      onClick={() => setPivot({ type, value })}>
                      {value}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
      {pivot && <RelatedDrawer entity={pivot} selfId={candidate.id} onClose={() => setPivot(undefined)} />}
    </Card>
  );
}

function History({ candidateId }: { candidateId: string }) {
  const { data } = useApi(() => api.audit(candidateId), [candidateId]);
  if (!data?.length) return null;
  return (
    <Card title="History">
      <ul className="timeline">
        {data.map((e) => (
          <li key={e.id}>
            <span className="muted">{dateTime(e.at)}</span> <strong>{e.actor}</strong> marked it{" "}
            <strong>{REVIEW_LABELS[e.detail.to as ReviewStatus] ?? String(e.detail.to)}</strong>
            {e.detail.note ? <span className="muted"> — “{String(e.detail.note)}”</span> : null}
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function DetectionDetailPage() {
  const { id = "" } = useParams();
  const { data, error, reload } = useApi(() => api.candidate(id), [id]);
  const [current, setCurrent] = useState<Candidate>();
  const [historyKey, setHistoryKey] = useState(0);
  const candidate = current?.id === id ? current : data;

  if (error && !candidate) {
    return error.includes("not found") ? (
      <EmptyState title="Detection not found">
        <Link className="link" to="/detections">Back to detections</Link>
      </EmptyState>
    ) : (
      <ErrorBanner message={error} onRetry={reload} />
    );
  }
  if (!candidate) return <Spinner />;

  return (
    <>
      <nav className="breadcrumbs" aria-label="Breadcrumb">
        <Link to="/detections">Detections</Link> / <span>{candidate.id}</span>
      </nav>
      <PageHeader
        title={candidate.kind === "web" ? candidate.domain : candidate.kind === "app" ? candidate.app?.label ?? candidate.domain : "Message lure"}
        subtitle={<span className="mono">{candidate.kind === "message" ? candidate.message?.excerpt : candidate.url}</span>}
        actions={candidate.campaign_id && (
          <Link className="btn" to={`/campaigns/${candidate.campaign_id}`}>View campaign</Link>
        )}
      />

      <div className="summary-strip card">
        <div><span className="muted">Risk</span><ScoreBar value={candidate.risk_score} /></div>
        <div><span className="muted">Verdict</span><VerdictBadge verdict={candidate.verdict} /></div>
        <div><span className="muted">Brand</span><strong>{brandName(candidate.brand_matched)}</strong></div>
        <div><span className="muted">Type</span><KindBadge kind={candidate.kind} /></div>
        <div><span className="muted">Status</span><LiveBadge live={candidate.live} /></div>
        <div><span className="muted">Source</span>{SOURCE_LABELS[candidate.source]}</div>
        <div><span className="muted">First seen</span>{dateTime(candidate.first_seen)}</div>
        {candidate.sightings > 1 && <div><span className="muted">Reported</span>{candidate.sightings} times</div>}
        {candidate.visual_similarity !== null && (
          <div><span className="muted">Looks like {brandName(candidate.brand_matched)}</span>{percent(candidate.visual_similarity)}</div>
        )}
      </div>

      <div className="grid detail-grid">
        <div className="stack">
          <Card title="Why it was flagged"><EvidenceList candidate={candidate} /></Card>
          {candidate.app && (
            <Card title="App details">
              <dl className="details">
                <dt>Package</dt><dd className="mono">{candidate.app.package}</dd>
                <dt>Version</dt><dd>{candidate.app.version ?? "—"}</dd>
                <dt>SHA-256</dt><dd className="mono">{candidate.app.sha256}</dd>
                <dt>Signed by</dt><dd className="mono">{candidate.app.cert_sha256.join(", ") || "unsigned"}</dd>
                {candidate.app.origin_url && (<><dt>Downloaded from</dt><dd className="mono">{candidate.app.origin_url}</dd></>)}
                <dt>Permissions</dt><dd>{candidate.app.permissions.map((p) => p.split(".").pop()).join(", ") || "—"}</dd>
              </dl>
            </Card>
          )}
          {candidate.message && (
            <Card title="Message">
              <blockquote className="note">{candidate.message.excerpt}</blockquote>
              <p className="muted">Card and account numbers are masked before storage.</p>
            </Card>
          )}
          <Infrastructure candidate={candidate} />
        </div>
        <div className="stack">
          <ReviewPanel candidate={candidate} onReviewed={(c) => { setCurrent(c); setHistoryKey((k) => k + 1); }} />
          {candidate.screenshot_url && (
            <Card title="Screenshot">
              <a href={api.evidenceUrl(candidate.screenshot_url)} target="_blank" rel="noreferrer">
                <img className="screenshot" src={api.evidenceUrl(candidate.screenshot_url)}
                  alt={`Screenshot of ${candidate.domain} captured during analysis`} loading="lazy" />
              </a>
            </Card>
          )}
          <History key={historyKey} candidateId={candidate.id} />
        </div>
      </div>
    </>
  );
}
