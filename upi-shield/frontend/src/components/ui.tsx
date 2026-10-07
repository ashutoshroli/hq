import { type ReactNode, useId } from "react";

import type { CandidateKind, ReviewStatus, TakedownStatus, Verdict } from "../api/types";
import { KIND_LABELS, REVIEW_LABELS, TAKEDOWN_LABELS, VERDICT_LABELS } from "../lib/format";

type Tone = "danger" | "warning" | "success" | "info" | "neutral" | "accent";

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

const VERDICT_TONE: Record<Verdict, Tone> = { malicious: "danger", suspicious: "warning", benign: "success" };
const REVIEW_TONE: Record<ReviewStatus, Tone> = {
  unreviewed: "neutral",
  confirmed: "danger",
  false_positive: "success",
  escalated: "accent",
};
const TAKEDOWN_TONE: Record<TakedownStatus, Tone> = {
  drafted: "neutral",
  sent: "info",
  acknowledged: "accent",
  resolved: "success",
  rejected: "danger",
};

export const VerdictBadge = ({ verdict }: { verdict: Verdict }) => (
  <Badge tone={VERDICT_TONE[verdict]}>{VERDICT_LABELS[verdict]}</Badge>
);
export const ReviewBadge = ({ status }: { status: ReviewStatus }) => (
  <Badge tone={REVIEW_TONE[status]}>{REVIEW_LABELS[status]}</Badge>
);
export const TakedownBadge = ({ status }: { status: TakedownStatus }) => (
  <Badge tone={TAKEDOWN_TONE[status]}>{TAKEDOWN_LABELS[status]}</Badge>
);
export const KindBadge = ({ kind }: { kind: CandidateKind }) => (
  <Badge tone={kind === "web" ? "info" : "accent"}>{KIND_LABELS[kind]}</Badge>
);

export function LiveBadge({ live }: { live: boolean | null }) {
  if (live === null) return <Badge title="The page was not fetched">Not checked</Badge>;
  return live ? (
    <Badge tone="danger" title="Still serving content">
      Live
    </Badge>
  ) : (
    <Badge tone="success" title="Taken down or unreachable">
      Offline
    </Badge>
  );
}

/** Risk score 0..1 as a coloured bar with the numeric value. */
export function ScoreBar({ value }: { value: number }) {
  const tone = value >= 0.7 ? "danger" : value >= 0.4 ? "warning" : "success";
  return (
    <span className="score" aria-label={`Risk score ${value.toFixed(2)}`}>
      <span className="score-track">
        <span className={`score-fill score-${tone}`} style={{ width: `${Math.round(value * 100)}%` }} />
      </span>
      <span className="score-value">{value.toFixed(2)}</span>
    </span>
  );
}

export function Card({ title, actions, children, className = "" }: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-header">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatCard({ label, value, hint, tone = "neutral" }: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Tone;
}) {
  return (
    <div className={`stat stat-${tone}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="spinner" role="status">
      <span className="spinner-dot" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="alert alert-error" role="alert">
      <span>{message}</span>
      {onRetry && (
        <button type="button" className="btn btn-small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <div className="muted">{children}</div>}
    </div>
  );
}

/** Labelled form control with an optional hint, wired up for screen readers. */
export function Field({ label, hint, children }: {
  label: string;
  hint?: ReactNode;
  children: (props: { id: string; "aria-describedby"?: string }) => ReactNode;
}) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, "aria-describedby": hintId })}
      {hint && (
        <small id={hintId} className="muted">
          {hint}
        </small>
      )}
    </div>
  );
}
