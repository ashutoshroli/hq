import type { CandidateKind, ReviewStatus, SourceType, TakedownStatus, Verdict } from "../api/types";

export const BRAND_NAMES: Record<string, string> = {
  phonepe: "PhonePe",
  gpay: "Google Pay",
  googlepay: "Google Pay",
  paytm: "Paytm",
  bhim: "BHIM UPI",
  sbi: "SBI",
  hdfc: "HDFC Bank",
  icici: "ICICI Bank",
  axisbank: "Axis Bank",
};

export const SOURCE_LABELS: Record<SourceType, string> = {
  ct_log: "Certificate logs",
  message: "Messages",
  user_report: "User reports",
  feed: "Threat feeds",
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  benign: "Benign",
};

export const REVIEW_LABELS: Record<ReviewStatus, string> = {
  unreviewed: "Not reviewed",
  confirmed: "Confirmed",
  false_positive: "False positive",
  escalated: "Escalated",
};

export const KIND_LABELS: Record<CandidateKind, string> = { web: "Website", app: "Android app", message: "Message" };

export const TAKEDOWN_LABELS: Record<TakedownStatus, string> = {
  drafted: "Drafted",
  sent: "Sent",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  rejected: "Rejected",
};

export const RECIPIENT_LABELS: Record<string, string> = {
  registrar: "Domain registrar",
  hosting: "Hosting provider",
  bank: "Impersonated brand",
  npci: "NPCI (UPI handles)",
  cert_in: "CERT-In",
  safe_browsing: "Browser blocklists",
  app_store: "Google Play Protect",
  cybercrime_portal: "National Cyber Crime Portal",
  telecom: "Sanchar Saathi (phone numbers)",
};

export function brandName(key: string | null | undefined): string {
  if (!key) return "Unknown brand";
  return BRAND_NAMES[key] ?? key;
}

/** "brand_in_unofficial_domain" -> "Brand in unofficial domain" */
export function humanize(name: string): string {
  const text = name.replace(/_/g, " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function percent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

export function score(value: number): string {
  return value.toFixed(2);
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function shortDate(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function timeAgo(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const seconds = Math.round((now.getTime() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const units: [number, string][] = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
  ];
  let value = Math.floor(seconds / 60);
  let unit = "minute";
  for (const [size, name] of units) {
    if (seconds >= size) {
      value = Math.floor(seconds / size);
      unit = name;
    }
  }
  return `${value} ${unit}${value === 1 ? "" : "s"} ago`;
}

/** Short display form of a candidate's address (site URL, app package or message excerpt). */
export function assetLabel(c: {
  kind: CandidateKind;
  url: string;
  app?: { label: string; package: string } | null;
  message?: { excerpt: string } | null;
}): string {
  if (c.kind === "app" && c.app) return `${c.app.label} (${c.app.package})`;
  if (c.kind === "message" && c.message) return `“${c.message.excerpt.slice(0, 90)}${c.message.excerpt.length > 90 ? "…" : ""}”`;
  return c.url;
}

export const ENTITY_LABELS: Record<string, string> = {
  domain: "Domain",
  ip: "IP address",
  asn: "Network",
  cert_fingerprint: "TLS certificate",
  registrar: "Registrar",
  upi_id: "UPI handle",
  phone: "Phone",
  telegram: "Telegram",
  favicon_hash: "Favicon",
  analytics_id: "Analytics ID",
  package_name: "App package",
  apk_sha256: "APK hash",
  signing_cert: "Signing certificate",
};

export function entityLabel(type: string): string {
  return ENTITY_LABELS[type] ?? humanize(type);
}
