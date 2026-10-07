import { type FormEvent, type ReactNode, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { IngestResponse } from "../api/types";
import { Card, ErrorBanner, Field, PageHeader } from "../components/ui";

type TabId = "url" | "message" | "app" | "bulk" | "feed" | "crawl";

const TABS: { id: TabId; label: string; description: string }[] = [
  { id: "url", label: "Website link", description: "Check one suspicious link reported by a customer or colleague." },
  { id: "message", label: "SMS / WhatsApp", description: "Paste a message; links, UPI IDs, phone numbers and Telegram handles are extracted." },
  { id: "app", label: "Android app", description: "Upload an APK file or give a download link to check for a fake banking app." },
  { id: "bulk", label: "Many links", description: "Check a list of links in the background, one per line." },
  { id: "feed", label: "Threat feed", description: "Import brand-related phishing URLs from a public feed." },
  { id: "crawl", label: "Certificate logs", description: "Search new TLS certificates for look-alike domains of monitored brands." },
];

interface Outcome {
  response: IngestResponse;
  background: boolean;
}

function Result({ outcome }: { outcome: Outcome }) {
  const { response, background } = outcome;
  const extracted = Object.entries(response.extracted ?? {}).filter(([, v]) => v.length);
  return (
    <div className="alert alert-success result" role="status">
      <div>
        {background ? (
          <p>
            Started in the background. <Link className="link" to={`/jobs?highlight=${response.job_id}`}>Follow progress</Link>.
          </p>
        ) : response.candidate_ids.length ? (
          <p>
            Analysed {response.candidate_ids.length} item{response.candidate_ids.length === 1 ? "" : "s"}:{" "}
            {response.candidate_ids.map((id, i) => (
              <span key={id}>
                {i > 0 && ", "}
                <Link className="link" to={`/detections/${id}`}>view result {i + 1}</Link>
              </span>
            ))}
          </p>
        ) : (
          <p>Nothing to analyse: no link, UPI ID, phone number or Telegram handle was found.</p>
        )}
        {response.job_ids.length > 0 && (
          <p>
            An Android app link was found and is being analysed.{" "}
            <Link className="link" to="/jobs">Follow progress</Link>.
          </p>
        )}
        {extracted.length > 0 && (
          <ul className="extracted">
            {extracted.map(([key, values]) => (
              <li key={key}>
                <strong>{{ urls: "Links", upi_ids: "UPI IDs", phones: "Phone numbers", telegram: "Telegram" }[key] ?? key}:</strong>{" "}
                <span className="mono">{values.join(", ")}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function SubmitForm({ onSubmit, label, children, disabled }: {
  onSubmit: () => Promise<Outcome>;
  label: string;
  children: ReactNode;
  disabled?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [outcome, setOutcome] = useState<Outcome>();

  async function handle(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    setOutcome(undefined);
    try {
      setOutcome(await onSubmit());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form" onSubmit={handle}>
      {children}
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy || disabled}>
          {busy ? "Working…" : label}
        </button>
      </div>
      {error && <ErrorBanner message={error} />}
      {outcome && <Result outcome={outcome} />}
    </form>
  );
}

function UrlForm() {
  const [url, setUrl] = useState("");
  return (
    <SubmitForm label="Check link" disabled={!url.trim()}
      onSubmit={async () => ({ response: await api.ingestUrl(url.trim()), background: false })}>
      <Field label="Suspicious link" hint="For example http://sbi-kyc-update.top/login. The page is not opened in your browser.">
        {(props) => <input {...props} type="text" inputMode="url" value={url} onChange={(e) => setUrl(e.target.value)} required />}
      </Field>
    </SubmitForm>
  );
}

function MessageForm() {
  const [text, setText] = useState("");
  return (
    <SubmitForm label="Analyse message" disabled={!text.trim()}
      onSubmit={async () => ({ response: await api.ingestMessage(text), background: false })}>
      <Field label="Message text" hint="Card and account numbers are masked before anything is stored.">
        {(props) => (
          <textarea {...props} rows={5} value={text} onChange={(e) => setText(e.target.value)} required
            placeholder="Dear customer, your account will be blocked today. Update KYC at …" />
        )}
      </Field>
    </SubmitForm>
  );
}

function AppForm() {
  const [file, setFile] = useState<File | null>(null);
  const [link, setLink] = useState("");
  return (
    <div className="grid grid-2">
      <SubmitForm label="Upload and analyse" disabled={!file}
        onSubmit={async () => ({ response: await api.uploadApp(file as File), background: false })}>
        <Field label="APK file" hint="The app is inspected statically; it is never installed or run.">
          {(props) => (
            <input {...props} type="file" accept=".apk,application/vnd.android.package-archive"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          )}
        </Field>
      </SubmitForm>
      <SubmitForm label="Download and analyse" disabled={!link.trim()}
        onSubmit={async () => ({ response: await api.ingestAppUrl(link.trim()), background: true })}>
        <Field label="APK download link">
          {(props) => <input {...props} type="text" inputMode="url" value={link} onChange={(e) => setLink(e.target.value)} />}
        </Field>
      </SubmitForm>
    </div>
  );
}

function BulkForm() {
  const [text, setText] = useState("");
  const urls = text.split(/\s+/).map((u) => u.trim()).filter(Boolean);
  return (
    <SubmitForm label={`Check ${urls.length || ""} link${urls.length === 1 ? "" : "s"}`.replace("  ", " ")}
      disabled={!urls.length || urls.length > 1000}
      onSubmit={async () => ({ response: await api.ingestBatch(urls), background: true })}>
      <Field label="Links" hint={`One per line, up to 1,000. ${urls.length} detected.`}>
        {(props) => <textarea {...props} rows={8} value={text} onChange={(e) => setText(e.target.value)} />}
      </Field>
    </SubmitForm>
  );
}

function FeedForm() {
  const [feed, setFeed] = useState<"openphish" | "urlhaus">("openphish");
  const [limit, setLimit] = useState(100);
  return (
    <SubmitForm label="Import feed"
      onSubmit={async () => ({ response: await api.ingestFeed(feed, limit), background: true })}>
      <Field label="Feed">
        {(props) => (
          <select {...props} value={feed} onChange={(e) => setFeed(e.target.value as "openphish" | "urlhaus")}>
            <option value="openphish">OpenPhish community feed</option>
            <option value="urlhaus">URLhaus recent URLs</option>
          </select>
        )}
      </Field>
      <Field label="Maximum links" hint="Only links that mention a monitored payment brand are imported.">
        {(props) => (
          <input {...props} type="number" min={1} max={5000} value={limit} onChange={(e) => setLimit(Number(e.target.value))} />
        )}
      </Field>
    </SubmitForm>
  );
}

function CrawlForm() {
  const [keywords, setKeywords] = useState("");
  const [max, setMax] = useState(50);
  const list = keywords.split(",").map((k) => k.trim()).filter(Boolean);
  return (
    <SubmitForm label="Search certificate logs"
      onSubmit={async () => ({ response: await api.crawl(list, max), background: true })}>
      <Field label="Brand keywords" hint="Comma separated, e.g. phonepe, paytm. Leave empty to search all monitored brands.">
        {(props) => <input {...props} value={keywords} onChange={(e) => setKeywords(e.target.value)} />}
      </Field>
      <Field label="Maximum domains to analyse" hint="Searching crt.sh can take a few minutes.">
        {(props) => (
          <input {...props} type="number" min={1} max={5000} value={max} onChange={(e) => setMax(Number(e.target.value))} />
        )}
      </Field>
    </SubmitForm>
  );
}

const FORMS: Record<TabId, () => ReactNode> = {
  url: () => <UrlForm />,
  message: () => <MessageForm />,
  app: () => <AppForm />,
  bulk: () => <BulkForm />,
  feed: () => <FeedForm />,
  crawl: () => <CrawlForm />,
};

export function IngestPage() {
  const [tab, setTab] = useState<TabId>("url");
  const current = TABS.find((t) => t.id === tab) ?? TABS[0]!;
  return (
    <>
      <PageHeader title="Report a threat" subtitle="Submit something suspicious or start a discovery run." />
      <Card>
        <div className="tabs" role="tablist" aria-label="What would you like to check?">
          {TABS.map((t) => (
            <button key={t.id} type="button" role="tab" id={`tab-${t.id}`} aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="tab-panel">
          <p className="muted">{current.description}</p>
          {FORMS[tab]()}
        </div>
      </Card>
    </>
  );
}
