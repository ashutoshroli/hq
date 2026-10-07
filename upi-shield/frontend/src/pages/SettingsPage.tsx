import { type FormEvent, useState } from "react";

import { API_BASE, api, settings } from "../api/client";
import { Card, Field, PageHeader } from "../components/ui";

export function SettingsPage() {
  const [apiKey, setApiKey] = useState(settings.getApiKey());
  const [analyst, setAnalyst] = useState(settings.getAnalyst());
  const [saved, setSaved] = useState(false);
  const [seedMessage, setSeedMessage] = useState<string>();

  function save(event: FormEvent) {
    event.preventDefault();
    settings.setApiKey(apiKey.trim());
    settings.setAnalyst(analyst.trim());
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2500);
  }

  async function seed() {
    if (!window.confirm("Replace all current data with the demo dataset? This cannot be undone.")) return;
    try {
      const result = await api.seedDemo();
      setSeedMessage(`Demo data loaded: ${result.candidates} detections in ${result.campaigns} campaigns.`);
    } catch (err) {
      setSeedMessage(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <PageHeader title="Settings" subtitle="Stored in this browser only." />
      <div className="grid grid-2">
        <Card title="Your details">
          <form className="form" onSubmit={save}>
            <Field label="Analyst name" hint="Recorded in the audit trail for reviews and takedowns.">
              {(props) => <input {...props} value={analyst} onChange={(e) => setAnalyst(e.target.value)} maxLength={120} />}
            </Field>
            <Field label="API key" hint="Only needed when the server sets UPI_SHIELD_API_KEY.">
              {(props) => (
                <input
                  {...props}
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  autoComplete="off"
                />
              )}
            </Field>
            <div className="form-actions">
              <button type="submit" className="btn btn-primary">
                Save
              </button>
              {saved && <span className="muted">Saved.</span>}
            </div>
          </form>
        </Card>
        <Card title="Connection">
          <dl className="details">
            <dt>API address</dt>
            <dd>
              <code>{API_BASE}</code>
            </dd>
            <dt>Interactive API docs</dt>
            <dd>
              <a className="link" href={`${API_BASE}/docs`} target="_blank" rel="noreferrer">
                Open Swagger UI
              </a>
            </dd>
          </dl>
          <hr />
          <p className="muted">Load the built-in demo dataset (two campaigns) to explore the dashboard.</p>
          <button type="button" className="btn btn-danger-outline" onClick={seed}>
            Reset to demo data
          </button>
          {seedMessage && <p role="status">{seedMessage}</p>}
        </Card>
      </div>
    </>
  );
}
