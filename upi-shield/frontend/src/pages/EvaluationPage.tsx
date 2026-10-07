import { api } from "../api/client";
import { Card, ErrorBanner, PageHeader, Spinner, StatCard } from "../components/ui";
import { percent } from "../lib/format";
import { useApi } from "../lib/useApi";

const STAGE_LABELS: Record<string, string> = {
  url_only: "Link features only",
  "url+visual": "Link + visual similarity",
  full: "Full pipeline (link, visual, behaviour, infrastructure)",
};

export function EvaluationPage() {
  const { data, error, reload } = useApi(() => api.metrics(), []);
  if (error) return <ErrorBanner message={error} onRetry={reload} />;
  if (!data) return <Spinner />;
  const test = data.benchmarks.find((b) => b.split === "test");

  return (
    <>
      <PageHeader title="Detection accuracy" subtitle="How often UPI Shield is right, measured on labelled samples." />
      {data.is_placeholder && (
        <div className="alert alert-info">No evaluation results yet. Run <code>python -m eval.evaluate</code> on the backend.</div>
      )}

      {test && (
        <>
          <div className="stats">
            <StatCard label="Precision" value={percent(test.precision, 1)} tone="success"
              hint={`${test.tp} of ${test.tp + test.fp} flagged hosts were real phishing`} />
            <StatCard label="Recall" value={percent(test.recall, 1)} tone="info"
              hint={`${test.tp} of ${test.positives} phishing hosts were caught`} />
            <StatCard label="False alarms" value={percent(test.false_positive_rate, 2)}
              hint={`${test.fp} of ${test.negatives} legitimate domains flagged`} />
            <StatCard label="F1 score" value={test.f1.toFixed(3)} tone="accent" />
          </div>
          <Card title="Real-world benchmark">
            <p>{test.description}</p>
            <p className="muted">
              Results are on the held-out <strong>test</strong> half; detection rules were tuned only on the other half
              (dev). Collected {test.collected ?? "—"}; flagged when the score is at least {test.threshold}.
            </p>
            <div className="table-scroll">
              <table className="table table-stack">
                <thead>
                  <tr>
                    <th scope="col">Split</th><th scope="col">Hosts</th><th scope="col">Phishing</th><th scope="col">Legitimate</th>
                    <th scope="col">Precision</th><th scope="col">Recall</th><th scope="col">False-alarm rate</th>
                  </tr>
                </thead>
                <tbody>
                  {data.benchmarks.map((b) => (
                    <tr key={b.split}>
                      <td><strong>{b.split === "test" ? "Test (reported)" : "Dev (tuning)"}</strong></td>
                      <td data-label="Hosts">{b.sample_size}</td>
                      <td data-label="Phishing">{b.positives}</td>
                      <td data-label="Legitimate">{b.negatives}</td>
                      <td data-label="Precision">{percent(b.precision, 1)}</td>
                      <td data-label="Recall">{percent(b.recall, 1)}</td>
                      <td data-label="False-alarm rate">{percent(b.false_positive_rate, 2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted">
              The phishing class is small ({test.positives} hosts in the test half), so treat these as estimates with wide
              confidence intervals. Every error is listed in <code>backend/eval/benchmark_report.md</code>.
            </p>
          </Card>
        </>
      )}

      <Card title="Controlled sample: every pipeline stage">
        <p className="muted">
          {data.sample_size} hand-built pages with known answers. It checks that each stage adds detection power; it is a
          regression test rather than an estimate of real-world accuracy.
        </p>
        <div className="table-scroll">
          <table className="table table-stack">
            <thead>
              <tr><th scope="col">Stage</th><th scope="col">Precision</th><th scope="col">Recall</th><th scope="col">F1</th></tr>
            </thead>
            <tbody>
              {data.stages.map((s) => (
                <tr key={s.stage}>
                  <td><strong>{STAGE_LABELS[s.stage] ?? s.stage}</strong></td>
                  <td data-label="Precision">{percent(s.precision, 1)}</td>
                  <td data-label="Recall">{percent(s.recall, 1)}</td>
                  <td data-label="F1">{s.f1.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
