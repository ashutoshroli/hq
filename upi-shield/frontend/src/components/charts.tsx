import { shortDate } from "../lib/format";

/** Label roughly seven evenly spaced days, always including the last one. */
function showLabel(index: number, count: number): boolean {
  const step = Math.max(1, Math.ceil(count / 7));
  if (index === count - 1) return true;
  return index % step === 0 && count - 1 - index >= step;
}

/** Daily detections as an accessible SVG column chart. */
export function DailyChart({ points }: { points: { date: string; count: number }[] }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const width = 640;
  const height = 160;
  const gap = 6;
  const barWidth = points.length ? (width - gap * (points.length - 1)) / points.length : 0;
  const total = points.reduce((sum, p) => sum + p.count, 0);

  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${width} ${height + 22}`} role="img" aria-label={`${total} detections over ${points.length} days`}>
        {points.map((p, i) => {
          const h = (p.count / max) * height;
          const x = i * (barWidth + gap);
          return (
            <g key={p.date}>
              <title>{`${shortDate(p.date)}: ${p.count} detection${p.count === 1 ? "" : "s"}`}</title>
              <rect x={x} y={height - h} width={barWidth} height={Math.max(h, p.count ? 2 : 0)} rx={3} className="chart-bar" />
              <rect x={x} y={0} width={barWidth} height={height} fill="transparent" />
              {showLabel(i, points.length) && (
                <text x={x + barWidth / 2} y={height + 16} textAnchor="middle" className="chart-label">
                  {shortDate(p.date)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </figure>
  );
}

/** Horizontal bars for a ranked breakdown (brands, sources, signals). */
export function BarList({ items, formatLabel = (k: string) => k }: {
  items: Record<string, number>;
  formatLabel?: (key: string) => string;
}) {
  const entries = Object.entries(items).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (!entries.length) return <p className="muted">No data yet.</p>;
  return (
    <ul className="barlist">
      {entries.map(([key, value]) => (
        <li key={key}>
          <span className="barlist-label">{formatLabel(key)}</span>
          <span className="barlist-track">
            <span className="barlist-fill" style={{ width: `${(value / max) * 100}%` }} />
          </span>
          <span className="barlist-value">{value}</span>
        </li>
      ))}
    </ul>
  );
}
