// Small inline SVG icons (no icon font, so they render identically everywhere).
const paths: Record<string, string> = {
  overview: "M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z",
  detections: "M12 2 4 5v6c0 5.5 3.4 10.3 8 11 4.6-.7 8-5.5 8-11V5l-8-3zm-1 14-4-4 1.4-1.4L11 13.2l4.6-4.6L17 10l-6 6z",
  campaigns:
    "M17 12a3 3 0 1 0-2.8-4H9.8A3 3 0 1 0 7 12a3 3 0 0 0 1.3-.3l2.4 3.6A3 3 0 1 0 13 15l2.5-3.3c.4.2.9.3 1.5.3z",
  ingest: "M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z",
  jobs: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 11h-5v-2h3V6h2v7z",
  evaluation: "M5 19h14v2H3V3h2v16zm3-3V9h3v7H8zm5 0V5h3v11h-3zm5 0v-5h3v5h-3z",
  settings:
    "M19.4 13a7.5 7.5 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7 7 0 0 0-1.7-1l-.4-2.6h-4l-.4 2.6a7 7 0 0 0-1.7 1l-2.5-1-2 3.5L4.6 11a7.5 7.5 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1a7 7 0 0 0 1.7 1l.4 2.6h4l.4-2.6a7 7 0 0 0 1.7-1l2.5 1 2-3.5-2.3-1.6zM12 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z",
  menu: "M3 6h18v2H3V6zm0 5h18v2H3v-2zm0 5h18v2H3v-2z",
};

export type IconName = keyof typeof paths;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="currentColor">
      <path d={paths[name]} />
    </svg>
  );
}
