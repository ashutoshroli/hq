import { type ComponentProps, Suspense, lazy } from "react";

import type { GraphView as GraphViewType } from "./GraphView";
import { Spinner } from "./ui";

// Cytoscape is the largest dependency; load it only when a graph is shown.
const GraphView = lazy(() => import("./GraphView").then((m) => ({ default: m.GraphView })));

export function LazyGraphView(props: ComponentProps<typeof GraphViewType>) {
  return (
    <Suspense fallback={<Spinner label="Loading the graph…" />}>
      <GraphView {...props} />
    </Suspense>
  );
}
