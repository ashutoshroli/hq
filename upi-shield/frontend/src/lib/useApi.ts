import { useCallback, useEffect, useRef, useState } from "react";

export interface ApiState<T> {
  data: T | undefined;
  error: string | undefined;
  loading: boolean;
  /** Re-run the request; keeps the previous data visible while loading. */
  reload: () => void;
}

interface Settled<T> {
  key: string;
  data: T | undefined;
  error: string | undefined;
}

/**
 * Runs an API call when ``deps`` change and exposes loading / error state.
 * ``intervalMs`` optionally refreshes the data in the background (e.g. job progress).
 * Loading is derived (the latest request has not settled yet), so no state is set
 * synchronously inside the effect.
 */
export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = [], intervalMs?: number): ApiState<T> {
  const [tick, setTick] = useState(0);
  const [settled, setSettled] = useState<Settled<T>>({ key: "", data: undefined, error: undefined });
  const fetcherRef = useRef(fetcher);
  const key = JSON.stringify([...deps, tick]);

  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    fetcherRef
      .current()
      .then((data) => {
        if (!cancelled) setSettled({ key, data, error: undefined });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setSettled((prev) => ({ key, data: prev.data, error: err instanceof Error ? err.message : String(err) }));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [key]);

  useEffect(() => {
    if (!intervalMs) return;
    const timer = window.setInterval(reload, intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, reload]);

  return { data: settled.data, error: settled.error, loading: settled.key !== key, reload };
}
