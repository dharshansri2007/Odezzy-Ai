import { useSyncExternalStore } from 'react';

/**
 * Tracks whether the last round of API calls fell back to the bundled demo
 * fixtures (lib/demo-data.ts) because the real Odezzy API server wasn't
 * reachable. `lib/api.ts` is the only writer; components just read it via
 * `useDemoMode()` to render a "showing sample data" banner instead of a
 * scary connection error.
 */
let demo = false;
const listeners = new Set<() => void>();

export function setDemoMode(value: boolean) {
  if (value === demo) return;
  demo = value;
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot() {
  return demo;
}

export function useDemoMode() {
  return useSyncExternalStore(subscribe, getSnapshot);
}
