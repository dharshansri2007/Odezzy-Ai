import { useEffect, useSyncExternalStore } from 'react';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'odezzy-theme';
const listeners = new Set<() => void>();

function readInitial(): Theme {
  if (typeof window === 'undefined') return 'dark';
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === 'light' || stored === 'dark') return stored;
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

let theme: Theme = readInitial();

function apply(t: Theme) {
  document.documentElement.classList.toggle('light', t === 'light');
}

if (typeof document !== 'undefined') apply(theme);

export function setTheme(next: Theme) {
  theme = next;
  window.localStorage.setItem(STORAGE_KEY, next);
  apply(next);
  listeners.forEach((l) => l());
}

export function toggleTheme() {
  setTheme(theme === 'light' ? 'dark' : 'light');
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): Theme {
  return theme;
}

/** Reactive theme value + toggle, safe to call from any component. */
export function useTheme() {
  const value = useSyncExternalStore(subscribe, getSnapshot, (): Theme => 'dark');
  // Re-assert on mount in case another tab/route changed the DOM class.
  useEffect(() => apply(value), [value]);
  return { theme: value, toggleTheme, setTheme };
}
