import { FlaskConical } from 'lucide-react';
import { useDemoMode } from '@/lib/demo-mode';

/**
 * Shown whenever the last API call fell back to bundled fixtures because
 * the real Odezzy API server (`npm run api`, port 8790) wasn't reachable.
 * Deliberately calm — this is expected in a lot of setups, not an error.
 */
export function DemoBanner() {
  const demo = useDemoMode();
  if (!demo) return null;

  return (
    <div className="fade-up mx-8 mt-8 flex items-center gap-2.5 rounded-xl border border-cyan/25 bg-cyan/5 px-4 py-2.5 text-sm text-foreground">
      <FlaskConical className="size-4 shrink-0 text-cyan" />
      <span>
        Showing sample scan data — the Odezzy API server isn't reachable.
        Run <code className="rounded bg-cyan/10 px-1.5 py-0.5 font-mono text-xs text-cyan">npm run api</code> to
        connect this dashboard to a real scan.
      </span>
    </div>
  );
}
