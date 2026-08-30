import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react';

/** Full-page loading state — a few skeleton cards, matches the stat-grid shape. */
export function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="p-8">
      <div className="skeleton mb-2 h-7 w-56" />
      <div className="skeleton mb-8 h-4 w-80" />
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="skeleton h-28" style={{ ['--stagger' as string]: i }} />
        ))}
      </div>
      <div className="mt-4 flex items-center justify-center gap-2 pt-10 text-sm text-muted-foreground">
        <span className="size-1.5 animate-pulse rounded-full bg-cyan" />
        {message}
      </div>
    </div>
  );
}

/** Inline skeleton block for smaller regions (tables, lists) — no page chrome. */
export function InlineSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton h-16" style={{ ['--stagger' as string]: i }} />
      ))}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="fade-up flex flex-col items-center justify-center gap-3 py-20 text-center">
      <div className="rounded-full bg-danger/10 p-3">
        <AlertTriangle className="size-5 text-danger" />
      </div>
      <p className="max-w-sm text-sm text-danger">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-1 inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm transition-colors hover:bg-elevated"
        >
          <RefreshCw className="size-3.5" />
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="fade-up flex flex-col items-center justify-center gap-3 py-20 text-center">
      <div className="rounded-full bg-muted p-3">
        <Inbox className="size-5 text-muted-foreground" />
      </div>
      <p className="max-w-sm text-sm text-muted-foreground">{message}</p>
    </div>
  );
}
