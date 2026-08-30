import { useState, useEffect, useRef } from 'react';
import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, ErrorState } from '@/components/dashboard/LoadingState';
import { Terminal, RefreshCw, ArrowDown } from 'lucide-react';

export function LogsPage() {
  const [lineCount, setLineCount] = useState(100);
  const logs = useApi(() => api.getLogs(lineCount), [lineCount]);
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs.data, autoScroll]);

  // Auto-refresh every 5 seconds
  useEffect(() => {
    const id = setInterval(() => logs.refetch(), 5000);
    return () => clearInterval(id);
  }, [logs.refetch]);

  return (
    <div className="p-8 flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">System Logs</h1>
          <p className="mt-1 text-sm text-muted-foreground">Live log output from Odezzy AI</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={lineCount}
            onChange={(e) => setLineCount(Number(e.target.value))}
            className="rounded-lg border border-border bg-card px-3 py-2 text-sm"
          >
            <option value={50}>50 lines</option>
            <option value={100}>100 lines</option>
            <option value={250}>250 lines</option>
            <option value={500}>500 lines</option>
          </select>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors ${
              autoScroll ? 'border-cyan/40 text-cyan' : 'border-border text-muted-foreground'
            }`}
          >
            <ArrowDown className="size-4" />
            Auto-scroll
          </button>
          <button
            onClick={logs.refetch}
            className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm transition-colors hover:bg-elevated"
          >
            <RefreshCw className="size-4" />
            Refresh
          </button>
        </div>
      </div>

      {logs.error ? (
        <ErrorState message={logs.error} onRetry={logs.refetch} />
      ) : (
        <div
          ref={containerRef}
          className="surface flex-1 min-h-0 overflow-y-auto p-4"
        >
          <div className="flex items-center gap-2 mb-3 pb-3 border-b border-border">
            <Terminal className="size-4 text-cyan" />
            <span className="font-mono text-xs text-muted-foreground">odezzy-ai.log</span>
            <span className="ml-auto size-2 rounded-full bg-safe animate-pulse" />
          </div>
          <pre className="font-mono text-[12px] leading-6 whitespace-pre-wrap break-all">
            {logs.data?.logs?.join('\n') || 'No logs available. Start a scan to generate logs.'}
          </pre>
        </div>
      )}
    </div>
  );
}
