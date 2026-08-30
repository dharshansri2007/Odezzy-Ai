import { useState, useEffect, useRef } from 'react';
import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { Terminal, RefreshCw, ArrowDown } from 'lucide-react';
import { cn } from '@/lib/utils';

/** Colors the `[scope]` prefix that the real winston logger writes at the start of each line. */
function LogLine({ line }: { line: string }) {
  const match = line.match(/^\[([\w-]+)\]\s*(.*)$/);
  if (!match) return <p className="text-muted-foreground">{line}</p>;
  const [, scope, rest] = match;
  const isWarn = /rate-limited|drift|revok|skip|error/i.test(rest);
  return (
    <p>
      <span className="text-cyan">[{scope}]</span>{' '}
      <span className={isWarn ? 'text-amber-500' : 'text-foreground'}>{rest}</span>
    </p>
  );
}

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

  useEffect(() => {
    const id = setInterval(() => logs.refetch(), 5000);
    return () => clearInterval(id);
  }, [logs.refetch]);

  const lines = logs.data?.logs ?? [];

  return (
    <div className="flex h-full flex-col p-8">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">System Logs</h2>
          <p className="mt-1 text-sm text-muted-foreground">Live log output from Odezzy AI</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={lineCount}
            onChange={(e) => setLineCount(Number(e.target.value))}
            className="rounded-lg border border-border bg-card px-3 py-2 text-sm transition-colors focus:border-cyan/40 focus:outline-none"
          >
            <option value={50}>50 lines</option>
            <option value={100}>100 lines</option>
            <option value={250}>250 lines</option>
            <option value={500}>500 lines</option>
          </select>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={cn(
              'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors',
              autoScroll ? 'border-cyan/40 text-cyan' : 'border-border text-muted-foreground hover:bg-elevated'
            )}
          >
            <ArrowDown className="size-4" />
            Auto-scroll
          </button>
          <button
            onClick={logs.refetch}
            className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm transition-colors hover:bg-elevated"
          >
            <RefreshCw className={cn('size-4', logs.loading && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      <div ref={containerRef} className="surface min-h-0 flex-1 overflow-y-auto bg-elevated/40 p-4">
        <div className="mb-3 flex items-center gap-2 border-b border-border pb-3">
          <Terminal className="size-4 text-cyan" />
          <span className="font-mono text-xs text-muted-foreground">odezzy-ai.log</span>
          <span className="pulse-dot ml-auto size-2 rounded-full bg-safe text-safe" />
        </div>
        <div className="space-y-1 font-mono text-[12px] leading-6 break-all whitespace-pre-wrap">
          {lines.length === 0 ? (
            <p className="text-muted-foreground">No logs available. Start a scan to generate logs.</p>
          ) : (
            lines.map((line, i) => <LogLine key={i} line={line} />)
          )}
        </div>
      </div>
    </div>
  );
}
