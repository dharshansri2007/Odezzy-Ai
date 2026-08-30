import { useState } from 'react';
import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, EmptyState } from '@/components/dashboard/LoadingState';
import { SeverityBadge, StatusBadge } from '@/components/dashboard/StatusBadge';

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
const CATEGORY_OPTIONS = [
  'all', 'undeclared-params', 'prompt-injection', 'leaked-secrets',
  'schema-mismatch', 'semantic-drift', 'shadow-server', 'excessive-permissions', 'quarantined'
] as const;

export function FindingsPage() {
  const sessions = useApi(() => api.listSessions(), []);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const latestSessionId = sessions.data?.sessions?.[sessions.data.sessions.length - 1];
  const session = useApi(
    () => (latestSessionId ? api.getSession(latestSessionId) : Promise.resolve(null)),
    [latestSessionId]
  );

  if (sessions.loading || session.loading) return <LoadingState message="Loading findings..." />;

  const findings = session.data?.findings || [];
  const filtered = findings.filter((f) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-semibold tracking-tight">Vulnerability Findings</h2>
        <p className="mt-1 text-sm text-muted-foreground">All discovered vulnerabilities across your MCP tool servers</p>
      </div>

      {/* Filters */}
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-border bg-card px-3 py-2 text-sm transition-colors focus:border-cyan/40 focus:outline-none"
        >
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s === 'all' ? 'All Severities' : s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="rounded-lg border border-border bg-card px-3 py-2 text-sm transition-colors focus:border-cyan/40 focus:outline-none"
        >
          {CATEGORY_OPTIONS.map((c) => (
            <option key={c} value={c}>{c === 'all' ? 'All Categories' : c}</option>
          ))}
        </select>
        <span className="ml-auto self-center text-sm text-muted-foreground">
          {filtered.length} of {findings.length} findings
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState message={findings.length === 0 ? 'No findings yet. Run a scan first.' : 'No findings match the current filters.'} />
      ) : (
        <div className="space-y-3">
          {filtered.map((f, i) => (
            <div key={f.id} className="surface lift fade-up p-5" style={{ ['--stagger' as string]: Math.min(i, 8) }}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={f.severity} />
                  <h3 className="font-medium">{f.title}</h3>
                </div>
                <span className="font-mono text-xs text-muted-foreground">{(f.confidence * 100).toFixed(0)}% confidence</span>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{f.description}</p>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <StatusBadge variant="neutral">{f.category}</StatusBadge>
                <span className="font-mono text-xs text-muted-foreground">Tool: {f.toolName}</span>
                <span className="font-mono text-xs text-muted-foreground">Server: {f.serverName}</span>
                {f.cweId && <span className="font-mono text-xs text-cyan">{f.cweId}</span>}
                {f.owaspCategory && <span className="text-xs text-muted-foreground">{f.owaspCategory}</span>}
              </div>
              <div className="mt-3 border-t border-border pt-3">
                <p className="text-xs font-medium text-muted-foreground">Evidence</p>
                <pre className="mt-1 overflow-x-auto rounded-lg bg-elevated p-3 font-mono text-xs">{f.evidence}</pre>
              </div>
              <div className="mt-3">
                <p className="text-xs font-medium text-muted-foreground">Remediation</p>
                <p className="mt-1 text-sm text-muted-foreground">{f.remediation}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
