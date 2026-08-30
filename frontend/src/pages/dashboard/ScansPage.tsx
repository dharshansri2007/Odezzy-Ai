import { useState } from 'react';
import { Play, RefreshCw, Server } from 'lucide-react';
import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, EmptyState } from '@/components/dashboard/LoadingState';
import { StatusBadge, SeverityBadge } from '@/components/dashboard/StatusBadge';
import { cn } from '@/lib/utils';

export function ScansPage() {
  const sessions = useApi(() => api.listSessions(), []);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scanRunning, setScanRunning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const selectedSession = useApi(
    () => (selectedId ? api.getSession(selectedId) : Promise.resolve(null)),
    [selectedId]
  );

  const handleStartScan = async () => {
    setScanRunning(true);
    setScanMessage('');
    try {
      const result = await api.startScan();
      setScanMessage(result.message || `Scan started — session ${result.sessionId}`);
      sessions.refetch();
    } catch (err) {
      setScanMessage(`Failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setScanRunning(false);
    }
  };

  if (sessions.loading) return <LoadingState message="Loading scan sessions..." />;

  const sessionIds = sessions.data?.sessions || [];

  return (
    <div className="p-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">Scan Sessions</h2>
          <p className="mt-1 text-sm text-muted-foreground">View past scans or trigger a new security analysis</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={sessions.refetch}
            className="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2.5 text-sm transition-colors hover:bg-elevated"
          >
            <RefreshCw className="size-4" />
            Refresh
          </button>
          <button
            onClick={handleStartScan}
            disabled={scanRunning}
            className="glow-hover bg-gradient-brand inline-flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium text-primary-foreground transition-transform active:scale-95 disabled:opacity-50"
          >
            <Play className={cn('size-4', scanRunning && 'animate-pulse')} />
            {scanRunning ? 'Scanning...' : 'Start New Scan'}
          </button>
        </div>
      </div>

      {scanMessage && <div className="fade-up surface mb-4 p-3 text-sm">{scanMessage}</div>}

      {sessionIds.length === 0 ? (
        <EmptyState message="No scan sessions found. Start a scan to begin." />
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Session List */}
          <div className="space-y-2 lg:col-span-1">
            {sessionIds.map((id, i) => (
              <button
                key={id}
                onClick={() => setSelectedId(id)}
                style={{ ['--stagger' as string]: i }}
                className={cn(
                  'surface lift fade-up w-full p-4 text-left transition-colors hover:border-cyan/40',
                  selectedId === id && 'border-cyan/50 shadow-[var(--glow-brand)]'
                )}
              >
                <p className="font-mono text-xs text-muted-foreground">Session</p>
                <p className="mt-1 truncate font-mono text-xs">{id}</p>
              </button>
            ))}
          </div>

          {/* Session Detail */}
          <div className="lg:col-span-2">
            {!selectedId ? (
              <div className="surface flex flex-col items-center gap-2 p-10 text-center text-sm text-muted-foreground">
                <Server className="size-5" />
                Select a session to view details
              </div>
            ) : selectedSession.loading ? (
              <LoadingState message="Loading session details..." />
            ) : selectedSession.data ? (
              <div className="surface fade-up space-y-6 p-6">
                <div>
                  <h3 className="font-semibold">Session Details</h3>
                  <dl className="mt-3 grid grid-cols-2 gap-y-2 text-sm">
                    <dt className="text-muted-foreground">ID</dt>
                    <dd className="truncate font-mono text-xs">{selectedSession.data.id}</dd>
                    <dt className="text-muted-foreground">Started</dt>
                    <dd>{new Date(selectedSession.data.startedAt).toLocaleString()}</dd>
                    <dt className="text-muted-foreground">Completed</dt>
                    <dd>{selectedSession.data.completedAt ? new Date(selectedSession.data.completedAt).toLocaleString() : 'In progress'}</dd>
                    <dt className="text-muted-foreground">Findings</dt>
                    <dd className="font-mono">{selectedSession.data.findings.length}</dd>
                    <dt className="text-muted-foreground">Servers</dt>
                    <dd className="font-mono">{selectedSession.data.discoveryResult?.servers?.length || 0}</dd>
                    <dt className="text-muted-foreground">Tools</dt>
                    <dd className="font-mono">{selectedSession.data.discoveryResult?.totalTools || 0}</dd>
                  </dl>
                </div>

                {selectedSession.data.findings.length > 0 && (
                  <div>
                    <h4 className="mb-3 text-sm font-medium">Findings</h4>
                    <div className="space-y-2">
                      {selectedSession.data.findings.map((f) => (
                        <div key={f.id} className="rounded-lg border border-border p-3 transition-colors hover:border-cyan/30">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={f.severity} />
                            <span className="text-sm font-medium">{f.title}</span>
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">{f.description}</p>
                          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                            <span>
                              Tool: <code className="font-mono">{f.toolName}</code>
                            </span>
                            <span>
                              Server: <code className="font-mono">{f.serverName}</code>
                            </span>
                            <StatusBadge variant="neutral">{f.category}</StatusBadge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
