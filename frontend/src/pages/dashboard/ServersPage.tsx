import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/LoadingState';
import { StatusBadge } from '@/components/dashboard/StatusBadge';
import { Server, Wrench } from 'lucide-react';

export function ServersPage() {
  const sessions = useApi(() => api.listSessions(), []);
  const latestSessionId = sessions.data?.sessions?.[sessions.data.sessions.length - 1];
  const session = useApi(
    () => (latestSessionId ? api.getSession(latestSessionId) : Promise.resolve(null)),
    [latestSessionId]
  );

  if (sessions.loading || session.loading) return <LoadingState message="Loading servers..." />;
  if (sessions.error) return <ErrorState message={sessions.error} onRetry={sessions.refetch} />;

  const servers = session.data?.discoveryResult?.servers || [];

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Discovered Servers</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          MCP servers and their exposed tools
        </p>
      </div>

      {servers.length === 0 ? (
        <EmptyState message="No servers discovered yet. Run a scan first." />
      ) : (
        <div className="space-y-4">
          {servers.map((server) => (
            <div key={server.serverName} className="surface p-6">
              <div className="flex items-center gap-3">
                <div className="rounded-xl bg-primary/10 p-2.5">
                  <Server className="size-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold">{server.serverName}</h3>
                  <p className="text-xs text-muted-foreground">v{server.serverVersion}</p>
                </div>
                <StatusBadge variant="neutral">{server.transport}</StatusBadge>
                <span className="ml-auto font-mono text-xs text-muted-foreground">
                  Scanned: {new Date(server.scannedAt).toLocaleString()}
                </span>
              </div>

              <div className="mt-4">
                <p className="text-xs font-medium text-muted-foreground mb-2">
                  <Wrench className="inline size-3 mr-1" />
                  {server.tools.length} tool(s)
                </p>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {server.tools.map((tool) => (
                    <div key={tool.name} className="rounded-lg border border-border p-3">
                      <p className="font-mono text-sm font-medium">{tool.name}</p>
                      {tool.description && (
                        <p className="mt-1 text-xs text-muted-foreground line-clamp-2">{tool.description}</p>
                      )}
                      {tool.inputSchema?.properties && (
                        <p className="mt-2 font-mono text-[10px] text-muted-foreground">
                          params: {Object.keys(tool.inputSchema.properties).join(', ')}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
