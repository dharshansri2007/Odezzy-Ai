import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, EmptyState } from '@/components/dashboard/LoadingState';
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

  const servers = session.data?.discoveryResult?.servers || [];

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-semibold tracking-tight">Discovered Servers</h2>
        <p className="mt-1 text-sm text-muted-foreground">MCP servers and their exposed tools</p>
      </div>

      {servers.length === 0 ? (
        <EmptyState message="No servers discovered yet. Run a scan first." />
      ) : (
        <div className="space-y-4">
          {servers.map((server, i) => (
            <div key={server.serverName} className="surface fade-up p-6" style={{ ['--stagger' as string]: i }}>
              <div className="flex flex-wrap items-center gap-3">
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
                <p className="mb-2 text-xs font-medium text-muted-foreground">
                  <Wrench className="mr-1 inline size-3" />
                  {server.tools.length} tool(s)
                </p>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {server.tools.map((tool) => (
                    <div key={tool.name} className="rounded-lg border border-border p-3 transition-colors hover:border-cyan/30">
                      <p className="font-mono text-sm font-medium">{tool.name}</p>
                      {tool.description && (
                        <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{tool.description}</p>
                      )}
                      {tool.inputSchema?.properties && (
                        <p className="mt-2 font-mono text-[10px] text-muted-foreground">
                          params: {Object.keys(tool.inputSchema.properties).join(', ') || 'none declared'}
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
