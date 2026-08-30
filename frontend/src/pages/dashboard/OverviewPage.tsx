import { Shield, Bug, Award, Ban, Server, AlertTriangle } from 'lucide-react';
import { StatCard } from '@/components/dashboard/StatCard';
import { StatusBadge, GradeBadge, SeverityBadge } from '@/components/dashboard/StatusBadge';
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/LoadingState';
import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

export function OverviewPage() {
  const sessions = useApi(() => api.listSessions(), []);
  const attestation = useApi(() => api.getAttestationLedger(), []);
  const quarantine = useApi(() => api.getQuarantineLog(), []);

  // Load latest session details if sessions exist
  const latestSessionId = sessions.data?.sessions?.[sessions.data.sessions.length - 1];
  const latestSession = useApi(
    () => (latestSessionId ? api.getSession(latestSessionId) : Promise.resolve(null)),
    [latestSessionId]
  );

  const isLoading = sessions.loading || attestation.loading || quarantine.loading;
  const hasError = sessions.error || attestation.error;

  if (isLoading) return <LoadingState message="Loading dashboard data..." />;

  const sessionData = latestSession.data;
  const findings = sessionData?.findings || [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    if (f.severity in severityCounts) severityCounts[f.severity as keyof typeof severityCounts]++;
  });

  const attestedCount = attestation.data?.records?.filter((r) => r.status === 'attested').length || 0;
  const revokedCount = attestation.data?.records?.filter((r) => r.status === 'revoked').length || 0;
  const quarantinedCount = quarantine.data?.records?.length || 0;
  const totalSessions = sessions.data?.sessions?.length || 0;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard Overview</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          MCP Security Red-Teaming Agent — monitoring your tool supply chain
        </p>
      </div>

      {hasError && (
        <div className="mb-6 surface border-danger/30 bg-danger/5 p-4 text-sm text-danger">
          <AlertTriangle className="inline size-4 mr-2" />
          Backend not reachable. Start the API server with <code className="font-mono bg-danger/10 px-1 rounded">npm run api</code> on port 8790.
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Findings"
          value={findings.length}
          subtitle={`${severityCounts.critical} critical, ${severityCounts.high} high`}
          icon={Bug}
          variant={severityCounts.critical > 0 ? 'danger' : 'default'}
        />
        <StatCard
          title="Scan Sessions"
          value={totalSessions}
          subtitle={sessionData?.completedAt ? `Latest: ${new Date(sessionData.completedAt).toLocaleDateString()}` : 'No scans yet'}
          icon={Shield}
        />
        <StatCard
          title="Attested Tools"
          value={attestedCount}
          subtitle={`${revokedCount} revoked`}
          icon={Award}
          variant="success"
        />
        <StatCard
          title="Quarantined"
          value={quarantinedCount}
          subtitle="Tools permanently banned"
          icon={Ban}
          variant={quarantinedCount > 0 ? 'danger' : 'default'}
        />
      </div>

      {/* Recent Findings */}
      {findings.length > 0 && (
        <div className="mt-8">
          <h2 className="text-lg font-semibold mb-4">Recent Findings</h2>
          <div className="surface overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Severity</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Title</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Tool</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Server</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Category</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {findings.slice(0, 10).map((f) => (
                  <tr key={f.id} className="border-b border-border last:border-0 hover:bg-elevated/50 transition-colors">
                    <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-3 font-medium">{f.title}</td>
                    <td className="px-4 py-3 font-mono text-xs">{f.toolName}</td>
                    <td className="px-4 py-3 font-mono text-xs">{f.serverName}</td>
                    <td className="px-4 py-3">
                      <StatusBadge variant="neutral">{f.category}</StatusBadge>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{(f.confidence * 100).toFixed(0)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Severity Distribution */}
      {findings.length > 0 && (
        <div className="mt-8 grid gap-4 md:grid-cols-2">
          <div className="surface p-6">
            <h3 className="text-sm font-medium text-muted-foreground mb-4">Severity Distribution</h3>
            <div className="space-y-3">
              {Object.entries(severityCounts).map(([sev, count]) => (
                <div key={sev} className="flex items-center gap-3">
                  <SeverityBadge severity={sev} />
                  <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all duration-500',
                        sev === 'critical' || sev === 'high' ? 'bg-danger' :
                        sev === 'medium' ? 'bg-amber-500' : 'bg-cyan'
                      )}
                      style={{ width: `${findings.length ? (count / findings.length) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="font-mono text-xs text-muted-foreground w-8 text-right">{count}</span>
                </div>
              ))}
            </div>
          </div>

          {sessionData?.approvalGateSummary && (
            <div className="surface p-6">
              <h3 className="text-sm font-medium text-muted-foreground mb-4">Approval Gate Summary</h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg bg-safe/5 border border-safe/20 p-3">
                  <p className="font-mono text-xl font-semibold text-safe">{sessionData.approvalGateSummary.approved}</p>
                  <p className="text-xs text-muted-foreground">Approved</p>
                </div>
                <div className="rounded-lg bg-danger/5 border border-danger/20 p-3">
                  <p className="font-mono text-xl font-semibold text-danger">{sessionData.approvalGateSummary.deniedReviewed}</p>
                  <p className="text-xs text-muted-foreground">Denied</p>
                </div>
                <div className="rounded-lg bg-amber-500/5 border border-amber-500/20 p-3">
                  <p className="font-mono text-xl font-semibold text-amber-500">{sessionData.approvalGateSummary.pending}</p>
                  <p className="text-xs text-muted-foreground">Pending</p>
                </div>
                <div className="rounded-lg bg-muted p-3">
                  <p className="font-mono text-xl font-semibold">{sessionData.approvalGateSummary.plumbingUnresolved}</p>
                  <p className="text-xs text-muted-foreground">Unresolved</p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {findings.length === 0 && !hasError && (
        <EmptyState message="No scan data yet. Run a scan from the Scans tab or via CLI." />
      )}
    </div>
  );
}
