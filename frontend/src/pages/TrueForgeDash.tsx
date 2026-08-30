import { Routes, Route, NavLink, Link, Outlet } from 'react-router-dom';
import { Shield, ArrowLeft, Users, GitBranch, Activity, Settings } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { StatCard } from '@/components/dashboard/StatCard';
import { StatusBadge } from '@/components/dashboard/StatusBadge';
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/LoadingState';

function TrueForgeLayout() {
  return (
    <div className="flex h-screen bg-background">
      <aside className="flex w-64 flex-col border-r border-border bg-card">
        <div className="flex h-16 items-center gap-2.5 border-b border-border px-6">
          <span className="size-6 rounded-md bg-cyan shadow-[0_0_18px_-2px_var(--brand-cyan)]" />
          <span className="font-semibold tracking-tight">TrueForge</span>
          <StatusBadge variant="info" className="ml-auto">Sponsor</StatusBadge>
        </div>
        <nav className="flex-1 overflow-y-auto p-3">
          <ul className="space-y-1">
            <li>
              <NavLink to="/trueforge" end className={({ isActive }) => cn('flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors', isActive ? 'bg-cyan/10 text-cyan' : 'text-muted-foreground hover:bg-elevated hover:text-foreground')}>
                <Activity className="size-4" />
                Overview
              </NavLink>
            </li>
            <li>
              <NavLink to="/trueforge/sessions" className={({ isActive }) => cn('flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors', isActive ? 'bg-cyan/10 text-cyan' : 'text-muted-foreground hover:bg-elevated hover:text-foreground')}>
                <GitBranch className="size-4" />
                Agent Sessions
              </NavLink>
            </li>
            <li>
              <NavLink to="/trueforge/approvals" className={({ isActive }) => cn('flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors', isActive ? 'bg-cyan/10 text-cyan' : 'text-muted-foreground hover:bg-elevated hover:text-foreground')}>
                <Users className="size-4" />
                Approval History
              </NavLink>
            </li>
            <li>
              <NavLink to="/trueforge/connectors" className={({ isActive }) => cn('flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors', isActive ? 'bg-cyan/10 text-cyan' : 'text-muted-foreground hover:bg-elevated hover:text-foreground')}>
                <Settings className="size-4" />
                MCP Connectors
              </NavLink>
            </li>
          </ul>
        </nav>
        <div className="border-t border-border p-3 space-y-1">
          <Link to="/dashboard" className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
            <ArrowLeft className="size-4" />
            Odezzy Dashboard
          </Link>
          <Link to="/" className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
            <ArrowLeft className="size-4" />
            Landing Page
          </Link>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}

function TrueForgeOverview() {
  const sessions = useApi(() => api.listSessions(), []);
  const quarantine = useApi(() => api.getQuarantineLog(), []);

  const latestSessionId = sessions.data?.sessions?.[sessions.data.sessions.length - 1];
  const session = useApi(
    () => (latestSessionId ? api.getSession(latestSessionId) : Promise.resolve(null)),
    [latestSessionId]
  );

  const approvalSummary = session.data?.approvalGateSummary;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">TrueForge Integration</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Human-in-the-loop orchestration layer for Odezzy AI
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-8">
        <StatCard title="Agent Sessions" value={sessions.data?.sessions?.length || 0} icon={GitBranch} />
        <StatCard title="Total Approvals" value={approvalSummary?.approved || 0} icon={Users} variant="success" />
        <StatCard title="Denied" value={approvalSummary?.deniedReviewed || 0} icon={Shield} variant="danger" />
        <StatCard title="Quarantined" value={quarantine.data?.records?.length || 0} icon={Shield} variant="warning" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="surface p-6">
          <h3 className="font-semibold mb-4">How TrueForge Integration Works</h3>
          <div className="space-y-3 text-sm text-muted-foreground">
            <div className="flex gap-3">
              <span className="bg-gradient-brand size-1.5 mt-2 shrink-0 rounded-full" />
              <p><strong className="text-foreground">Session Creation:</strong> Each fullscan creates a TrueForge agent session with scan context and remediation MCP connector.</p>
            </div>
            <div className="flex gap-3">
              <span className="bg-gradient-brand size-1.5 mt-2 shrink-0 rounded-full" />
              <p><strong className="text-foreground">Phase Narration:</strong> Scan progress is streamed into TrueForge's chat UI via createTurn API calls.</p>
            </div>
            <div className="flex gap-3">
              <span className="bg-gradient-brand size-1.5 mt-2 shrink-0 rounded-full" />
              <p><strong className="text-foreground">Approval Gating:</strong> When vulnerabilities are found, remediation proposals are sent as TrueForge tool calls with <code className="font-mono text-xs bg-elevated px-1 rounded">requireApprovalForTools: ["@all"]</code>.</p>
            </div>
            <div className="flex gap-3">
              <span className="bg-gradient-brand size-1.5 mt-2 shrink-0 rounded-full" />
              <p><strong className="text-foreground">Shadow Detection:</strong> TrueForge's MCP registry is cross-referenced against local configs to catch unregistered servers.</p>
            </div>
          </div>
        </div>

        {approvalSummary && (
          <div className="surface p-6">
            <h3 className="font-semibold mb-4">Latest Approval Gate Summary</h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center p-3 rounded-lg border border-border">
                <span className="text-sm">Total Requests</span>
                <span className="font-mono font-semibold">{approvalSummary.totalRequests}</span>
              </div>
              <div className="flex justify-between items-center p-3 rounded-lg border border-safe/20 bg-safe/5">
                <span className="text-sm">Approved</span>
                <span className="font-mono font-semibold text-safe">{approvalSummary.approved}</span>
              </div>
              <div className="flex justify-between items-center p-3 rounded-lg border border-danger/20 bg-danger/5">
                <span className="text-sm">Denied (Reviewed)</span>
                <span className="font-mono font-semibold text-danger">{approvalSummary.deniedReviewed}</span>
              </div>
              <div className="flex justify-between items-center p-3 rounded-lg border border-amber-500/20 bg-amber-500/5">
                <span className="text-sm">Pending</span>
                <span className="font-mono font-semibold text-amber-500">{approvalSummary.pending}</span>
              </div>
              <div className="flex justify-between items-center p-3 rounded-lg border border-border">
                <span className="text-sm">Plumbing Unresolved</span>
                <span className="font-mono font-semibold">{approvalSummary.plumbingUnresolved}</span>
              </div>
              <div className="flex justify-between items-center p-3 rounded-lg border border-border">
                <span className="text-sm">No Request</span>
                <span className="font-mono font-semibold">{approvalSummary.noRequest}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function TrueForgeSessionsPage() {
  const sessions = useApi(() => api.listSessions(), []);
  if (sessions.loading) return <LoadingState />;
  if (sessions.error) return <ErrorState message={sessions.error} />;

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold tracking-tight mb-8">Agent Sessions</h1>
      {(sessions.data?.sessions || []).length === 0 ? (
        <EmptyState message="No TrueForge agent sessions yet. Run a fullscan to create one." />
      ) : (
        <div className="space-y-3">
          {sessions.data!.sessions.map((id) => (
            <div key={id} className="surface p-4">
              <p className="font-mono text-sm">{id}</p>
              <p className="text-xs text-muted-foreground mt-1">TrueForge agent session</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TrueForgeApprovalsPage() {
  const quarantine = useApi(() => api.getQuarantineLog(), []);
  if (quarantine.loading) return <LoadingState />;
  if (quarantine.error) return <ErrorState message={quarantine.error} />;

  const records = quarantine.data?.records || [];

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold tracking-tight mb-8">Approval History</h1>
      <p className="mb-6 text-sm text-muted-foreground">
        Human approvals that led to tool quarantine via TrueForge or CLI
      </p>
      {records.length === 0 ? (
        <EmptyState message="No approval records yet." />
      ) : (
        <div className="space-y-3">
          {records.map((r, i) => (
            <div key={i} className="surface p-5">
              <div className="flex items-center gap-3">
                <StatusBadge variant={r.tokenSource === 'trueforge-ui' || r.tokenSource === 'trueforge-gated-tool-call' ? 'success' : 'warning'}>
                  {r.tokenSource}
                </StatusBadge>
                <span className="font-mono text-sm font-medium">{r.toolName}</span>
                <span className="text-xs text-muted-foreground">on {r.serverName}</span>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{r.reason}</p>
              <p className="mt-1 text-xs text-muted-foreground">Granted: {new Date(r.grantedAt).toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TrueForgeConnectorsPage() {
  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold tracking-tight mb-8">MCP Connectors</h1>
      <div className="surface p-6">
        <h3 className="font-semibold mb-4">Remediation Server Connector</h3>
        <div className="space-y-3 text-sm">
          <div className="flex justify-between items-center p-3 rounded-lg border border-border">
            <span className="text-muted-foreground">Server Name</span>
            <code className="font-mono text-xs">odezzy-remediation</code>
          </div>
          <div className="flex justify-between items-center p-3 rounded-lg border border-border">
            <span className="text-muted-foreground">URL</span>
            <code className="font-mono text-xs">http://localhost:8791/mcp</code>
          </div>
          <div className="flex justify-between items-center p-3 rounded-lg border border-border">
            <span className="text-muted-foreground">Transport</span>
            <code className="font-mono text-xs">Streamable HTTP (stateless)</code>
          </div>
          <div className="flex justify-between items-center p-3 rounded-lg border border-border">
            <span className="text-muted-foreground">Tool Approval</span>
            <code className="font-mono text-xs">requireApprovalForTools: ["@all"]</code>
          </div>
          <div className="flex justify-between items-center p-3 rounded-lg border border-border">
            <span className="text-muted-foreground">Exposed Tool</span>
            <code className="font-mono text-xs">apply_fix(findingId)</code>
          </div>
        </div>
        <div className="mt-4 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
          <p className="text-xs text-amber-500">
            ⚠️ Register this connector manually in TrueForge → Settings → Connectors → "+ Add MCP Server" before running fullscan.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function TrueForgeDash() {
  return (
    <Routes>
      <Route element={<TrueForgeLayout />}>
        <Route index element={<TrueForgeOverview />} />
        <Route path="sessions" element={<TrueForgeSessionsPage />} />
        <Route path="approvals" element={<TrueForgeApprovalsPage />} />
        <Route path="connectors" element={<TrueForgeConnectorsPage />} />
      </Route>
    </Routes>
  );
}
