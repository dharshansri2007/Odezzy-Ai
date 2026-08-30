import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/LoadingState';
import { SeverityBadge, GradeBadge } from '@/components/dashboard/StatusBadge';
import { FileText, Clock, AlertTriangle } from 'lucide-react';

export function ReportsPage() {
  const report = useApi(() => api.getLatestReport(), []);

  if (report.loading) return <LoadingState message="Loading latest report..." />;
  if (report.error) return <ErrorState message={report.error} onRetry={report.refetch} />;
  if (!report.data) return <EmptyState message="No reports generated yet. Run a scan first." />;

  const r = report.data;
  const duration = r.metadata.scanDurationMs;
  const durationStr = duration > 60000 ? `${(duration / 60000).toFixed(1)}m` : `${(duration / 1000).toFixed(1)}s`;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Governance Report</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Full security governance report for the latest scan
        </p>
      </div>

      <div className="surface p-6 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileText className="size-5 text-primary" />
            <div>
              <h3 className="font-semibold">{r.projectName}</h3>
              <p className="text-xs text-muted-foreground">Agent v{r.metadata.agentVersion}</p>
            </div>
          </div>
          <div className="text-right text-xs text-muted-foreground">
            <p><Clock className="inline size-3 mr-1" />{durationStr}</p>
            <p>{new Date(r.scanCompletedAt).toLocaleString()}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
        <div className="surface p-4 text-center">
          <p className="font-mono text-3xl font-semibold">{r.summary.totalFindings}</p>
          <p className="text-xs text-muted-foreground">Total Findings</p>
        </div>
        {Object.entries(r.summary.bySeverity).map(([sev, count]) => (
          <div key={sev} className="surface p-4 text-center">
            <p className="font-mono text-2xl font-semibold">{count as number}</p>
            <SeverityBadge severity={sev} />
          </div>
        ))}
      </div>

      {r.summary.byCategory && Object.keys(r.summary.byCategory).length > 0 && (
        <div className="surface p-6 mb-6">
          <h3 className="text-sm font-medium text-muted-foreground mb-4">Findings by Category</h3>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(r.summary.byCategory).map(([cat, count]) => (
              <div key={cat} className="flex items-center justify-between rounded-lg border border-border p-3">
                <span className="text-sm">{cat}</span>
                <span className="font-mono text-sm font-semibold">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {r.incompleteAnalysis && (
        <div className="surface border-amber-500/30 bg-amber-500/5 p-6 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="size-4 text-amber-500" />
            <h3 className="text-sm font-medium">Incomplete Analysis (Fail-Visible)</h3>
          </div>
          {r.incompleteAnalysis.erroredTools.length > 0 && (
            <div className="mb-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">Errored Tools:</p>
              {r.incompleteAnalysis.erroredTools.map((t, i) => (
                <p key={i} className="text-xs text-muted-foreground">
                  {t.toolName} on {t.serverName} (stage: {t.stage}): {t.error}
                </p>
              ))}
            </div>
          )}
          {r.incompleteAnalysis.skippedStages.length > 0 && (
            <p className="text-xs text-muted-foreground">
              Skipped stages: {r.incompleteAnalysis.skippedStages.join(', ')}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
