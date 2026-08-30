import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, EmptyState } from '@/components/dashboard/LoadingState';
import { StatusBadge } from '@/components/dashboard/StatusBadge';
import { Ban, CheckCircle, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export function QuarantinePage() {
  const quarantine = useApi(() => api.getQuarantineLog(), []);
  const integrity = useApi(() => api.getQuarantineIntegrity(), []);

  if (quarantine.loading) return <LoadingState message="Loading quarantine registry..." />;

  const records = quarantine.data?.records || [];

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-semibold tracking-tight">Quarantine Registry</h2>
        <p className="mt-1 text-sm text-muted-foreground">Hash-chained, tamper-evident log of quarantined tools</p>
      </div>

      {/* Chain Integrity */}
      {integrity.data && (
        <div
          className={cn(
            'surface fade-up mb-8 flex items-center gap-3 p-4',
            integrity.data.valid ? 'border-safe/30' : 'border-danger/30 bg-danger/5'
          )}
        >
          {integrity.data.valid ? (
            <>
              <CheckCircle className="size-5 text-safe" />
              <span className="text-sm">Hash chain integrity verified ✓</span>
            </>
          ) : (
            <>
              <XCircle className="size-5 text-danger" />
              <span className="text-sm text-danger">Chain integrity broken at index {integrity.data.brokenAtIndex}</span>
            </>
          )}
        </div>
      )}

      {records.length === 0 ? (
        <EmptyState message="No quarantined tools. Quarantine records appear when vulnerabilities are remediated." />
      ) : (
        <div className="space-y-3">
          {records.map((r, i) => (
            <div key={`${r.toolName}-${r.serverName}-${i}`} className="surface lift fade-up border-danger/20 p-5" style={{ ['--stagger' as string]: i }}>
              <div className="flex flex-wrap items-center gap-3">
                <div className="rounded-xl bg-danger/10 p-2.5">
                  <Ban className="size-5 text-danger" />
                </div>
                <div>
                  <p className="font-mono text-sm font-medium">{r.toolName}</p>
                  <p className="text-xs text-muted-foreground">on {r.serverName}</p>
                </div>
                <StatusBadge variant="critical">Quarantined</StatusBadge>
              </div>
              <div className="mt-3 space-y-1 text-xs text-muted-foreground">
                <p><span className="font-medium">Reason:</span> {r.reason}</p>
                <p><span className="font-medium">Finding ID:</span> <code className="font-mono">{r.findingId}</code></p>
                <p className="flex items-center gap-1.5">
                  <span className="font-medium">Approved via:</span> <StatusBadge variant="warning">{r.tokenSource}</StatusBadge>
                </p>
                <p><span className="font-medium">Granted:</span> {new Date(r.grantedAt).toLocaleString()}</p>
                <p><span className="font-medium">Recorded:</span> {new Date(r.recordedAt).toLocaleString()}</p>
                <p><span className="font-medium">Chain Hash:</span> <code className="font-mono">{r.previousHash.slice(0, 24)}...</code></p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
