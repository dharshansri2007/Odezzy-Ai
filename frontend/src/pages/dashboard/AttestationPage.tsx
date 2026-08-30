import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { StatCard } from '@/components/dashboard/StatCard';
import { LoadingState, EmptyState } from '@/components/dashboard/LoadingState';
import { StatusBadge } from '@/components/dashboard/StatusBadge';
import { Award, Key, ShieldCheck, ShieldX } from 'lucide-react';

export function AttestationPage() {
  const ledger = useApi(() => api.getAttestationLedger(), []);
  const pubKey = useApi(() => api.getAttestationPublicKey(), []);

  if (ledger.loading) return <LoadingState message="Loading attestation ledger..." />;

  const records = ledger.data?.records || [];
  const attested = records.filter((r) => r.status === 'attested');
  const revoked = records.filter((r) => r.status === 'revoked');

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-semibold tracking-tight">Attestation Ledger</h2>
        <p className="mt-1 text-sm text-muted-foreground">Ed25519-signed, hash-chained cryptographic trust records</p>
      </div>

      <div className="mb-8 grid gap-4 md:grid-cols-3">
        <StatCard title="Total Records" value={records.length} icon={Award} style={{ ['--stagger' as string]: 0 }} />
        <StatCard title="Attested" value={attested.length} icon={ShieldCheck} variant="success" style={{ ['--stagger' as string]: 1 }} />
        <StatCard title="Revoked" value={revoked.length} icon={ShieldX} variant="danger" style={{ ['--stagger' as string]: 2 }} />
      </div>

      {pubKey.data?.publicKey && (
        <div className="surface fade-up mb-8 p-4" style={{ ['--stagger' as string]: 3 }}>
          <div className="mb-2 flex items-center gap-2">
            <Key className="size-4 text-cyan" />
            <p className="text-xs font-medium text-muted-foreground">Public Key (Ed25519)</p>
          </div>
          <pre className="overflow-x-auto font-mono text-[11px] text-muted-foreground">{pubKey.data.publicKey}</pre>
        </div>
      )}

      {records.length === 0 ? (
        <EmptyState message="No attestation records yet. Run a scan to generate attestations." />
      ) : (
        <div className="space-y-3">
          {records.map((r, i) => (
            <div
              key={`${r.toolName}-${r.serverName}-${r.timestamp}-${i}`}
              className={`surface lift fade-up p-5 ${r.status === 'revoked' ? 'border-danger/30 bg-danger/5' : 'border-safe/20'}`}
              style={{ ['--stagger' as string]: Math.min(i, 8) }}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  {r.status === 'attested' ? (
                    <ShieldCheck className="size-5 text-safe" />
                  ) : (
                    <ShieldX className="size-5 text-danger" />
                  )}
                  <div>
                    <p className="font-mono text-sm font-medium">{r.toolName}</p>
                    <p className="text-xs text-muted-foreground">on {r.serverName}</p>
                  </div>
                </div>
                <StatusBadge variant={r.status === 'attested' ? 'success' : 'critical'}>{r.status}</StatusBadge>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                <div>
                  <span className="font-medium">Definition Hash:</span>
                  <code className="ml-1 font-mono">{r.definitionHash.slice(0, 16)}...</code>
                </div>
                <div>
                  <span className="font-medium">Signature:</span>
                  <code className="ml-1 font-mono">{r.signature.slice(0, 16)}...</code>
                </div>
                <div>
                  <span className="font-medium">Timestamp:</span>
                  <span className="ml-1">{new Date(r.timestamp).toLocaleString()}</span>
                </div>
                <div>
                  <span className="font-medium">Chain Hash:</span>
                  <code className="ml-1 font-mono">{r.previousRecordHash.slice(0, 16)}...</code>
                </div>
              </div>
              {r.revokedReason && (
                <div className="mt-3 rounded-lg bg-danger/10 p-3">
                  <p className="text-xs font-medium text-danger">Revocation Reason</p>
                  <p className="mt-1 text-xs text-muted-foreground">{r.revokedReason}</p>
                  {r.revokedAt && <p className="mt-1 text-xs text-muted-foreground">Revoked: {new Date(r.revokedAt).toLocaleString()}</p>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
