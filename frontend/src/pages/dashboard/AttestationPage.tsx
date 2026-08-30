import { useApi } from '@/hooks/use-api';
import { api } from '@/lib/api';
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/LoadingState';
import { StatusBadge } from '@/components/dashboard/StatusBadge';
import { Award, Key, ShieldCheck, ShieldX } from 'lucide-react';

export function AttestationPage() {
  const ledger = useApi(() => api.getAttestationLedger(), []);
  const pubKey = useApi(() => api.getAttestationPublicKey(), []);

  if (ledger.loading) return <LoadingState message="Loading attestation ledger..." />;
  if (ledger.error) return <ErrorState message={ledger.error} onRetry={ledger.refetch} />;

  const records = ledger.data?.records || [];
  const attested = records.filter((r) => r.status === 'attested');
  const revoked = records.filter((r) => r.status === 'revoked');

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Attestation Ledger</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Ed25519-signed, hash-chained cryptographic trust records
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3 mb-8">
        <div className="surface p-6">
          <div className="flex items-center gap-2">
            <Award className="size-5 text-primary" />
            <p className="text-sm font-medium text-muted-foreground">Total Records</p>
          </div>
          <p className="mt-2 font-mono text-3xl font-semibold">{records.length}</p>
        </div>
        <div className="surface p-6">
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-safe" />
            <p className="text-sm font-medium text-muted-foreground">Attested</p>
          </div>
          <p className="mt-2 font-mono text-3xl font-semibold text-safe">{attested.length}</p>
        </div>
        <div className="surface p-6">
          <div className="flex items-center gap-2">
            <ShieldX className="size-5 text-danger" />
            <p className="text-sm font-medium text-muted-foreground">Revoked</p>
          </div>
          <p className="mt-2 font-mono text-3xl font-semibold text-danger">{revoked.length}</p>
        </div>
      </div>

      {pubKey.data?.publicKey && (
        <div className="surface mb-8 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Key className="size-4 text-cyan" />
            <p className="text-xs font-medium text-muted-foreground">Public Key (Ed25519)</p>
          </div>
          <pre className="font-mono text-[11px] text-muted-foreground overflow-x-auto">
            {pubKey.data.publicKey}
          </pre>
        </div>
      )}

      {records.length === 0 ? (
        <EmptyState message="No attestation records yet. Run a scan to generate attestations." />
      ) : (
        <div className="space-y-3">
          {records.map((r, i) => (
            <div
              key={`${r.toolName}-${r.serverName}-${r.timestamp}-${i}`}
              className={`surface p-5 transition-all ${
                r.status === 'revoked' ? 'border-danger/30 bg-danger/5' : 'border-safe/20'
              }`}
            >
              <div className="flex items-center justify-between">
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
                <StatusBadge variant={r.status === 'attested' ? 'success' : 'critical'}>
                  {r.status}
                </StatusBadge>
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
                  {r.revokedAt && (
                    <p className="mt-1 text-xs text-muted-foreground">Revoked: {new Date(r.revokedAt).toLocaleString()}</p>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
