import { setDemoMode } from './demo-mode';
import {
  DEMO_SESSIONS_LIST,
  DEMO_SESSION,
  DEMO_ATTESTATION_LEDGER,
  DEMO_PUBLIC_KEY,
  DEMO_QUARANTINE_LOG,
  DEMO_REPORT,
  DEMO_SERVERS,
  DEMO_RISK_SCORES,
  DEMO_LOGS,
} from './demo-data';

const API_BASE = '/api';

export interface MCPToolSchema {
  name: string;
  description?: string;
  inputSchema: {
    type: string;
    properties?: Record<string, any>;
    required?: string[];
  };
}

export interface MCPServerInventory {
  serverName: string;
  serverVersion: string;
  transport: 'stdio' | 'sse' | 'streamable-http';
  tools: MCPToolSchema[];
  scannedAt: string;
  connectionUri: string;
}

export interface VulnerabilityFinding {
  id: string;
  toolName: string;
  serverName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cweId?: string;
  confidence: number;
  owaspCategory?: string;
}

export interface RiskScore {
  entityName: string;
  entityType: 'server' | 'tool';
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findingCount: number;
  highestSeverity: string;
}

export interface AttestationRecord {
  toolName: string;
  serverName: string;
  definitionHash: string;
  timestamp: string;
  scanFindingsCount: number;
  signature: string;
  previousRecordHash: string;
  status: 'attested' | 'revoked';
  revokedAt?: string;
  revokedReason?: string;
}

export interface QuarantineRecord {
  toolName: string;
  serverName: string;
  findingId: string;
  reason: string;
  action: 'quarantine';
  tokenSource: 'trueforge-ui' | 'cli-confirm' | 'trueforge-gated-tool-call';
  grantedAt: string;
  recordedAt: string;
  previousHash: string;
}

export interface ScanSession {
  id: string;
  startedAt: string;
  completedAt?: string;
  configSnapshot: any;
  discoveryResult?: {
    servers: MCPServerInventory[];
    totalTools: number;
    timestamp: string;
  };
  findings: VulnerabilityFinding[];
  approvalGateSummary?: {
    totalRequests: number;
    approved: number;
    deniedReviewed: number;
    noRequest: number;
    plumbingUnresolved: number;
    pending: number;
  };
}

export interface ScanReport {
  id: string;
  projectName: string;
  scanStartedAt: string;
  scanCompletedAt: string;
  summary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
  findings: VulnerabilityFinding[];
  inventories: MCPServerInventory[];
  incompleteAnalysis?: {
    erroredTools: { toolName: string; serverName: string; stage: string; error: string }[];
    skippedStages: string[];
  };
  metadata: {
    agentVersion: string;
    scanDurationMs: number;
  };
}

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res.json();
}

/**
 * Calls the real API; if it's unreachable (server not running, network
 * error, non-2xx), flips global demo mode on and resolves with the given
 * fixture instead of throwing. Every read endpoint below goes through this
 * so the dashboard always has something real-shaped to render — see
 * lib/demo-data.ts and lib/demo-mode.ts.
 */
async function withDemoFallback<T>(url: string, fallback: T, options?: RequestInit): Promise<T> {
  try {
    const result = await fetchJson<T>(url, options);
    setDemoMode(false);
    return result;
  } catch {
    setDemoMode(true);
    return fallback;
  }
}

export const api = {
  // Health
  health: () =>
    withDemoFallback<{ status: string; version: string }>('/health', {
      status: 'demo',
      version: '0.1.0',
    }),

  // Sessions
  listSessions: () =>
    withDemoFallback<{ sessions: string[] }>('/sessions', { sessions: DEMO_SESSIONS_LIST }),
  getSession: (id: string) =>
    withDemoFallback<ScanSession>(`/sessions/${id}`, { ...DEMO_SESSION, id }),

  // Scans
  startScan: (options?: { skipDrift?: boolean }) =>
    withDemoFallback<{ sessionId: string; message: string }>(
      '/scan',
      { sessionId: DEMO_SESSION.id, message: 'Demo mode: no live API server — showing a sample session instead.' },
      { method: 'POST', body: JSON.stringify(options || {}) }
    ),

  // Attestation
  getAttestationLedger: () =>
    withDemoFallback<{ records: AttestationRecord[] }>('/attestation/ledger', {
      records: DEMO_ATTESTATION_LEDGER,
    }),
  getAttestationPublicKey: () =>
    withDemoFallback<{ publicKey: string }>('/attestation/public-key', { publicKey: DEMO_PUBLIC_KEY }),

  // Quarantine
  getQuarantineLog: () =>
    withDemoFallback<{ records: QuarantineRecord[] }>('/quarantine/log', { records: DEMO_QUARANTINE_LOG }),
  getQuarantineIntegrity: () =>
    withDemoFallback<{ valid: boolean; brokenAtIndex?: number }>('/quarantine/integrity', { valid: true }),

  // Reports
  getLatestReport: () => withDemoFallback<ScanReport>('/reports/latest', DEMO_REPORT),

  // Discovery
  getDiscovery: () =>
    withDemoFallback<{ servers: MCPServerInventory[]; totalTools: number }>('/discovery', {
      servers: DEMO_SERVERS,
      totalTools: DEMO_SERVERS.reduce((n, s) => n + s.tools.length, 0),
    }),

  // Risk scores
  getRiskScores: (sessionId: string) =>
    withDemoFallback<{ scores: RiskScore[] }>(`/sessions/${sessionId}/scores`, { scores: DEMO_RISK_SCORES }),

  // Logs
  getLogs: (lines?: number) =>
    withDemoFallback<{ logs: string[] }>(`/logs?lines=${lines || 100}`, { logs: DEMO_LOGS }),
};
