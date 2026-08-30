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

export const api = {
  // Health
  health: () => fetchJson<{ status: string; version: string }>('/health'),

  // Sessions
  listSessions: () => fetchJson<{ sessions: string[] }>('/sessions'),
  getSession: (id: string) => fetchJson<ScanSession>(`/sessions/${id}`),

  // Scans
  startScan: (options?: { skipDrift?: boolean }) =>
    fetchJson<{ sessionId: string; message: string }>('/scan', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    }),

  // Attestation
  getAttestationLedger: () => fetchJson<{ records: AttestationRecord[] }>('/attestation/ledger'),
  getAttestationPublicKey: () => fetchJson<{ publicKey: string }>('/attestation/public-key'),

  // Quarantine
  getQuarantineLog: () => fetchJson<{ records: QuarantineRecord[] }>('/quarantine/log'),
  getQuarantineIntegrity: () => fetchJson<{ valid: boolean; brokenAtIndex?: number }>('/quarantine/integrity'),

  // Reports
  getLatestReport: () => fetchJson<ScanReport>('/reports/latest'),

  // Discovery
  getDiscovery: () => fetchJson<{ servers: MCPServerInventory[]; totalTools: number }>('/discovery'),

  // Risk scores
  getRiskScores: (sessionId: string) => fetchJson<{ scores: RiskScore[] }>(`/sessions/${sessionId}/scores`),

  // Logs
  getLogs: (lines?: number) => fetchJson<{ logs: string[] }>(`/logs?lines=${lines || 100}`),
};
