import { z } from 'zod';

/**
 * MCPToolSchema - represents a single tool from an MCP server
 */
export const MCPToolSchemaSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  inputSchema: z.object({
    type: z.string(),
    properties: z.record(z.any()).optional(),
    required: z.array(z.string()).optional(),
  }).passthrough(),
});
export type MCPToolSchema = z.infer<typeof MCPToolSchemaSchema>;

/**
 * MCPServerInventory - represents a scanned MCP server
 */
export const MCPServerInventorySchema = z.object({
  serverName: z.string(),
  serverVersion: z.string(),
  transport: z.enum(['stdio', 'sse', 'streamable-http']),
  tools: z.array(MCPToolSchemaSchema),
  scannedAt: z.string().datetime(),
  connectionUri: z.string(),
});
export type MCPServerInventory = z.infer<typeof MCPServerInventorySchema>;

/**
 * DiscoveryResult - the output of the discovery engine
 */
export const DiscoveryResultSchema = z.object({
  servers: z.array(MCPServerInventorySchema),
  totalTools: z.number(),
  timestamp: z.string().datetime(),
});
export type DiscoveryResult = z.infer<typeof DiscoveryResultSchema>;

/**
 * VulnerabilityFinding - a single discovered vulnerability
 */
export const VulnerabilityFindingSchema = z.object({
  id: z.string().uuid(),
  toolName: z.string(),
  serverName: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  category: z.enum([
    'undeclared-params',
    'prompt-injection',
    'leaked-secrets',
    'excessive-permissions',
    'insecure-transport',
    'schema-mismatch',
    'semantic-drift',
    'shadow-server',
    'quarantined'
  ]),
  title: z.string(),
  description: z.string(),
  evidence: z.string(),
  remediation: z.string(),
  cweId: z.string().optional(),
  confidence: z.number().min(0).max(1),
  owaspCategory: z.string().optional(),
});
export type VulnerabilityFinding = z.infer<typeof VulnerabilityFindingSchema>;

/**
 * ScanReport - the full output report
 */
/**
 * ErroredTool — tracks a tool whose analysis was attempted but failed.
 * Used by the fail-visible system to ensure incomplete analysis is
 * reported honestly rather than silently producing a misleadingly clean
 * scan. A security tool that fails toward LESS visible risk is failing
 * in the most dangerous possible direction — this type exists to prevent that.
 */
export const ErroredToolSchema = z.object({
  toolName: z.string(),
  serverName: z.string(),
  stage: z.enum(['semantic-check', 'drift-detection', 'shadow-detection']),
  error: z.string(),
});
export type ErroredTool = z.infer<typeof ErroredToolSchema>;

/**
 * AnalysisPipelineResult — the return type for any analysis stage that
 * can partially fail. Replaces bare VulnerabilityFinding[] returns so
 * callers always know which tools couldn't be checked.
 */
export interface AnalysisPipelineResult {
  findings: VulnerabilityFinding[];
  erroredTools: ErroredTool[];
  activeServers: DiscoveryResult['servers'];
}

export const ScanReportSchema = z.object({
  id: z.string().uuid(),
  projectName: z.string(),
  scanStartedAt: z.string().datetime(),
  scanCompletedAt: z.string().datetime(),
  summary: z.object({
    totalFindings: z.number(),
    bySeverity: z.record(z.number()),
    byCategory: z.record(z.number()),
  }),
  findings: z.array(VulnerabilityFindingSchema),
  inventories: z.array(MCPServerInventorySchema),
  /** Fail-visible: tools that could not be fully analyzed. */
  incompleteAnalysis: z.object({
    erroredTools: z.array(ErroredToolSchema),
    skippedStages: z.array(z.string()),
  }).optional(),
  metadata: z.object({
    agentVersion: z.string(),
    scanDurationMs: z.number(),
  }),
});
export type ScanReport = z.infer<typeof ScanReportSchema>;

/**
 * ProbeTemplate - defines a probe to run against a tool
 */
export const ProbeTemplateSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  category: VulnerabilityFindingSchema.shape.category,
  probeType: z.enum(['schema-diff', 'injection-test', 'secret-scan', 'permission-check']),
  // We use z.any() for functions as Zod cannot fully validate runtime functions easily
  payloadGenerator: z.any(),
  resultParser: z.any(),
});
export type ProbeTemplate = {
  id: string;
  name: string;
  description: string;
  category: VulnerabilityFinding['category'];
  probeType: 'schema-diff' | 'injection-test' | 'secret-scan' | 'permission-check';
  payloadGenerator: (tool: MCPToolSchema) => unknown;
  resultParser: (response: unknown) => VulnerabilityFinding | null;
};

/**
 * McpServerConfig - a single MCP server entry normalized from a host's
 * config file (Claude Desktop, Cursor, VS Code, etc). A server is either
 * a local stdio process or a remote HTTP endpoint.
 */
export const McpServerConfigSchema = z.union([
  z.object({
    name: z.string(),
    sourceFile: z.string(),
    transport: z.literal('stdio'),
    command: z.string(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string()).optional(),
  }),
  z.object({
    name: z.string(),
    sourceFile: z.string(),
    transport: z.literal('http'),
    url: z.string(),
    headers: z.record(z.string()).optional(),
  }),
]);
export type McpServerConfig = z.infer<typeof McpServerConfigSchema>;

/**
 * OdezzyConfig - project configuration
 */
export const OdezzyConfigSchema = z.object({
  servers: z.array(z.object({
    name: z.string(),
    command: z.string(),
    args: z.array(z.string()),
    env: z.record(z.string()).optional(),
  })).default([]),
  geminiApiKey: z.string().optional(),
  gcpProjectId: z.string().optional(),
  /** Vertex AI region, e.g. "us-central1". Only used when gcpProjectId is set (Vertex AI + ADC path). */
  gcpLocation: z.string().default('us-central1'),
  /** Name of the TrueForge MCP connector exposing apply_fix, registered under Settings → Connectors. Required for the fullscan approval loop to ever actually pause for a human — see agent/root-agent.ts. */
  remediationMcpServerName: z.string().optional(),
  trueforgeUrl: z.string().optional(),
  /** Bearer token for the TrueForge server, if auth is enabled. Not required in local single-user mode. */
  trueforgeApiKey: z.string().optional(),
  /** Model FQN passed to TrueForge,  (provider/model). */
  trueforgeModel: z.string().default('grok/grok-4-1-fast'),
  scanOptions: z.object({
    maxConcurrency: z.number().default(3),
    timeoutMs: z.number().default(30000),
    probeCategories: z.array(VulnerabilityFindingSchema.shape.category).default([]),
  }).default({
    maxConcurrency: 3,
    timeoutMs: 30000,
    probeCategories: ['undeclared-params', 'prompt-injection', 'leaked-secrets', 'schema-mismatch'],
  }),
});
export type OdezzyConfig = z.infer<typeof OdezzyConfigSchema>;

/**
 * RiskScore - risk score for an entity
 */
export const RiskScoreSchema = z.object({
  entityName: z.string(),
  entityType: z.enum(['server', 'tool']),
  score: z.number().min(0).max(100),
  grade: z.enum(['A', 'B', 'C', 'D', 'F']),
  findingCount: z.number(),
  highestSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info', 'none']),
});
export type RiskScore = z.infer<typeof RiskScoreSchema>;

/**
 * RiskClassification - classification of risk
 */
export const RiskClassificationSchema = z.object({
  level: z.enum(['green', 'yellow', 'orange', 'red']),
  score: RiskScoreSchema,
});
export type RiskClassification = z.infer<typeof RiskClassificationSchema>;

/**
 * ProbeCallResult - output of a probe run
 */
export const ProbeCallResultSchema = z.object({
  toolName: z.string(),
  serverName: z.string(),
  sentArgKeys: z.array(z.string()),
  callSucceeded: z.boolean(),
  responseText: z.string(),
  responseContainsArgEcho: z.boolean(),
});
export type ProbeCallResult = z.infer<typeof ProbeCallResultSchema>;

/**
 * AttestationRecord — a cryptographically signed record certifying a tool
 * scanned clean, or revoking a previous attestation when drift is detected.
 */
export const AttestationRecordSchema = z.object({
  toolName: z.string(),
  serverName: z.string(),
  definitionHash: z.string(),
  timestamp: z.string(),
  scanFindingsCount: z.number(),
  signature: z.string(),
  previousRecordHash: z.string(),
  status: z.enum(['attested', 'revoked']),
  revokedAt: z.string().optional(),
  revokedReason: z.string().optional(),
});
export type AttestationRecord = z.infer<typeof AttestationRecordSchema>;

/**
 * QuarantineRecord — a tamper-evident, hash-chained entry recording that a
 * specific human, via a specific approval source, at a specific time,
 * authorized quarantining a tool. Mirrors AttestationRecord's chain
 * pattern (see HashChainedLog in utils/hash-chained-log.ts) so that
 * "this tool is quarantined" and "a human genuinely authorized this" are
 * both independently provable, not just the former.
 */
export const QuarantineRecordSchema = z.object({
  toolName: z.string(),
  serverName: z.string(),
  findingId: z.string(),
  reason: z.string(),
  action: z.literal('quarantine'),
  tokenSource: z.enum(['trueforge-ui', 'cli-confirm', 'trueforge-gated-tool-call']),
  grantedAt: z.string(),
  recordedAt: z.string(),
  previousHash: z.string(),
});
export type QuarantineRecord = z.infer<typeof QuarantineRecordSchema>;