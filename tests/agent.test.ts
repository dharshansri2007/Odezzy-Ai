import { describe, it, expect, vi } from 'vitest';
import { RootAgent } from '../src/agent/root-agent.js';
import type { OdezzyConfig } from '../src/types/index.js';

// Mock all dependencies
vi.mock('../src/agent/trueforge-client.js', () => ({
  createTrueForgeClient: vi.fn().mockReturnValue({
    mcpServers: {
      list: vi.fn().mockResolvedValue({ data: [] }),
    },
  }),
  createOdezzyScanSession: vi.fn().mockResolvedValue({ sessionId: 'test-session-id' }),
  sendOdezzyTurn: vi.fn().mockResolvedValue({ turnId: 'turn-1', responseText: null, pendingApprovals: [] }),
  narrateScanPhase: vi.fn().mockResolvedValue('turn-narration-1'),
}));

vi.mock('../src/discovery/inventory.js', () => ({
  InventoryBuilder: vi.fn().mockImplementation(() => ({
    buildInventory: vi.fn().mockResolvedValue({
      servers: [],
      totalTools: 0,
      timestamp: new Date().toISOString(),
    }),
  })),
}));

vi.mock('../src/analysis/index.js', () => ({
  AnalysisOrchestrator: vi.fn().mockImplementation(() => ({
    runAnalysis: vi.fn().mockResolvedValue({ findings: [], erroredTools: [] }),
  })),
}));

vi.mock('../src/agent/subagent.js', () => ({
  runProbesForServers: vi.fn().mockResolvedValue([]),
}));

vi.mock('../src/remediation/fix-proposer.js', () => ({
  FixProposer: vi.fn().mockImplementation(() => ({
    proposeFixes: vi.fn().mockReturnValue([]),
  })),
}));

vi.mock('../src/remediation/approval-gate.js', () => ({
  ApprovalGate: vi.fn().mockImplementation(() => ({
    requestApproval: vi.fn().mockResolvedValue({ approved: false, reason: 'test' }),
  })),
}));

vi.mock('../src/report/graph-builder.js', () => ({
  buildGraph: vi.fn().mockReturnValue({ nodes: [], edges: [] }),
}));

vi.mock('../src/persistence/session-store.js', () => ({
  SessionStore: vi.fn().mockImplementation(() => ({
    save: vi.fn().mockResolvedValue(undefined),
  })),
}));

const mockConfig: OdezzyConfig = {
  servers: [],
  geminiApiKey: 'test-key',
  trueforgeUrl: 'http://localhost:8790',
  scanOptions: { maxConcurrency: 3, timeoutMs: 30000, probeCategories: [] },
};

describe('RootAgent', () => {
  it('creates a RootAgent instance', () => {
    const agent = new RootAgent(mockConfig);
    expect(agent).toBeDefined();
  });

  it('runs a full scan and returns findings + sessionId', async () => {
  const agent = new RootAgent(mockConfig);
  const result = await agent.runFullScan();
  expect(result).toHaveProperty('findings');
  expect(result).toHaveProperty('sessionId');
  expect(Array.isArray(result.findings)).toBe(true);
});

// New — this is the one that would have caught the original bug
it('shadow server detection succeeds with a well-formed TrueForge client mock', async () => {
  const agent = new RootAgent(mockConfig);
  const result = await agent.runFullScan();
  expect(result.erroredTools).toBeDefined();      // fails now if the property doesn't exist
  expect(result.erroredTools).toHaveLength(0);
});
});