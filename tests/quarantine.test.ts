import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { VulnerabilityFinding, OdezzyConfig, DiscoveryResult } from '../src/types/index.js';
import type { FixProposal } from '../src/remediation/fix-proposer.js';

// ---------------------------------------------------------------------------
// 1. QuarantineRegistry — in-memory fake filesystem so this actually proves
//    persistence + isQuarantined() round-trip without touching real disk.
// ---------------------------------------------------------------------------
let fakeDisk: Record<string, string> = {};

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn((path: string) => {
    if (fakeDisk[path] === undefined) return Promise.reject(new Error('ENOENT'));
    return Promise.resolve(fakeDisk[path]);
  }),
  writeFile: vi.fn((path: string, data: string) => {
    fakeDisk[path] = data;
    return Promise.resolve();
  }),
  appendFile: vi.fn((path: string, data: string) => {
    fakeDisk[path] = (fakeDisk[path] ?? '') + data;
    return Promise.resolve();
  }),
  mkdir: vi.fn(() => Promise.resolve()),
}));

describe('QuarantineRegistry', () => {
  beforeEach(() => {
    fakeDisk = {};
  });

  it('is not quarantined before any quarantine call', async () => {
    const { QuarantineRegistry } = await import('../src/remediation/quarantine-registry.js');
    const registry = new QuarantineRegistry();
    expect(await registry.isQuarantined('read_notes', 'canary-server')).toBe(false);
  });

  it('persists a quarantine entry and reports it on future checks', async () => {
    const { QuarantineRegistry } = await import('../src/remediation/quarantine-registry.js');
    const registry = new QuarantineRegistry();
    await registry.quarantine('read_notes', 'canary-server', 'prompt injection', 'finding-1');

    expect(await registry.isQuarantined('read_notes', 'canary-server')).toBe(true);
    // a different tool on the same server is unaffected
    expect(await registry.isQuarantined('search_docs', 'canary-server')).toBe(false);
  });

  it('does not duplicate an entry if quarantined twice', async () => {
    const { QuarantineRegistry } = await import('../src/remediation/quarantine-registry.js');
    const registry = new QuarantineRegistry();
    await registry.quarantine('read_notes', 'canary-server', 'reason A', 'finding-1');
    await registry.quarantine('read_notes', 'canary-server', 'reason B', 'finding-2');

    const raw = JSON.parse(fakeDisk['.odezzy/quarantine.json']);
    expect(raw).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 2. AnalysisOrchestrator — proves a quarantined tool is excluded from
//    active analysis/attestation and instead gets a single honest finding.
// ---------------------------------------------------------------------------
describe('AnalysisOrchestrator quarantine handling', () => {
  beforeEach(() => {
    vi.resetModules();
    fakeDisk = {};
  });

  it('skips active analysis for a quarantined tool and emits a single quarantined finding', async () => {
    vi.doMock('../src/remediation/quarantine-registry.js', () => ({
      QuarantineRegistry: vi.fn().mockImplementation(() => ({
        isQuarantined: vi.fn((toolName: string) => Promise.resolve(toolName === 'bad_tool')),
      })),
    }));

    const { AnalysisOrchestrator } = await import('../src/analysis/index.js');

    const config: OdezzyConfig = {
      servers: [],
      gcpLocation: 'us-central1',
      scanOptions: { maxConcurrency: 3, timeoutMs: 30000, probeCategories: [] },
    };

    const discovery: DiscoveryResult = {
      totalTools: 2,
      timestamp: new Date().toISOString(),
      servers: [
        {
          serverName: 'test-server',
          serverVersion: '1.0.0',
          transport: 'stdio',
          connectionUri: 'stdio://test',
          scannedAt: new Date().toISOString(),
          tools: [
            { name: 'bad_tool', description: 'quarantined', inputSchema: { type: 'object', properties: { x: {} } } },
            { name: 'good_tool', description: 'clean', inputSchema: { type: 'object', properties: { x: {} } } },
          ],
        },
      ],
    };

    const orchestrator = new AnalysisOrchestrator(config);
    const result = await orchestrator.runAnalysis(discovery);

    const quarantineFindings = result.findings.filter((f) => f.category === 'quarantined');
    expect(quarantineFindings).toHaveLength(1);
    expect(quarantineFindings[0].toolName).toBe('bad_tool');

    // good_tool should still go through normal schema-diff analysis;
    // bad_tool should not produce any non-quarantine findings.
    const badToolOtherFindings = result.findings.filter(
      (f) => f.toolName === 'bad_tool' && f.category !== 'quarantined'
    );
    expect(badToolOtherFindings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 3. ApprovalGate.resolveApproval — proves an approved decision now actually
//    triggers ApplyFix, and a denied decision never does.
// ---------------------------------------------------------------------------
describe('ApprovalGate.resolveApproval applies fixes on approval', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  const mockFinding: VulnerabilityFinding = {
    id: '11111111-1111-1111-1111-111111111111',
    toolName: 'evil_tool',
    serverName: 'test-server',
    severity: 'critical',
    category: 'prompt-injection',
    title: 'Prompt injection detected',
    description: 'desc',
    evidence: 'evidence',
    remediation: 'remediate',
    confidence: 0.9,
  };

  const mockProposal: FixProposal = {
    findingId: mockFinding.id,
    proposedFix: 'quarantine it',
    autoFixable: true,
    risk: 'safe',
  };

  it('calls ApplyFix.apply when the human approves', async () => {
    const applyMock = vi.fn().mockResolvedValue({ applied: true, detail: 'quarantined' });
    vi.doMock('../src/remediation/apply-fix.js', () => ({
      ApplyFix: vi.fn().mockImplementation(() => ({ apply: applyMock })),
    }));
    vi.doMock('../src/agent/trueforge-client.js', () => ({
      sendOdezzyTurn: vi.fn(),
      resolveOdezzyApproval: vi.fn().mockResolvedValue({ turnId: 'turn-2', responseText: null, pendingApprovals: [] }),
    }));

    const { ApprovalGate } = await import('../src/remediation/approval-gate.js');
    const gate = new ApprovalGate({} as any, 'session-1', 'turn-1');

    const result = await gate.resolveApproval({
      toolCallId: 'call-1',
      threadId: 'thread-1',
      approved: true,
      proposal: mockProposal,
      finding: mockFinding,
    });

    expect(applyMock).toHaveBeenCalledWith(mockProposal, mockFinding);
    expect(result.approved).toBe(true);
    expect(result.fixResult?.applied).toBe(true);
  });

  it('never calls ApplyFix.apply when the human denies', async () => {
    const applyMock = vi.fn();
    vi.doMock('../src/remediation/apply-fix.js', () => ({
      ApplyFix: vi.fn().mockImplementation(() => ({ apply: applyMock })),
    }));
    vi.doMock('../src/agent/trueforge-client.js', () => ({
      sendOdezzyTurn: vi.fn(),
      resolveOdezzyApproval: vi.fn().mockResolvedValue({ turnId: 'turn-2', responseText: null, pendingApprovals: [] }),
    }));

    const { ApprovalGate } = await import('../src/remediation/approval-gate.js');
    const gate = new ApprovalGate({} as any, 'session-1', 'turn-1');

    const result = await gate.resolveApproval({
      toolCallId: 'call-1',
      threadId: 'thread-1',
      approved: false,
      reason: 'not convinced',
      proposal: mockProposal,
      finding: mockFinding,
    });

    expect(applyMock).not.toHaveBeenCalled();
    expect(result.approved).toBe(false);
    expect(result.fixResult).toBeUndefined();
  });
});