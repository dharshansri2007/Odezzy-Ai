import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DriftDetector } from '../src/analysis/drift-detector.js';
import { EmbeddingBaselineStore } from '../src/persistence/embedding-baseline-store.js';
import type { MCPToolSchema, OdezzyConfig } from '../src/types/index.js';

// Mock the Google Generative AI
vi.mock('@google/generative-ai', () => ({
  GoogleGenerativeAI: vi.fn().mockImplementation(() => ({
    getGenerativeModel: vi.fn().mockReturnValue({
      embedContent: vi.fn().mockResolvedValue({
        embedding: { values: Array(768).fill(0).map((_, i) => Math.sin(i * 0.1)) },
      }),
    }),
  })),
}));

// Mock the baseline store
vi.mock('../src/persistence/embedding-baseline-store.js');

// Mock the attestation ledger (DriftDetector now calls ledger.revoke on drift)
vi.mock('../src/attestation/attestation-ledger.js', () => ({
  AttestationLedger: vi.fn().mockImplementation(() => ({
    revoke: vi.fn().mockResolvedValue(null),
    attest: vi.fn().mockResolvedValue(null),
    getFullLedger: vi.fn().mockResolvedValue([]),
    getPublicKey: vi.fn().mockResolvedValue('mock-public-key'),
  })),
}));

const mockConfig: OdezzyConfig = {
  servers: [],
  geminiApiKey: 'test-key',
  scanOptions: { maxConcurrency: 3, timeoutMs: 30000, probeCategories: [] },
};

const mockTool: MCPToolSchema = {
  name: 'test_tool',
  description: 'A test tool that does testing things',
  inputSchema: { type: 'object', properties: {} },
};

describe('DriftDetector', () => {
  let detector: DriftDetector;
  let mockStore: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockStore = {
      load: vi.fn().mockResolvedValue(null),
      save: vi.fn().mockResolvedValue(undefined),
    };
    vi.mocked(EmbeddingBaselineStore).mockImplementation(() => mockStore as any);
    detector = new DriftDetector(mockConfig);
  });

  it('throws if no geminiApiKey provided', () => {
    expect(() => new DriftDetector({ ...mockConfig, geminiApiKey: undefined })).toThrow();
  });

  it('establishes baseline on first scan (no existing baseline)', async () => {
    mockStore.load.mockResolvedValue(null);
    const findings = await detector.checkDrift(mockTool, 'test-server');
    expect(findings).toHaveLength(0);
    expect(mockStore.save).toHaveBeenCalledOnce();
  });

  it('returns no findings when description hash matches', async () => {
    const { createHash } = await import('node:crypto');
    const hash = createHash('sha256').update(mockTool.description!).digest('hex');
    mockStore.load.mockResolvedValue({
      toolName: 'test_tool',
      serverName: 'test-server',
      descriptionHash: hash,
      embedding: Array(768).fill(0),
      scannedAt: new Date().toISOString(),
    });
    const findings = await detector.checkDrift(mockTool, 'test-server');
    expect(findings).toHaveLength(0);
    expect(mockStore.save).not.toHaveBeenCalled();
  });

  it('detects drift when description changes significantly', async () => {
    // Return a very different embedding to ensure cosine distance exceeds threshold
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    vi.mocked(GoogleGenerativeAI).mockImplementation(() => ({
      getGenerativeModel: vi.fn().mockReturnValue({
        embedContent: vi.fn().mockResolvedValue({
          embedding: { values: Array(768).fill(0).map((_, i) => Math.cos(i * 3.14)) },
        }),
      }),
    }) as any);
    detector = new DriftDetector(mockConfig);

    mockStore.load.mockResolvedValue({
      toolName: 'test_tool',
      serverName: 'test-server',
      descriptionHash: 'old-hash-different',
      embedding: Array(768).fill(0).map((_, i) => Math.sin(i * 0.1)),
      scannedAt: new Date().toISOString(),
    });
    const findings = await detector.checkDrift(mockTool, 'test-server');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe('semantic-drift');
    expect(mockStore.save).not.toHaveBeenCalled(); // baseline should NOT be overwritten when drift is detected
  });

  it('batchCheckDrift processes multiple tools', async () => {
    mockStore.load.mockResolvedValue(null);
    const tools = [
      { tool: mockTool, serverName: 'server-1' },
      { tool: { ...mockTool, name: 'tool_2', description: 'Another tool' }, serverName: 'server-1' },
    ];
    const findings = await detector.batchCheckDrift(tools);
    expect(mockStore.save).toHaveBeenCalledTimes(2);
  });

  it('handles embed failures gracefully in batch mode', async () => {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    vi.mocked(GoogleGenerativeAI).mockImplementation(() => ({
      getGenerativeModel: vi.fn().mockReturnValue({
        embedContent: vi.fn().mockRejectedValue(new Error('API rate limited')),
      }),
    }) as any);
    detector = new DriftDetector(mockConfig);
    mockStore.load.mockResolvedValue(null);
    const findings = await detector.batchCheckDrift([{ tool: mockTool, serverName: 'test' }]);
    expect(findings).toHaveLength(0); // graceful failure, no crash
  });
});
