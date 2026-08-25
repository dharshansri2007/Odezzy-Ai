import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DriftDetector } from '../src/analysis/drift-detector.js';
import { EmbeddingBaselineStore } from '../src/persistence/embedding-baseline-store.js';
import type { MCPToolSchema, OdezzyConfig } from '../src/types/index.js';

// 1. Mock the unified @google/genai SDK (Vertex AI + ADC) so we can manipulate it in tests
const mockEmbedContent = vi.fn();
const mockGenAiInstance = { models: { embedContent: mockEmbedContent } };

vi.mock('@google/genai', () => ({
  GoogleGenAI: vi.fn().mockImplementation(() => mockGenAiInstance),
}));

// 2. Mock the baseline store
vi.mock('../src/persistence/embedding-baseline-store.js');

// 3. Mock the attestation ledger (DriftDetector now calls ledger.revoke on drift)
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
  gcpProjectId: 'test-project',
  gcpLocation: 'us-central1',
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
    
    // Reset default mock behavior for embedding
    mockEmbedContent.mockResolvedValue({
      embeddings: [{ values: Array(768).fill(0).map((_, i) => Math.sin(i * 0.1)) }],
    });

    mockStore = {
      load: vi.fn().mockResolvedValue(null),
      save: vi.fn().mockResolvedValue(undefined),
    };
    vi.mocked(EmbeddingBaselineStore).mockImplementation(() => mockStore as any);
    detector = new DriftDetector(mockConfig);
  });

  it('throws if no gcpProjectId provided', () => {
    expect(() => new DriftDetector({ ...mockConfig, gcpProjectId: undefined })).toThrow();
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
    mockEmbedContent.mockResolvedValueOnce({
      embeddings: [{ values: Array(768).fill(0).map((_, i) => Math.cos(i * 3.14)) }],
    });

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
    
    // Fix: batchCheckDrift returns an object { findings, erroredTools }
    const { findings, erroredTools } = await detector.batchCheckDrift(tools);
    expect(mockStore.save).toHaveBeenCalledTimes(2);
  });

  it('handles embed failures gracefully in batch mode', async () => {
    mockStore.load.mockResolvedValue(null);

    // Force embedContent to reject/fail for this specific test
    mockEmbedContent.mockRejectedValueOnce(new Error('Embedding API rate limit or outage'));

    const result = await detector.batchCheckDrift([
      { tool: mockTool, serverName: 'test-server' }
    ]);

    // 1. Findings array should be empty
    expect(result.findings).toBeDefined();
    expect(result.findings).toHaveLength(0);

    // 2. Errored tools must record the failure explicitly
    expect(result.erroredTools).toHaveLength(1);
    expect(result.erroredTools[0]).toMatchObject({
      toolName: mockTool.name,
      serverName: 'test-server',
      stage: 'drift-detection',
    });
    expect(result.erroredTools[0].error).toContain('Embedding API rate limit or outage');
  });
});