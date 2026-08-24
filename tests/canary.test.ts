import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AttestationLedger } from '../src/attestation/attestation-ledger.js';
import { rm, mkdir } from 'node:fs/promises';
import type { MCPToolSchema, VulnerabilityFinding } from '../src/types/index.js';
import { randomUUID } from 'node:crypto';

const TEST_LEDGER_DIR = '.odezzy/attestation';

const cleanTool: MCPToolSchema = {
  name: 'test_tool',
  description: 'A perfectly safe tool',
  inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
};

const makeFinding = (toolName: string, serverName: string): VulnerabilityFinding => ({
  id: randomUUID(),
  toolName,
  serverName,
  severity: 'high',
  category: 'prompt-injection',
  title: 'Test finding',
  description: 'A test vulnerability',
  evidence: 'test evidence',
  remediation: 'fix it',
  confidence: 0.9,
});

describe('AttestationLedger', () => {
  let ledger: AttestationLedger;

  beforeEach(async () => {
    // Clean up any leftover ledger data
    try { await rm(TEST_LEDGER_DIR, { recursive: true, force: true }); } catch {}
    ledger = new AttestationLedger();
  });

  afterEach(async () => {
    try { await rm(TEST_LEDGER_DIR, { recursive: true, force: true }); } catch {}
  });

  it('attests a clean tool and returns a signed record', async () => {
    const record = await ledger.attest(cleanTool, 'test-server', []);
    expect(record).not.toBeNull();
    expect(record!.status).toBe('attested');
    expect(record!.signature).toBeTruthy();
    expect(record!.scanFindingsCount).toBe(0);
    expect(record!.toolName).toBe('test_tool');
  });

  it('refuses to attest a tool with findings', async () => {
    const findings = [makeFinding('test_tool', 'test-server')];
    const record = await ledger.attest(cleanTool, 'test-server', findings);
    expect(record).toBeNull();
  });

  it('verifies a signature round-trips correctly', async () => {
    const record = await ledger.attest(cleanTool, 'test-server', []);
    expect(record).not.toBeNull();
    const valid = await ledger.verify(record!);
    expect(valid).toBe(true);
  });

  it('rejects a tampered record', async () => {
    const record = await ledger.attest(cleanTool, 'test-server', []);
    expect(record).not.toBeNull();
    const tampered = { ...record!, definitionHash: 'tampered-hash-value' };
    const valid = await ledger.verify(tampered);
    expect(valid).toBe(false);
  });

  it('revoke flips status correctly', async () => {
    await ledger.attest(cleanTool, 'test-server', []);
    const revoked = await ledger.revoke('test_tool', 'test-server', 'drift detected');
    expect(revoked).not.toBeNull();
    expect(revoked!.status).toBe('revoked');
    expect(revoked!.revokedReason).toBe('drift detected');

    const latest = await ledger.getLatest('test_tool', 'test-server');
    expect(latest!.status).toBe('revoked');
  });

  it('maintains chain integrity across records', async () => {
    const record1 = await ledger.attest(cleanTool, 'test-server', []);
    expect(record1).not.toBeNull();

    const tool2: MCPToolSchema = { ...cleanTool, name: 'tool_2' };
    const record2 = await ledger.attest(tool2, 'test-server', []);
    expect(record2).not.toBeNull();

    // The second record's previousRecordHash should be the SHA-256 of the first record
    const { createHash } = await import('node:crypto');
    const expectedHash = createHash('sha256').update(JSON.stringify(record1)).digest('hex');
    expect(record2!.previousRecordHash).toBe(expectedHash);
  });

  it('getFullLedger returns all records in order', async () => {
    await ledger.attest(cleanTool, 'test-server', []);
    await ledger.revoke('test_tool', 'test-server', 'drift');

    const full = await ledger.getFullLedger();
    expect(full).toHaveLength(2);
    expect(full[0].status).toBe('attested');
    expect(full[1].status).toBe('revoked');
  });
});
