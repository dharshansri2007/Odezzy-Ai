import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SessionStore } from '../src/persistence/session-store.js';
import { QuarantineRegistry } from '../src/remediation/quarantine-registry.js';
import type { VulnerabilityFinding } from '../src/types/index.js';

const TEST_SESSION_ID = 'test-remediation-server-session';
const TEST_FINDING: VulnerabilityFinding = {
  id: 'aaaaaaaa-1111-2222-3333-444444444444',
  toolName: 'test_tool',
  serverName: 'test-server',
  severity: 'critical',
  category: 'prompt-injection',
  title: 'Test finding for remediation server integration test',
  description: 'desc',
  evidence: 'evidence',
  remediation: 'remediate',
  confidence: 0.9,
};

let client: Client;
let transport: StdioClientTransport;

describe('remediation-server (real MCP subprocess)', () => {
  beforeAll(async () => {
    // Seed a real session file on disk so the server has something real to find —
    // this is a genuine subprocess talking real MCP protocol, not a mock.
    await new SessionStore().save({
      id: TEST_SESSION_ID,
      startedAt: new Date().toISOString(),
      configSnapshot: {} as any,
      findings: [TEST_FINDING],
    });

    transport = new StdioClientTransport({
      command: 'npx',
      args: ['tsx', 'remediation-server/server.ts'],
    });
    client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 20000);

  afterAll(async () => {
    await client?.close();
    // Clean up what this test created so repeated runs stay reproducible.
    const fs = await import('node:fs/promises');
    await fs.rm(`.odezzy/sessions/${TEST_SESSION_ID}.json`, { force: true });
    await fs.rm('.odezzy/quarantine.json', { force: true });
  });

  it('declares exactly one tool: apply_fix', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(['apply_fix']);
  });

  it('errors cleanly on a nonexistent finding id instead of crashing', async () => {
    const result = await client.callTool({ name: 'apply_fix', arguments: { findingId: 'does-not-exist' } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('No finding found');
  });

  it('errors cleanly when findingId is missing', async () => {
    const result = await client.callTool({ name: 'apply_fix', arguments: {} });
    expect(result.isError).toBe(true);
  });

  it('actually quarantines a real finding end to end', async () => {
    const result = await client.callTool({ name: 'apply_fix', arguments: { findingId: TEST_FINDING.id } });
    expect(result.isError).toBeFalsy();
    expect(JSON.stringify(result.content)).toContain('quarantined');

    // Verify the real side effect landed on disk, not just a success message.
    const isQuarantined = await new QuarantineRegistry().isQuarantined(TEST_FINDING.toolName, TEST_FINDING.serverName);
    expect(isQuarantined).toBe(true);
  });
});