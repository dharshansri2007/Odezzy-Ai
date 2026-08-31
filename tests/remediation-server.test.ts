import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { rm, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SessionStore } from '../src/persistence/session-store.js';
import type { VulnerabilityFinding } from '../src/types/index.js';

const TEST_TOKEN = 'test-remediation-token';
const TEST_PORT = 18791; // deliberately not the real default (8791), so this never collides with a dev instance actually running
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

let serverProcess: ChildProcess;
let client: Client;
let isolatedDir: string;

/** Waits for the subprocess to print its "listening" line, then actively confirms it's really accepting connections — under full-suite parallel load, the log line can print fractionally before Express is truly ready to accept, causing an intermittent connection race. */
function waitForServerReady(proc: ChildProcess, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('remediation-server did not become ready in time')), 15000);
    proc.on('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`remediation-server exited early with code ${code}`));
    });
    proc.stderr?.on('data', async (chunk: Buffer) => {
      if (!chunk.toString().includes('listening on')) return;
      // Poll with real requests until one actually succeeds, rather than
      // trusting the log line's timing alone.
      for (let attempt = 0; attempt < 30; attempt++) {
        try {
          await fetch(`http://localhost:${port}/mcp`, { method: 'GET' });
          clearTimeout(timeout);
          resolve();
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
      clearTimeout(timeout);
      reject(new Error('remediation-server logged "listening" but never actually accepted a connection'));
    });
  });
}

describe('remediation-server (real HTTP subprocess)', () => {
  beforeAll(async () => {
    // Fully isolated project-state directory for this test run — nothing
    // here touches the developer's real .odezzy/ directory, real
    // attestation keypair, or real quarantine log. This is the exact gap
    // review flagged: the previous version of this test mutated real
    // project state and never restored it.
    isolatedDir = await mkdtemp(join(tmpdir(), 'odezzy-remediation-test-'));

    const env = {
      ...process.env,
      REMEDIATION_SERVER_TOKEN: TEST_TOKEN,
      REMEDIATION_SERVER_PORT: String(TEST_PORT),
      ODEZZY_SESSIONS_DIR: join(isolatedDir, 'sessions'),
      QUARANTINE_REGISTRY_PATH: join(isolatedDir, 'quarantine.jsonl'),
      QUARANTINE_LEGACY_PATH: join(isolatedDir, 'quarantine.json'), // deliberately absent — no legacy fallback needed in a fresh temp dir
      ATTESTATION_LEDGER_DIR: join(isolatedDir, 'attestation'),
    };

    // Seed a real session file in the isolated directory so the server has
    // something real to find — same isolation env vars, so this writes to
    // the temp dir, not the real project.
    await new SessionStore(env.ODEZZY_SESSIONS_DIR).save({
      id: TEST_SESSION_ID,
      startedAt: new Date().toISOString(),
      configSnapshot: {} as any,
      findings: [TEST_FINDING],
    });

    serverProcess = spawn('npx', ['tsx', 'remediation-server/server.ts'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await waitForServerReady(serverProcess, TEST_PORT);

    const transport = new StreamableHTTPClientTransport(new URL(`http://localhost:${TEST_PORT}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${TEST_TOKEN}` } },
    });
    client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 20000);

  afterAll(async () => {
    await client?.close();
    serverProcess?.kill();
    // Isolated temp dir only — never touches real project state, so a
    // simple recursive delete is safe and complete, unlike trying to
    // precisely undo two scattered mutations against the real .odezzy/ dir.
    await rm(isolatedDir, { recursive: true, force: true });
  });

  it('rejects requests with no auth token', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });
    expect(res.status).toBe(401);
  });

  it('rejects requests with the wrong auth token', async () => {
    const res = await fetch(`http://localhost:${TEST_PORT}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer wrong-token' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });
    expect(res.status).toBe(401);
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

  // TODO: this specific assertion currently fails — investigation ongoing.
  // The server correctly receives the isolated ODEZZY_SESSIONS_DIR (verified
  // via manual repro outside vitest too) and the session file is confirmed
  // written to disk before this call, but findFindingAcrossSessions still
  // returns null for a finding id that genuinely exists in that file. Every
  // other test in this file (auth, tool listing, the two error paths) passes
  // and is trustworthy — this is isolated to the one success-path assertion.
  it('actually quarantines a real finding end to end, in the isolated store', async () => {
    const result = await client.callTool({ name: 'apply_fix', arguments: { findingId: TEST_FINDING.id } });
    expect(result.isError).toBeFalsy();
    expect(JSON.stringify(result.content)).toContain('quarantined');

    // Verify the real side effect landed in the isolated store, not the
    // real project's .odezzy/quarantine.jsonl. QuarantineRegistry reads
    // its path from env at MODULE LOAD time, so the env vars must be set
    // before this import runs, not after — a static top-level import here
    // would have already evaluated against whatever was set (or unset) at
    // file-load time, before beforeAll even ran.
    process.env.QUARANTINE_REGISTRY_PATH = join(isolatedDir, 'quarantine.jsonl');
    process.env.QUARANTINE_LEGACY_PATH = join(isolatedDir, 'quarantine.json');
    const { QuarantineRegistry } = await import('../src/remediation/quarantine-registry.js');
    const isQuarantined = await new QuarantineRegistry().isQuarantined(TEST_FINDING.toolName, TEST_FINDING.serverName);
    expect(isQuarantined).toBe(true);
    delete process.env.QUARANTINE_REGISTRY_PATH;
    delete process.env.QUARANTINE_LEGACY_PATH;
  });
});