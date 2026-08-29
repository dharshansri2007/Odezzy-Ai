import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import request from 'supertest';

// Must be set before src/server.ts is imported, since it reads
// process.env.ODEZZY_API_TOKEN once at module load time.
process.env.ODEZZY_API_TOKEN = 'test-secret-token';

const applyMock = vi.fn();
vi.mock('../src/remediation/apply-fix.js', () => ({
  ApplyFix: vi.fn().mockImplementation(() => ({ apply: applyMock })),
}));

const sessionLoadMock = vi.fn();
vi.mock('../src/persistence/session-store.js', () => ({
  SessionStore: vi.fn().mockImplementation(() => ({ load: sessionLoadMock })),
  redactConfig: vi.fn((c) => c),
}));

vi.mock('../src/agent/trueforge-client.js', () => ({
  createTrueForgeClient: vi.fn().mockReturnValue({}),
  sendOdezzyTurn: vi.fn(),
  resolveOdezzyApproval: vi.fn().mockResolvedValue({ turnId: 'turn-2', responseText: null, pendingApprovals: [] }),
}));

const fakeFinding = {
  id: 'real-finding-id',
  toolName: 'search_docs',
  serverName: 'canary-server',
  severity: 'critical' as const,
  category: 'prompt-injection' as const,
  title: 'Hidden HTML comment inside tool description',
  description: 'desc',
  evidence: 'evidence',
  remediation: 'remediate',
  confidence: 0.9,
};

const fakeSession = {
  id: 'real-session-id',
  startedAt: new Date().toISOString(),
  configSnapshot: {},
  findings: [fakeFinding],
};

describe('POST /api/approvals/resolve', () => {
  let app: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    sessionLoadMock.mockResolvedValue(fakeSession);
    vi.resetModules();
    ({ app } = await import('../src/server.js'));
  });

  it('rejects requests with no Authorization header at all', async () => {
    const res = await request(app)
      .post('/api/approvals/resolve')
      .send({ sessionId: 'real-session-id', findingId: 'real-finding-id', toolCallId: 'call-1', threadId: 'thread-1', approved: true });

    expect(res.status).toBe(401);
    expect(applyMock).not.toHaveBeenCalled();
  });

  it('rejects requests with the wrong bearer token', async () => {
    const res = await request(app)
      .post('/api/approvals/resolve')
      .set('Authorization', 'Bearer wrong-token')
      .send({ sessionId: 'real-session-id', findingId: 'real-finding-id', toolCallId: 'call-1', threadId: 'thread-1', approved: true });

    expect(res.status).toBe(401);
    expect(applyMock).not.toHaveBeenCalled();
  });

  it('404s on a garbage findingId instead of calling ApplyFix — the exact bug class this fix closes', async () => {
    const res = await request(app)
      .post('/api/approvals/resolve')
      .set('Authorization', 'Bearer test-secret-token')
      .send({ sessionId: 'real-session-id', findingId: 'totally-made-up-finding-id', toolCallId: 'call-1', threadId: 'thread-1', approved: true });

    expect(res.status).toBe(404);
    expect(applyMock).not.toHaveBeenCalled();
  });

  it('404s on a garbage sessionId instead of calling ApplyFix', async () => {
    sessionLoadMock.mockResolvedValue(null);
    const res = await request(app)
      .post('/api/approvals/resolve')
      .set('Authorization', 'Bearer test-secret-token')
      .send({ sessionId: 'made-up-session-id', findingId: 'real-finding-id', toolCallId: 'call-1', threadId: 'thread-1', approved: true });

    expect(res.status).toBe(404);
    expect(applyMock).not.toHaveBeenCalled();
  });

  it('400s when required fields are missing or the wrong type', async () => {
    const res = await request(app)
      .post('/api/approvals/resolve')
      .set('Authorization', 'Bearer test-secret-token')
      .send({ sessionId: 'real-session-id', approved: 'yes' }); // approved should be boolean, not string

    expect(res.status).toBe(400);
    expect(applyMock).not.toHaveBeenCalled();
  });
});

afterAll(() => {
  delete process.env.ODEZZY_API_TOKEN;
});