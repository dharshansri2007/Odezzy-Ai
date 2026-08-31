// src/server.ts — the dashboard API bridge between the backend's real
// output files (.odezzy/**, logs/odezzy.log) and the browser. Read-only
// except for /api/scan (spawns a real fullscan) and /api/approvals/resolve
// (bearer-token gated), the two routes that actually change state.
//
// This surface intentionally matches what frontend/src/lib/api.ts already
// calls — before this file was rewritten, the frontend called routes
// (/api/sessions/:id, /api/attestation/ledger, /api/quarantine/log,
// /api/reports/latest, /api/discovery, /api/logs, /api/scan, /api/health)
// that simply didn't exist here, so every dashboard request 404'd and the
// UI silently fell back to demo data on every load, permanently. This is
// the fix for that: every one of those routes is now real, backed by the
// same classes the CLI (src/index.ts) uses, not a second reimplementation.
//
// NOTE: this file is deliberately separate from remediation-server/server.ts.
// A prior merge overwrote this file's actual content with a duplicate copy
// of the remediation MCP server, which (a) deleted every dashboard route
// below, and (b) exposed an unauthenticated endpoint that could trigger
// real quarantine + attestation revocation from any HTTP client that could
// reach the port. The remediation server logic lives only in
// remediation-server/server.ts, on its own port, with its own auth.
import express, { type Request, type Response } from 'express';
import cors from 'cors';
import { spawn } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from './utils/logger.js';
import { buildGraph } from './report/graph-builder.js';
import { RiskCalculator } from './scoring/risk-formula.js';
import { classifyRisk } from './scoring/risk-classifier.js';
import { ApprovalGate } from './remediation/approval-gate.js';
import { createTrueForgeClient } from './agent/trueforge-client.js';
import { SessionStore } from './persistence/session-store.js';
import { FixProposer } from './remediation/fix-proposer.js';
import { AttestationLedger } from './attestation/attestation-ledger.js';
import { QuarantineRegistry } from './remediation/quarantine-registry.js';
import type { DiscoveryResult, MCPServerInventory, VulnerabilityFinding, RiskScore } from './types/index.js';

const logger = createLogger('api-server');
const app = express();
const PORT = Number(process.env.ODEZZY_API_PORT) || 4000;

app.use(cors()); // dev-only convenience; Vite's proxy makes this mostly unnecessary but harmless
app.use(express.json());

const REPORTS_DIR = '.odezzy/reports';
const SESSIONS_DIR = process.env.ODEZZY_SESSIONS_DIR ?? '.odezzy/sessions';
const LOG_PATH = 'logs/odezzy.log';

const sessionStore = new SessionStore(SESSIONS_DIR);
const ledger = new AttestationLedger();
const quarantine = new QuarantineRegistry();

// The one mutating route on this server that resolves an approval requires
// a shared secret set at process startup. Loopback binding alone stops
// remote attackers, but not a malicious browser tab open on the same
// machine — that's the class of attacker this token is actually for.
// Refuse to accept mutating requests at all if this isn't configured,
// rather than silently running unauthenticated.
const API_TOKEN = process.env.ODEZZY_API_TOKEN;
if (!API_TOKEN) {
  logger.warn(
    'ODEZZY_API_TOKEN is not set. /api/approvals/resolve will refuse all requests until it is. ' +
    'Set ODEZZY_API_TOKEN in your environment before starting this server if you need that route.'
  );
}

function requireApiToken(req: Request, res: Response, next: () => void) {
  if (!API_TOKEN) {
    return res.status(503).json({ error: 'Server has no ODEZZY_API_TOKEN configured — mutating routes are disabled.' });
  }
  const header = req.header('Authorization');
  const provided = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;
  if (!provided || provided !== API_TOKEN) {
    return res.status(401).json({ error: 'Missing or invalid Authorization: Bearer <token>.' });
  }
  next();
}

/** Finds the most recent .json report — filenames are ISO-timestamp prefixed, so alphabetical sort is chronological. */
async function getLatestReportPath(): Promise<string | null> {
  try {
    const files = (await readdir(REPORTS_DIR)).filter((f) => f.endsWith('.json')).sort();
    return files.length > 0 ? join(REPORTS_DIR, files[files.length - 1]) : null;
  } catch {
    return null; // no reports yet — expected before the first scan, not an error
  }
}

async function readLatestReport(): Promise<any | null> {
  const path = await getLatestReportPath();
  if (!path) return null;
  try {
    return JSON.parse(await readFile(path, 'utf-8'));
  } catch (err) {
    logger.error('Failed to parse latest report', err);
    return null;
  }
}

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', version: process.env.npm_package_version ?? '0.6.0' });
});

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

app.get('/api/sessions', async (_req: Request, res: Response) => {
  try {
    const ids = await sessionStore.list();
    res.json({ sessions: ids });
  } catch (err) {
    logger.error('Failed to list sessions', err);
    res.status(500).json({ error: 'Failed to list sessions' });
  }
});

app.get('/api/sessions/:id', async (req: Request, res: Response) => {
  try {
    const session = await sessionStore.load(req.params.id as string);
    if (!session) {
      return res.status(404).json({ error: `No session found with id ${req.params.id}.` });
    }
    // Never let the config snapshot's secrets leak to the browser.
    const safe = { ...session, configSnapshot: session.configSnapshot ? { ...session.configSnapshot, geminiApiKey: undefined, trueforgeApiKey: undefined } : session.configSnapshot };
    res.json(safe);
  } catch (err) {
    logger.error(`Failed to load session ${req.params.id}`, err);
    res.status(500).json({ error: 'Failed to load session' });
  }
});

app.get('/api/sessions/:id/scores', async (req: Request, res: Response) => {
  try {
    const session = await sessionStore.load(req.params.id as string);
    if (!session) {
      return res.status(404).json({ error: `No session found with id ${req.params.id}.` });
    }
    const servers = session.discoveryResult?.servers ?? [];
    const findings = session.findings ?? [];
    const scores: RiskScore[] = servers.map((s: MCPServerInventory) =>
      RiskCalculator.calculate(s.serverName, 'server', findings.filter((f) => f.serverName === s.serverName))
    );
    res.json({ scores });
  } catch (err) {
    logger.error(`Failed to compute scores for session ${req.params.id}`, err);
    res.status(500).json({ error: 'Failed to compute risk scores' });
  }
});

// ---------------------------------------------------------------------------
// Scan trigger — spawns the same CLI command a human would run, and streams
// nothing back synchronously (a fullscan takes too long for one HTTP
// response); the dashboard is expected to poll /api/sessions afterward.
// ---------------------------------------------------------------------------

app.post('/api/scan', (req: Request, res: Response) => {
  const skipDrift = req.body?.skipDrift === true;
  const args = ['tsx', 'src/index.ts', 'fullscan', ...(skipDrift ? ['--skip-drift'] : [])];

  logger.info(`Spawning scan: npx ${args.join(' ')}`);
  const child = spawn('npx', args, { detached: true, stdio: 'ignore' });
  child.unref(); // let it keep running after this request completes; we're not waiting on it

  child.on('error', (err) => {
    logger.error('Failed to spawn scan process', err);
  });

  res.status(202).json({
    message: 'Scan started in the background. Poll /api/sessions for the new session id once it completes.',
  });
});

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

app.get('/api/attestation/ledger', async (_req: Request, res: Response) => {
  try {
    const records = await ledger.getFullLedger();
    res.json({ records });
  } catch (err) {
    logger.error('Failed to read attestation ledger', err);
    res.json({ records: [] }); // no ledger yet is a valid empty state, not an error
  }
});

app.get('/api/attestation/public-key', async (_req: Request, res: Response) => {
  try {
    const publicKey = await ledger.getPublicKey();
    res.json({ publicKey });
  } catch (err) {
    logger.error('Failed to read attestation public key', err);
    res.status(500).json({ error: 'Failed to read attestation public key' });
  }
});

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

app.get('/api/quarantine/log', async (_req: Request, res: Response) => {
  try {
    const records = await quarantine.getFullLog();
    res.json({ records });
  } catch (err) {
    logger.error('Failed to read quarantine log', err);
    res.json({ records: [] });
  }
});

app.get('/api/quarantine/integrity', async (_req: Request, res: Response) => {
  try {
    const result = await quarantine.verifyChainIntegrity();
    res.json(result);
  } catch (err) {
    logger.error('Failed to verify quarantine chain integrity', err);
    res.status(500).json({ error: 'Failed to verify chain integrity' });
  }
});

// ---------------------------------------------------------------------------
// Reports / discovery / graph
// ---------------------------------------------------------------------------

app.get('/api/reports/latest', async (_req: Request, res: Response) => {
  const report = await readLatestReport();
  if (!report) {
    return res.status(404).json({ error: 'No scan reports found yet. Run npm run fullscan first.' });
  }
  res.json(report);
});

// Kept for backwards compatibility with anything still calling the old name.
app.get('/api/latest-scan', async (_req: Request, res: Response) => {
  const report = await readLatestReport();
  if (!report) {
    return res.status(404).json({ error: 'No scan reports found yet. Run npm run fullscan first.' });
  }
  res.json(report);
});

app.get('/api/discovery', async (_req: Request, res: Response) => {
  const report = await readLatestReport();
  const servers: MCPServerInventory[] = report?.inventories ?? [];
  res.json({ servers, totalTools: servers.reduce((sum, s) => sum + s.tools.length, 0) });
});

// Kept for backwards compatibility with the old flat name.
app.get('/api/ledger', async (_req: Request, res: Response) => {
  try {
    const records = await ledger.getFullLedger();
    res.json(records);
  } catch {
    res.json([]);
  }
});

app.get('/api/graph', async (_req: Request, res: Response) => {
  const report = await readLatestReport();
  if (!report) {
    return res.status(404).json({ error: 'No scan reports found yet.' });
  }
  try {
    const servers: MCPServerInventory[] = report.inventories ?? [];
    const findings: VulnerabilityFinding[] = report.findings ?? [];
    const discovery: DiscoveryResult = {
      servers,
      totalTools: servers.reduce((sum, s) => sum + s.tools.length, 0),
      timestamp: report.scanCompletedAt ?? new Date().toISOString(),
    };
    const scores: RiskScore[] = servers.map((s) =>
      RiskCalculator.calculate(s.serverName, 'server', findings.filter((f) => f.serverName === s.serverName))
    );
    scores.map(classifyRisk); // computed for parity with the CLI pipeline

    const graph = buildGraph(discovery, findings, scores);
    res.json(graph);
  } catch (err) {
    logger.error('Failed to build graph from latest scan', err);
    res.status(500).json({ error: 'Failed to build graph' });
  }
});

// ---------------------------------------------------------------------------
// Logs — tails the real winston log file (logs/odezzy.log), not a synthetic
// feed. Returns the last N lines, newest last (same order they were written).
// ---------------------------------------------------------------------------

app.get('/api/logs', async (req: Request, res: Response) => {
  const lines = Math.min(Number(req.query.lines) || 100, 2000);
  try {
    const raw = await readFile(LOG_PATH, 'utf-8');
    const allLines = raw.split('\n').filter((l) => l.trim().length > 0);
    res.json({ logs: allLines.slice(-lines) });
  } catch {
    res.json({ logs: [] }); // no log file yet — nothing has run in this environment
  }
});

// ---------------------------------------------------------------------------
// Approval resolution — the one route that actually mutates state
// (quarantine + attestation revocation via ApplyFix). Bearer-token gated.
// ---------------------------------------------------------------------------

app.post('/api/approvals/resolve', requireApiToken, async (req: Request, res: Response) => {
  const { sessionId, toolCallId, threadId, findingId, approved, reason, lastTurnId } = req.body ?? {};

  if (typeof sessionId !== 'string' || typeof findingId !== 'string' || typeof toolCallId !== 'string' || typeof threadId !== 'string' || typeof approved !== 'boolean') {
    return res.status(400).json({ error: 'sessionId, findingId, toolCallId, threadId (strings) and approved (boolean) are all required.' });
  }

  const session = await sessionStore.load(sessionId);
  if (!session) {
    return res.status(404).json({ error: `No session found with id ${sessionId}.` });
  }

  const finding = session.findings.find((f) => f.id === findingId);
  if (!finding) {
    return res.status(404).json({ error: `No finding with id ${findingId} in session ${sessionId}.` });
  }

  const proposal = new FixProposer().proposeFixes([finding])[0];

  try {
    const client = createTrueForgeClient({} as any);
    const gate = new ApprovalGate(client, sessionId, lastTurnId);
    const result = await gate.resolveApproval({ toolCallId, threadId, approved, reason, proposal, finding });
    res.json(result);
  } catch (err) {
    logger.error('Failed to resolve approval', err);
    res.status(500).json({ error: 'Failed to resolve approval.' });
  }
});

export { app };

const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  app.listen(PORT, '127.0.0.1', () => {
    logger.info(`Odezzy API server running on http://127.0.0.1:${PORT} (loopback only)`);
  });
}
