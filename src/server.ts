// src/server.ts — the dashboard API bridge between the backend's output
// files and the browser. Read-only except for /api/approvals/resolve,
// which is the one mutating route and is bearer-token gated.
//
// NOTE: this file is deliberately separate from remediation-server/server.ts.
// A prior merge overwrote this file's actual content with a duplicate copy
// of the remediation MCP server, which (a) deleted every dashboard route
// below, and (b) exposed an unauthenticated endpoint that could trigger
// real quarantine + attestation revocation from any HTTP client that could
// reach the port. Restored here; the remediation server logic now lives
// only in remediation-server/server.ts, on its own port, with its own auth.
import express, { type Request, type Response } from 'express';
import cors from 'cors';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from './utils/logger.js';
import { buildGraph } from './report/graph-builder.js';
import { RiskCalculator } from './scoring/risk-formula.js';
import { ApprovalGate } from './remediation/approval-gate.js';
import { createTrueForgeClient } from './agent/trueforge-client.js';
import { SessionStore } from './persistence/session-store.js';
import { FixProposer } from './remediation/fix-proposer.js';
import type { DiscoveryResult, MCPServerInventory, VulnerabilityFinding, RiskScore } from './types/index.js';
import type { ScanSession } from './persistence/session-store.js';

const logger = createLogger('api-server');
const app = express();
const PORT = 4000;

app.use(cors()); // dev-only convenience; Vite's proxy makes this mostly unnecessary but harmless

const REPORTS_DIR = '.odezzy/reports';
const LEDGER_PATH = '.odezzy/attestation/ledger.jsonl';
const SESSIONS_DIR = '.odezzy/sessions';

// The one mutating route on this server (/api/approvals/resolve) requires
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
    const files = (await readdir(REPORTS_DIR)).filter(f => f.endsWith('.json')).sort();
    return files.length > 0 ? join(REPORTS_DIR, files[files.length - 1]) : null;
  } catch {
    return null; // no reports yet — expected before the first scan, not an error
  }
}

/** Loads every saved session from disk. Empty array if none exist yet — not an error state. */
async function readAllSessions(): Promise<ScanSession[]> {
  try {
    const files = (await readdir(SESSIONS_DIR)).filter(f => f.endsWith('.json'));
    return await Promise.all(
      files.map(async (f) => JSON.parse(await readFile(join(SESSIONS_DIR, f), 'utf-8')) as ScanSession)
    );
  } catch {
    return [];
  }
}

app.get('/api/latest-scan', async (_req: Request, res: Response) => {
  const path = await getLatestReportPath();
  if (!path) {
    return res.status(404).json({ error: 'No scan reports found yet. Run npm run fullscan first.' });
  }
  try {
    const raw = await readFile(path, 'utf-8');
    res.json(JSON.parse(raw));
  } catch (err) {
    logger.error('Failed to read latest report', err);
    res.status(500).json({ error: 'Failed to read report file' });
  }
});

app.get('/api/ledger', async (_req: Request, res: Response) => {
  try {
    const raw = await readFile(LEDGER_PATH, 'utf-8');
    const records = raw
      .split('\n')
      .filter(line => line.trim().length > 0)
      .map(line => JSON.parse(line));
    res.json(records);
  } catch {
    res.json([]); // no ledger yet is a valid empty state, not an error — frontend should handle an empty array gracefully
  }
});

app.get('/api/sessions', async (_req: Request, res: Response) => {
  const sessions = await readAllSessions();
  const safe = sessions
    .map((s) => ({
      ...s,
      configSnapshot: s.configSnapshot ? { ...s.configSnapshot, geminiApiKey: undefined } : s.configSnapshot,
    }))
    .sort((a, b) => (b.startedAt ?? '').localeCompare(a.startedAt ?? ''));
  res.json(safe);
});

app.get('/api/graph', async (_req: Request, res: Response) => {
  const path = await getLatestReportPath();
  if (!path) {
    return res.status(404).json({ error: 'No scan reports found yet.' });
  }
  try {
    const report = JSON.parse(await readFile(path, 'utf-8'));

    const servers: MCPServerInventory[] = report.inventories ?? [];
    const findings: VulnerabilityFinding[] = report.findings ?? [];
    const discovery: DiscoveryResult = {
      servers,
      totalTools: servers.reduce((sum, s) => sum + s.tools.length, 0),
      timestamp: report.scanCompletedAt ?? new Date().toISOString(),
    };
    const scores: RiskScore[] = servers.map((s) =>
      RiskCalculator.calculate(
        s.serverName,
        'server',
        findings.filter((f) => f.serverName === s.serverName)
      )
    );

    const graph = buildGraph(discovery, findings, scores);
    res.json(graph);
  } catch (err) {
    logger.error('Failed to build graph from latest scan', err);
    res.status(500).json({ error: 'Failed to build graph' });
  }
});

app.post('/api/approvals/resolve', requireApiToken, express.json(), async (req: Request, res: Response) => {
  const { sessionId, toolCallId, threadId, findingId, approved, reason, lastTurnId } = req.body ?? {};

  if (typeof sessionId !== 'string' || typeof findingId !== 'string' || typeof toolCallId !== 'string' || typeof threadId !== 'string' || typeof approved !== 'boolean') {
    return res.status(400).json({ error: 'sessionId, findingId, toolCallId, threadId (strings) and approved (boolean) are all required.' });
  }

  const session = await new SessionStore().load(sessionId);
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