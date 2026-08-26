// src/server.ts — the API bridge between the backend's output files and the browser.
import express, { type Request, type Response } from 'express';
import cors from 'cors';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from './utils/logger.js';
import { buildGraph } from './report/graph-builder.js';
import { RiskCalculator } from './scoring/risk-formula.js';
import type { DiscoveryResult, MCPServerInventory, VulnerabilityFinding, RiskScore } from './types/index.js';
import type { ScanSession } from './persistence/session-store.js';
import { redactConfig } from './persistence/session-store.js';
import { ApprovalGate } from './remediation/approval-gate.js';
import { createTrueForgeClient } from './agent/trueforge-client.js';

const logger = createLogger('api-server');
const app = express();
const PORT = 4000;

app.use(cors({ origin: ['http://localhost:5173', 'http://127.0.0.1:5173'] })); // Vite's dev origin only

const REPORTS_DIR = '.odezzy/reports';
const LEDGER_PATH = '.odezzy/attestation/ledger.jsonl';
const SESSIONS_DIR = '.odezzy/sessions';

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
  let files: string[];
  try {
    files = (await readdir(SESSIONS_DIR)).filter((f) => f.endsWith('.json'));
  } catch {
    return []; // directory genuinely doesn't exist yet
  }

  const results = await Promise.allSettled(
    files.map(async (f) => JSON.parse(await readFile(join(SESSIONS_DIR, f), 'utf-8')) as ScanSession)
  );

  const sessions: ScanSession[] = [];
  for (const [i, r] of results.entries()) {
    if (r.status === 'fulfilled') {
      sessions.push(r.value);
    } else {
      logger.warn(`Skipping unreadable session file "${files[i]}": ${r.reason}`);
    }
  }
  return sessions;
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
  let raw: string;
  try {
    raw = await readFile(LEDGER_PATH, 'utf-8');
  } catch {
    return res.json([]); // genuinely no ledger file yet — real empty state
  }

  try {
    const records = raw
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line));
    res.json(records);
  } catch (err) {
    logger.error('Ledger file exists but contains invalid JSON — possible corruption', err);
    res.status(500).json({ error: 'Ledger file is corrupted or unreadable. Check .odezzy/attestation/ledger.jsonl directly.' });
  }
});

// Single source of truth for /api/sessions. There was previously a second,
// duplicate handler for this same path further down that called a
// never-defined readAllSessions() and would have crashed on every request —
// Express only ever dispatches to the first handler registered for a given
// route, so that second one was silently dead code anyway. Consolidated into
// one handler here, keeping the redaction behavior from the dead one since
// that was the more complete version.
app.get('/api/sessions', async (_req: Request, res: Response) => {
  const sessions = await readAllSessions();
  const safe = sessions
    .map((s) => ({
      ...s,
      configSnapshot: s.configSnapshot ? redactConfig(s.configSnapshot) : s.configSnapshot,
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

    // The saved report stores servers under `inventories` (a flat
    // MCPServerInventory[]), not `inventory` — and it doesn't persist risk
    // scores at all, since those were only ever printed to the terminal.
    // Reconstruct both here to match what buildGraph actually expects.
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

app.post('/api/approvals/resolve', express.json(), async (req: Request, res: Response) => {
  const { sessionId, toolCallId, threadId, findingId, approved, reason, lastTurnId } = req.body;
  // TODO: load the real `proposal` and `finding` objects for `findingId` from the
  // matching saved session/report before calling this — omitted here since it
  // depends on how you want to look them up (session-store vs latest report).
  const proposal: any = {}; 
  const finding: any = {};

  const client = createTrueForgeClient({} as any);
  const gate = new ApprovalGate(client, sessionId, lastTurnId);
  const result = await gate.resolveApproval({ toolCallId, threadId, approved, reason, proposal, finding });
  res.json(result);
});

app.listen(PORT, '127.0.0.1', () => {
  logger.info(`Odezzy API server running on http://127.0.0.1:${PORT} (loopback only)`);
});