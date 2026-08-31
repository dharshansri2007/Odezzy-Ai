#!/usr/bin/env node
/**
 * Odezzy AI — Remediation Server
 * ===============================
 * A real MCP server exposing exactly one tool, `apply_fix`, that TrueForge
 * calls to actually apply an approved remediation (quarantine a tool +
 * revoke its attestation).
 *
 * This server does nothing dangerous on its own — it has no idea whether a
 * human approved anything. The safety property comes entirely from how this
 * server is registered on TrueForge's side: under Settings → Connectors,
 * with `requireApprovalForTools: ["@all"]` set. TrueForge itself refuses to
 * ever forward a call to this server's `apply_fix` handler until a human
 * clicks approve in TrueForge's own UI. The handler below running at all
 * *is* the proof of human approval — see
 * HumanApprovalToken.fromTrueForgeGatedToolCall() for why that's minted
 * here instead of trusting a boolean flag in the tool call arguments.
 *
 * TRANSPORT: Streamable HTTP, not stdio. TrueForge's "Add MCP Server"
 * dialog only accepts a URL — it cannot launch a local process via a
 * command string — so this serves over HTTP via Express.
 *
 * A FRESH Server+transport pair is built PER REQUEST inside the /mcp
 * handler below, matching the MCP SDK's own reference example for
 * stateless mode (examples/server/simpleStatelessStreamableHttp.ts). An
 * earlier revision of this file built one shared Server+transport pair
 * once at startup and reused it for every request — that worked for the
 * first `initialize` call and then 500'd on every request after it. Tested
 * directly with curl against a live instance; the SDK's own example
 * confirmed the correct pattern is a fresh pair per request, not a shared
 * singleton, even in stateless mode.
 *
 * AUTH: requires REMEDIATION_SERVER_TOKEN, checked via
 * `Authorization: Bearer <token>` on every request. Without this, anything
 * that could reach this port could call apply_fix directly and bypass
 * TrueForge's approval gate entirely — the HumanApprovalToken minted below
 * only proves "this handler ran," not "TrueForge's gate ran first."
 *
 * Setup (manual, on TrueForge's platform, not scriptable from here):
 *   1. Set REMEDIATION_SERVER_TOKEN in your .env to a long random secret.
 *   2. Run: npm run remediation-server (listens on REMEDIATION_SERVER_PORT,
 *      default 8791).
 *   3. Make that port reachable from wherever TrueForge itself runs. If
 *      TrueForge is remote, localhost there means "the box TrueForge runs
 *      on," not this one.
 *   4. TrueForge → Settings → Connectors → "+ Add MCP Server":
 *        URL: http://<reachable-host>:8791/mcp
 *        Auth: Bearer token = same REMEDIATION_SERVER_TOKEN value
 *        requireApprovalForTools: ["@all"]
 *   5. Set that connector's name as REMEDIATION_MCP_SERVER_NAME in .env.
 *   6. Run `npm run fullscan` — an autoFixable finding will now genuinely
 *      pause in TrueForge's UI instead of failing closed.
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { SessionStore } from '../src/persistence/session-store.js';
import { FixProposer } from '../src/remediation/fix-proposer.js';
import { ApplyFix } from '../src/remediation/apply-fix.js';
import { HumanApprovalToken } from '../src/remediation/human-approval-token.js';
import type { VulnerabilityFinding } from '../src/types/index.js';

const REMEDIATION_TOKEN = process.env.REMEDIATION_SERVER_TOKEN;
if (!REMEDIATION_TOKEN) {
  console.error(
    '[remediation-server] FATAL: REMEDIATION_SERVER_TOKEN is not set. Refusing to start — ' +
    'without it, this server would apply real remediations for anything that can reach its port.'
  );
  process.exit(1);
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header('Authorization');
  const provided = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;
  if (!provided || provided !== REMEDIATION_TOKEN) {
    res.status(401).json({ jsonrpc: '2.0', error: { code: -32001, message: 'Missing or invalid Authorization: Bearer <token>.' }, id: null });
    return;
  }
  next();
}

const APPLY_FIX_TOOL = {
  name: 'apply_fix',
  description:
    'Applies an approved security remediation for a specific Odezzy AI finding — quarantines the ' +
    'offending tool and revokes its cryptographic attestation. Only call this after a human has ' +
    'reviewed and approved the specific finding id. This tool is registered with ' +
    'requireApprovalForTools, so TrueForge itself will pause and ask a human before this handler ' +
    'ever actually runs.',
  inputSchema: {
    type: 'object',
    properties: {
      findingId: { type: 'string', description: 'The id of the VulnerabilityFinding to remediate.' },
    },
    required: ['findingId'],
  },
};

async function findFindingAcrossSessions(findingId: string): Promise<VulnerabilityFinding | null> {
  const store = new SessionStore();
  const sessionIds = await store.list();
  for (const id of sessionIds) {
    const session = await store.load(id);
    const finding = session?.findings.find((f) => f.id === findingId);
    if (finding) return finding;
  }
  return null;
}

/**
 * Builds one fresh Server instance with its tool handlers wired up. Cheap
 * to call per-request — no state lives on the Server object itself, all
 * real state is the on-disk stores each handler call reads/writes.
 */
function buildServer(): Server {
  const server = new Server(
    { name: 'odezzy-remediation-server', version: '0.3.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [APPLY_FIX_TOOL],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name !== 'apply_fix') {
      throw new Error(`Unknown tool: ${name}`);
    }

    const findingId = typeof args?.findingId === 'string' ? args.findingId : undefined;
    if (!findingId) {
      return { content: [{ type: 'text', text: '[remediation-server] Error: findingId is required.' }], isError: true };
    }

    const finding = await findFindingAcrossSessions(findingId);
    if (!finding) {
      return { content: [{ type: 'text', text: `[remediation-server] No finding found with id ${findingId} in any saved session.` }], isError: true };
    }

    const proposal = new FixProposer().proposeFixes([finding])[0];
    if (!proposal.autoFixable) {
      return { content: [{ type: 'text', text: `[remediation-server] Finding "${finding.title}" (category: ${finding.category}) is not eligible for automated quarantine.` }], isError: true };
    }

    // This handler only runs if (a) the caller had a valid bearer token,
    // proving it's TrueForge, AND (b) TrueForge itself refused to make
    // this call until a human approved the pending tool call.
    const token = HumanApprovalToken.fromTrueForgeGatedToolCall(finding.id);
    const result = await new ApplyFix().apply(proposal, finding, token);

    if (!result.applied) {
      return { content: [{ type: 'text', text: `[remediation-server] Failed to apply fix: ${result.error}` }], isError: true };
    }

    return { content: [{ type: 'text', text: `[remediation-server] ${result.detail}` }] };
  });

  return server;
}

async function main() {
  const port = Number(process.env.REMEDIATION_SERVER_PORT ?? 8791);
  const app = express();
  app.use(express.json());

  app.post('/mcp', requireAuth, async (req, res) => {
    // Fresh Server + transport per request — see the header comment above
    // for why a shared instance breaks after the first call.
    try {
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error('[remediation-server] error handling POST /mcp:', err);
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
      }
    }
  });

  app.get('/mcp', requireAuth, (_req, res) => res.status(405).json({ error: 'This server is stateless; GET /mcp is not supported.' }));
  app.delete('/mcp', requireAuth, (_req, res) => res.status(405).json({ error: 'This server is stateless; DELETE /mcp is not supported.' }));

  app.listen(port, () => {
    console.error(`[remediation-server] listening on http://localhost:${port}/mcp (Streamable HTTP, stateless, auth required)`);
    console.error('[remediation-server] if TrueForge runs remotely, point its connector at a URL that can actually reach this port — not localhost from TrueForge\'s side.');
  });
}

main().catch((err) => {
  console.error('[remediation-server] fatal:', err);
  process.exit(1);
});