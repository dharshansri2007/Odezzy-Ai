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
 * HumanApprovalToken.fromTrueForgeGatedToolCall() in
 * src/remediation/human-approval-token.ts for why that's minted here
 * instead of trusting a boolean flag passed in the tool call arguments
 * (which anyone — or anything — could set to true).
 *
 * Setup (Job 3 — manual, on TrueForge's platform, not scriptable from here):
 *   1. Register this server under TrueForge's Settings → Connectors,
 *      pointing its command at: npx tsx remediation-server/server.ts
 *   2. Set requireApprovalForTools: ["@all"] on that connector.
 *   3. Give the connector a name, then set that same name as
 *      REMEDIATION_MCP_SERVER_NAME in your .env (see src/config/parser.ts).
 *   4. Run `npm run fullscan` — a finding with an autoFixable proposal will
 *      now genuinely pause in TrueForge's UI instead of failing closed.
 *
 * Run standalone (for manual testing outside TrueForge):
 *   npm run remediation-server
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { SessionStore } from '../src/persistence/session-store.js';
import { FixProposer } from '../src/remediation/fix-proposer.js';
import { ApplyFix } from '../src/remediation/apply-fix.js';
import { HumanApprovalToken } from '../src/remediation/human-approval-token.js';
import type { VulnerabilityFinding } from '../src/types/index.js';

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

/**
 * Finding ids are globally unique UUIDs minted fresh on every scan, so the
 * right session to search is whichever one actually contains this id — not
 * necessarily the most recent scan (a human might approve something from an
 * earlier run). Search newest-first since that's the common case, but check
 * all of them rather than assuming "latest" is always correct.
 */
async function findFindingAcrossSessions(findingId: string): Promise<VulnerabilityFinding | null> {
  const store = new SessionStore();
  const sessionIds = await store.list();
  // list() doesn't guarantee order; sort descending so newest sessions
  // (higher/later ids, which session ids aren't inherently sortable by —
  // so fall back to checking every session; this is O(n) in session count,
  // which is fine at hackathon/dev scale) are checked without assuming.
  for (const id of sessionIds) {
    const session = await store.load(id);
    const finding = session?.findings.find((f) => f.id === findingId);
    if (finding) return finding;
  }
  return null;
}

const server = new Server(
  { name: 'odezzy-remediation-server', version: '0.1.0' },
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
    return {
      content: [{ type: 'text', text: '[remediation-server] Error: findingId is required.' }],
      isError: true,
    };
  }

  const finding = await findFindingAcrossSessions(findingId);
  if (!finding) {
    return {
      content: [{ type: 'text', text: `[remediation-server] No finding found with id ${findingId} in any saved session.` }],
      isError: true,
    };
  }

  const proposal = new FixProposer().proposeFixes([finding])[0];
  if (!proposal.autoFixable) {
    return {
      content: [{ type: 'text', text: `[remediation-server] Finding "${finding.title}" (category: ${finding.category}) is not eligible for automated quarantine.` }],
      isError: true,
    };
  }

  // This handler only ever runs because TrueForge itself refused to call
  // it until a human approved the pending tool call — that's the whole
  // point of requireApprovalForTools. The token below documents that,
  // rather than trusting anything in `args`.
  const token = HumanApprovalToken.fromTrueForgeGatedToolCall(finding.id);
  const result = await new ApplyFix().apply(proposal, finding, token);

  if (!result.applied) {
    return {
      content: [{ type: 'text', text: `[remediation-server] Failed to apply fix: ${result.error}` }],
      isError: true,
    };
  }

  return {
    content: [{ type: 'text', text: `[remediation-server] ${result.detail}` }],
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[remediation-server] running on stdio');
}

main().catch((err) => {
  console.error('[remediation-server] fatal:', err);
  process.exit(1);
});