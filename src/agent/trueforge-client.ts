/**
 * Thin adapter around the real @truefoundry/trueforge-sdk client.
 *
 * VERIFICATION NOTE (replaces the guessed fetch()-based adapter from the
 * prior handoff): rather than reading `/api/v1/docs` in a browser, this
 * was verified by installing `@truefoundry/trueforge-sdk` in isolation
 * and reading its shipped `.d.ts` files directly — the SDK is generated
 * (via Fern) straight from TrueForge's real OpenAPI spec, so its types
 * ARE the contract. That's the second verification path the prior
 * handoff described ("TypeScript will show you the real method
 * signatures the moment you import it") — just done via `.d.ts`
 * inspection instead of editor autocomplete.
 *
 * Key corrections vs. the prior guessed adapter:
 *  - There is no bare `/api/v1/sessions` REST shape to hand-roll — use
 *    the `TrueForge` SDK client (`client.sessions.*`, `client.agents.*`).
 *  - There is no generic `/api/v1/approvals/:id` endpoint. Tool-call
 *    approval is a first-class part of the turn lifecycle: a turn can
 *    end in `state.status === "done"` with
 *    `requiredActions: [{ type: "tool.approval_required", toolCalls }]`.
 *    You resolve it by starting the NEXT turn with a
 *    `{ type: "user.tool_approval", toolCallId, approval }` input item
 *    chained via `previousTurnId`.
 *  - There is no generic "run this code in the sandbox" endpoint on the
 *    client either — sandbox execution happens as a side effect of the
 *    agent's own tool calls inside a turn (see `RuntimeConfig.sandbox`
 *    on `AgentSpec`), not something you invoke directly from outside.
 *    Odezzy's probing (probing/sandbox-runner.ts) intentionally does NOT
 *    go through TrueForge for this reason — it needs to send exact,
 *    adversarial argument payloads, which isn't what an LLM-driven tool
 *    call gives you. Only remediation approval is TrueForge-native.
 *  - MCP servers are referenced by NAME and must already exist as a
 *    connector under TrueForge's Settings → Connectors — there is no
 *    "register a new MCP server" call on `client.mcpServers` (only
 *    `list`, `authorize`, `deleteAuthorization`, `listTools`). This is a
 *    one-time manual setup step, not something this file can automate.
 *    See root-agent.ts's class doc for what to register.
 */
import { TrueForge, TrueForgeApi } from '@truefoundry/trueforge-sdk';
import { createLogger } from '../utils/logger.js';
import type { OdezzyConfig } from '../types/index.js';

const logger = createLogger('trueforge-client');

export interface OdezzyTurnOutcome {
  turnId: string;
  /** Final assistant text, or null if the turn paused without a final message. */
  responseText: string | null;
  /** Non-empty when the turn stopped waiting on a tool-call approval decision. */
  pendingApprovals: { toolCallId: string; sourceEventId: string; threadId: string }[];
}

/**
 * Creates a configured TrueForge SDK client from Odezzy's own config.
 * `trueforgeApiKey` is optional — TrueForge's local single-user mode
 * (`npx @truefoundry/trueforge`) doesn't require a bearer token.
 */
export function createTrueForgeClient(config: OdezzyConfig): TrueForge {
  return new TrueForge({
    baseUrl: config.trueforgeUrl ?? 'http://localhost:8790',
    token: config.trueforgeApiKey,
  });
}

/**
 * Opens a new TrueForge session for this scan run, with an inline agent
 * spec (not a named/registered agent — Odezzy defines its own agent
 * behavior per run rather than requiring a pre-registered agent).
 */
export async function createOdezzyScanSession(
  client: TrueForge,
  config: OdezzyConfig,
  opts: { remediationMcpServerName?: string } = {}
): Promise<{ sessionId: string }> {
  const { data: session } = await client.sessions.create({
    agent: {
      spec: {
        model: { name: config.trueforgeModel },
        instructions:
          'You are Odezzy AI, an MCP security red-teaming agent. You review proposed ' +
          'remediation fixes for vulnerabilities found in third-party MCP servers and, ' +
          'when asked, request the appropriate remediation tool call so a human can approve or deny it.',
        // Only attach the remediation-tools MCP server if the caller configured one.
        // This MUST already exist as a connector under TrueForge's Settings →
        // Connectors — see root-agent.ts for what to register and why.
        mcpServers: opts.remediationMcpServerName
          ? [
              {
                name: opts.remediationMcpServerName,
                requireApprovalForTools: ['@all'],
              },
            ]
          : undefined,
      },
    },
  });

  logger.info(`Opened TrueForge session ${session.id}`);
  return { sessionId: session.id };
}

/**
 * Sends a turn and normalizes the result into the shape Odezzy's
 * agent/remediation code actually needs, regardless of whether the turn
 * finished cleanly or paused on a pending tool approval.
 *
 * Uses the non-streaming variant (`createTurn`, not `createTurnStream`)
 * — Odezzy doesn't need token-by-token output, just the final state.
 */
export async function sendOdezzyTurn(
  client: TrueForge,
  sessionId: string,
  params: {
    /** Plain user message text, OR resume item(s) resolving a prior pending approval. */
    input: TrueForgeApi.TurnInputItem[];
    previousTurnId?: TrueForgeApi.PreviousTurnIdInput;
  }
): Promise<OdezzyTurnOutcome> {
  const { data: turn } = await client.sessions.createTurn(sessionId, {
    input: params.input,
    previousTurnId: params.previousTurnId,
  });

  if (turn.state.status !== 'done') {
    // Non-streaming createTurn still executes synchronously to a
    // terminal state in the common case; if it ever comes back
    // "running" (e.g. server chose to background it), the caller
    // should poll getTurn — not modeled here since Odezzy's remediation
    // flow is low-volume and synchronous by design.
    logger.warn(`Turn ${turn.id} returned in unexpected state "${turn.state.status}"`);
    return { turnId: turn.id, responseText: null, pendingApprovals: [] };
  }

  const pendingApprovals = turn.state.requiredActions
    .filter((a): a is TrueForgeApi.ToolApprovalRequiredEvent => a.type === 'tool.approval_required')
    .flatMap((a) =>
      a.toolCalls.map((tc: TrueForgeApi.ToolCallRef) => ({
        toolCallId: tc.id,
        sourceEventId: tc.sourceEventId,
        threadId: a.threadId,
      }))
    );

  const responseText =
    turn.state.output?.content && typeof turn.state.output.content === 'string'
      ? turn.state.output.content
      : null;

  return { turnId: turn.id, responseText, pendingApprovals };
}

/**
 * Resolves one pending tool-call approval by chaining a new turn off the
 * turn that raised it, with a `user.tool_approval` input item — the
 * TrueForge-native replacement for the prior CLI readline prompt.
 */
export async function resolveOdezzyApproval(
  client: TrueForge,
  sessionId: string,
  params: {
    previousTurnId: string;
    toolCallId: string;
    threadId: string;
    approved: boolean;
    reason?: string;
  }
): Promise<OdezzyTurnOutcome> {
  return sendOdezzyTurn(client, sessionId, {
    previousTurnId: params.previousTurnId,
    input: [
      {
        type: 'user.tool_approval',
        toolCallId: params.toolCallId,
        threadId: params.threadId,
        approval: params.approved ? { status: 'allow' } : { status: 'deny', reason: params.reason },
      },
    ],
  });
}

/**
 * Narrates a scan phase into the TrueForge session as a lightweight turn.
 * This makes the entire Odezzy scan visible and replayable inside
 * TrueForge's own UI — not just the approval step (Lever 3).
 *
 * Fires and forgets: narration failures never block the scan.
 */
export async function narrateScanPhase(
  client: TrueForge,
  sessionId: string,
  phase: string,
  details: string,
  previousTurnId?: string
): Promise<string | undefined> {
  try {
    const { data: turn } = await client.sessions.createTurn(sessionId, {
      input: [
        {
          type: 'user.message',
          content: `[Odezzy Scan Phase: ${phase}] ${details}`,
        },
      ],
      previousTurnId: previousTurnId ?? 'auto',
    });
    return turn.id;
  } catch (err) {
    logger.warn(`Failed to narrate scan phase "${phase}" — non-fatal`, err);
    return previousTurnId;
  }
}
