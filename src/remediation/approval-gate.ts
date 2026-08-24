import { createLogger } from '../utils/logger.js';
import { sendOdezzyTurn, resolveOdezzyApproval } from '../agent/trueforge-client.js';
import type { TrueForge } from '@truefoundry/trueforge-sdk';
import type { VulnerabilityFinding } from '../types/index.js';
import type { FixProposal } from './fix-proposer.js';

const logger = createLogger('approval-gate');

/**
 * Replaces the previous CLI readline y/n prompt with TrueForge's real
 * tool-call approval mechanism (verified against @truefoundry/trueforge-sdk's
 * shipped types — see agent/trueforge-client.ts for how).
 *
 * Important shape difference from a generic "approve this thing" API:
 * TrueForge only pauses for approval on a TOOL CALL the agent's own LLM
 * decided to make against an MCP server configured with
 * `requireApprovalForTools`. This class does not itself decide when to
 * pause — it asks the agent to consider applying the fix, and if (and
 * only if) that causes the agent to attempt a gated tool call, TrueForge
 * surfaces a `pendingApprovals` entry that this class then resolves.
 *
 * This means `requestApproval` requires a remediation-tools MCP server
 * to already be registered under TrueForge's Settings → Connectors,
 * exposing something like an `apply_fix` tool, with
 * `requireApprovalForTools: ["@all"]` set on it (see root-agent.ts). If
 * no such connector exists, the agent has nothing gated to call, so no
 * approval pause will ever occur — this fails closed (see below), it
 * does not silently apply fixes.
 */
export class ApprovalGate {
  constructor(private client: TrueForge, private sessionId: string, private lastTurnId?: string) {}

  public async requestApproval(
    proposal: FixProposal,
    finding: VulnerabilityFinding
  ): Promise<{ approved: boolean; reason?: string }> {
    logger.info(`Requesting TrueForge approval for finding ${finding.id} (${finding.title})`);

    const outcome = await sendOdezzyTurn(this.client, this.sessionId, {
      previousTurnId: this.lastTurnId ?? 'auto',
      input: [
        {
          type: 'user.message',
          content:
            `Proposed remediation for finding "${finding.title}" (${finding.severity}) on tool ` +
            `"${finding.toolName}": ${proposal.proposedFix}. Risk: ${proposal.risk}. ` +
            `If you have an apply_fix tool available, call it now with this finding's id ` +
            `(${finding.id}) so a human can approve or deny the actual change.`,
        },
      ],
    });
    this.lastTurnId = outcome.turnId;

    if (outcome.pendingApprovals.length === 0) {
      // No approval pause was triggered — either no remediation-tools
      // connector is registered, or the agent chose not to call it.
      // Fail closed (never fail open on a security tool): treat as
      // rejected rather than assuming the fix was silently applied.
      logger.warn(
        `No approval pause returned for finding ${finding.id} — defaulting to rejected (fail closed). ` +
          `Check that a remediation-tools MCP connector with requireApprovalForTools is registered in TrueForge.`
      );
      return { approved: false, reason: 'No approval mechanism triggered — failed closed' };
    }

    // In a real run, a human resolves this via TrueForge's own chat UI
    // (http://localhost:8790) before this process would ever see it
    // resolved — Odezzy AI is not the thing granting approval, TrueForge
    // is. For an unattended batch run there is nothing to poll from here
    // that isn't already TrueForge's own session/turn state, so we
    // surface the pause and let the caller decide whether to wait.
    const pending = outcome.pendingApprovals[0];
    logger.info(
      `Finding ${finding.id} is now pending human approval in TrueForge (toolCallId=${pending.toolCallId}). ` +
        `Resolve it in the TrueForge chat UI, or call resolveApproval() below programmatically once a decision is made.`
    );
    return { approved: false, reason: 'Awaiting human resolution via TrueForge UI' };
  }

  /**
   * Programmatic escape hatch for a caller (e.g. a UI or test) that
   * already has a human's decision and wants to resolve the pending
   * approval directly, rather than waiting on TrueForge's own chat UI.
   */
  public async resolveApproval(params: {
    toolCallId: string;
    threadId: string;
    approved: boolean;
    reason?: string;
  }): Promise<{ approved: boolean; reason?: string }> {
    if (!this.lastTurnId) {
      throw new Error('resolveApproval() called before any turn was sent for this gate.');
    }
    const outcome = await resolveOdezzyApproval(this.client, this.sessionId, {
      previousTurnId: this.lastTurnId,
      toolCallId: params.toolCallId,
      threadId: params.threadId,
      approved: params.approved,
      reason: params.reason,
    });
    this.lastTurnId = outcome.turnId;
    return { approved: params.approved, reason: params.reason };
  }
}
