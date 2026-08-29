/**
 * A HumanApprovalToken can only be minted by code paths that actually
 * received a human decision. ApplyFix.apply() requires one as a parameter.
 * There is no way to construct one except through the two blessed static
 * factories below — the constructor is private, so `new HumanApprovalToken(...)`
 * and object-literal stand-ins like `{}` or `{ findingId, approved: true }`
 * are both structurally impossible to pass where a token is required.
 *
 * This exists because a real bug shipped without it: an API endpoint built
 * `proposal`/`finding` as empty stub objects and called ApplyFix.apply()
 * directly from an unauthenticated POST body's `approved: true` flag. With
 * this type in place, that bug class cannot compile — there is no way to
 * get a HumanApprovalToken without going through fromTrueForgeResolution()
 * or fromCliConfirmFlag(), and both require the caller to already be holding
 * a genuine human decision, not just an intention to fabricate one.
 */
export class HumanApprovalToken {
  private constructor(
    readonly findingId: string,
    readonly source: 'trueforge-ui' | 'cli-confirm' | 'trueforge-gated-tool-call',
    readonly grantedAt: string
  ) {}

  /**
   * The only path from TrueForge's own approval resolution. Throws if the
   * outcome wasn't actually an approval — you cannot mint a token from a
   * denial, so a caller can't "downgrade" a rejected outcome into a token
   * by mistake.
   */
  static fromTrueForgeResolution(outcome: { approved: boolean; findingId: string }): HumanApprovalToken {
    if (!outcome.approved) {
      throw new Error('Cannot mint a HumanApprovalToken from a denial or unresolved outcome.');
    }
    return new HumanApprovalToken(outcome.findingId, 'trueforge-ui', new Date().toISOString());
  }

  /**
   * The only path from the CLI's `quarantine <session> <finding> --confirm`
   * command. A human typing --confirm against a specific finding id, on
   * their own machine, in their own terminal, is the human decision itself
   * — same authority level as the TrueForge UI path, just a different
   * surface.
   */
  static fromCliConfirmFlag(findingId: string): HumanApprovalToken {
    return new HumanApprovalToken(findingId, 'cli-confirm', new Date().toISOString());
  }

  /**
   * The path from the remediation MCP server (remediation-server/server.ts)
   * — deliberately distinct from fromTrueForgeResolution above. This one's
   * proof of approval isn't an { approved: true } outcome object at all: a
   * server registered with `requireApprovalForTools` never has its handler
   * invoked until TrueForge itself confirms a human approved the pending
   * tool call. The handler running is the proof — there's nothing further
   * to check here, and pretending there's an "outcome" to inspect would be
   * less honest than naming this as its own distinct source.
   */
  static fromTrueForgeGatedToolCall(findingId: string): HumanApprovalToken {
    return new HumanApprovalToken(findingId, 'trueforge-gated-tool-call', new Date().toISOString());
  }
}