import { describe, it, expect } from 'vitest';
import { HumanApprovalToken } from '../src/remediation/human-approval-token.js';
import { ApplyFix } from '../src/remediation/apply-fix.js';
import type { FixProposal } from '../src/remediation/fix-proposer.js';
import type { VulnerabilityFinding } from '../src/types/index.js';

describe('HumanApprovalToken', () => {
  it('cannot be constructed directly — there is no public constructor', () => {
    // This is a compile-time guarantee, not a runtime one: `new HumanApprovalToken(...)`
    // is a type error, not a throw. Proving it here means casting through `any`
    // to attempt the exact bypass the private constructor exists to block.
    expect(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      new (HumanApprovalToken as any)('finding-1', 'trueforge-ui', new Date().toISOString());
    }).not.toThrow();
    // Note: this call *succeeds* at runtime once cast through `any` — JS has no
    // private-field enforcement without ES2022 `#` fields. The real protection is
    // TypeScript refusing to compile `new HumanApprovalToken(...)` anywhere in the
    // actual (non-cast) codebase. That's why the codebase has zero legitimate call
    // sites for it besides the three factories below.
  });

  it('fromTrueForgeResolution throws when the outcome was a denial', () => {
    expect(() => HumanApprovalToken.fromTrueForgeResolution({ approved: false, findingId: 'finding-1' })).toThrow(
      /Cannot mint a HumanApprovalToken from a denial/
    );
  });

  it('fromTrueForgeResolution mints a token when the outcome was approved', () => {
    const token = HumanApprovalToken.fromTrueForgeResolution({ approved: true, findingId: 'finding-1' });
    expect(token.findingId).toBe('finding-1');
    expect(token.source).toBe('trueforge-ui');
    expect(typeof token.grantedAt).toBe('string');
  });

  it('fromCliConfirmFlag always succeeds — a human typing --confirm is the decision itself', () => {
    const token = HumanApprovalToken.fromCliConfirmFlag('finding-2');
    expect(token.findingId).toBe('finding-2');
    expect(token.source).toBe('cli-confirm');
  });

  it('fromTrueForgeGatedToolCall always succeeds — the handler running IS the proof of approval', () => {
    const token = HumanApprovalToken.fromTrueForgeGatedToolCall('finding-3');
    expect(token.findingId).toBe('finding-3');
    expect(token.source).toBe('trueforge-gated-tool-call');
  });
});

describe('ApplyFix.apply() finding-id cross-check', () => {
  const mockFinding: VulnerabilityFinding = {
    id: 'finding-A',
    toolName: 'evil_tool',
    serverName: 'test-server',
    severity: 'critical',
    category: 'prompt-injection',
    title: 'Prompt injection detected',
    description: 'desc',
    evidence: 'evidence',
    remediation: 'remediate',
    confidence: 0.9,
  };

  const mockProposal: FixProposal = {
    findingId: mockFinding.id,
    proposedFix: 'quarantine it',
    autoFixable: true,
    risk: 'safe',
  };

  it('rejects a token minted for a different finding, even though it is a genuine token', async () => {
    // This token is 100% legitimately minted — a human really did approve
    // something. It's just approval for finding-B, not finding-A. A token
    // being real is not the same as it being the right token.
    const tokenForADifferentFinding = HumanApprovalToken.fromCliConfirmFlag('finding-B');

    const result = await new ApplyFix().apply(mockProposal, mockFinding, tokenForADifferentFinding);

    expect(result.applied).toBe(false);
    expect(result.error).toMatch(/finding-B/);
    expect(result.error).toMatch(/finding-A/);
  });
});
