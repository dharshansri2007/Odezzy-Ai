import { createLogger } from '../utils/logger.js';
import { QuarantineRegistry } from './quarantine-registry.js';
import { AttestationLedger } from '../attestation/attestation-ledger.js';
import { HumanApprovalToken } from './human-approval-token.js';
import type { FixProposal } from './fix-proposer.js';
import type { VulnerabilityFinding } from '../types/index.js';

const logger = createLogger('apply-fix');
const registry = new QuarantineRegistry();
const ledger = new AttestationLedger();

export interface FixResult {
  applied: boolean;
  detail?: string;
  error?: string;
}

export class ApplyFix {
  /**
   * Called only after a human decision exists — enforced by the type
   * system, not a comment: there is no way to construct a HumanApprovalToken
   * without going through HumanApprovalToken.fromTrueForgeResolution() or
   * .fromCliConfirmFlag(), and both of those require a genuine human
   * decision to already exist before a token can be minted.
   */
  public async apply(proposal: FixProposal, finding: VulnerabilityFinding, token: HumanApprovalToken): Promise<FixResult> {
    if (token.findingId !== finding.id) {
      // Defense in depth: a token minted for one finding must never be
      // reusable to approve a different one, even by accident.
      return { applied: false, error: `Approval token was granted for finding ${token.findingId}, not ${finding.id}.` };
    }

    if (!proposal.autoFixable) {
      return { applied: false, error: 'Finding is not eligible for automated quarantine' };
    }

    try {
      logger.info(`Executing approved remediation for ${finding.id} (approval source: ${token.source}, granted ${token.grantedAt})`);
      
      // 1. Add to the hard quarantine list — pass the token itself so the
      // quarantine record's tokenSource/grantedAt come from a genuine
      // approval, not a re-derived string.
      await registry.quarantine(finding.toolName, finding.serverName, finding.title, finding.id, token);
      
      // 2. Revoke cryptographic attestation immediately
      await ledger.revoke(finding.toolName, finding.serverName, `Quarantined via approved remediation: ${finding.title}`);
      
      return { 
        applied: true, 
        detail: `"${finding.toolName}" quarantined. Cryptographic trust revoked. It will be excluded from trusted results on all future scans.` 
      };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to apply quarantine: ${errorMsg}`);
      return { applied: false, error: errorMsg };
    }
  }
}