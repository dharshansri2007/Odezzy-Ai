import { createLogger } from '../utils/logger.js';
import { QuarantineRegistry } from './quarantine-registry.js';
import { AttestationLedger } from '../attestation/attestation-ledger.js';
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
  /** Called only after TrueForge ApprovalGate returns { approved: true }. */
  public async apply(proposal: FixProposal, finding: VulnerabilityFinding): Promise<FixResult> {
    if (!proposal.autoFixable) {
      return { applied: false, error: 'Finding is not eligible for automated quarantine' };
    }

    try {
      logger.info(`Executing approved remediation for ${finding.id}`);
      
      // 1. Add to the hard quarantine list
      await registry.quarantine(finding.toolName, finding.serverName, finding.title, finding.id);
      
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