import { createLogger } from '../utils/logger.js';
import { HashChainedLog } from '../utils/hash-chained-log.js';
import type { HumanApprovalToken } from './human-approval-token.js';
import type { QuarantineRecord } from '../types/index.js';

const logger = createLogger('quarantine-registry');
const REGISTRY_PATH = '.odezzy/quarantine.jsonl';

/**
 * Append-only, hash-chained quarantine log (see utils/hash-chained-log.ts —
 * the same primitive AttestationLedger uses for its Ed25519 ledger).
 *
 * This replaces the previous plain-JSON-array implementation for two
 * reasons raised in review:
 *  1. "This tool is quarantined" was provable, but "this specific human,
 *     via this specific approval source, at this time, authorized it"
 *     wasn't independently tamper-evident — a plain array entry could be
 *     edited or reordered with no trace. Hash-chaining closes that gap.
 *  2. The old read-modify-write (readAll -> push -> writeFile) was not
 *     atomic: two concurrent writers could race and one could silently
 *     clobber the other's entry. `HashChainedLog.append()` uses a single
 *     `appendFile` call per entry instead of a read-modify-write cycle,
 *     which removes the clobbering failure mode for the common case.
 *
 * Still NOT safe under true concurrent multi-process quarantine calls:
 * two processes could both read the same `latestChainHash()` and then
 * both append, producing a "fork" (two records both claiming the same
 * previous hash). `verifyChainIntegrity()` will detect that fork after
 * the fact, but nothing here prevents it up front — for v3, concurrency
 * is explicitly out of scope (this is a single-process CLI plus one
 * remediation MCP server invoked by TrueForge, never both at once in
 * practice). If that assumption ever changes, add a file lock or move to
 * a real datastore before trusting this under concurrent writers.
 */
export class QuarantineRegistry {
  private readonly log = new HashChainedLog<QuarantineRecord>(REGISTRY_PATH, (r) => r.previousHash);

  /**
   * Requires a genuine HumanApprovalToken, not a bare string reason — the
   * token's `source` and `grantedAt` are what make "who authorized this
   * and how" independently checkable later, instead of trusting whatever
   * string a caller happened to pass in.
   */
  public async quarantine(
    toolName: string,
    serverName: string,
    reason: string,
    findingId: string,
    token: HumanApprovalToken
  ): Promise<void> {
    if (token.findingId !== findingId) {
      throw new Error(
        `Refusing to quarantine: approval token was granted for finding ${token.findingId}, not ${findingId}.`
      );
    }

    if (await this.isQuarantined(toolName, serverName)) return;

    const previousHash = await this.log.latestChainHash();
    const record: QuarantineRecord = {
      toolName,
      serverName,
      findingId,
      reason,
      action: 'quarantine',
      tokenSource: token.source,
      grantedAt: token.grantedAt,
      recordedAt: new Date().toISOString(),
      previousHash,
    };

    await this.log.append(record);
    logger.warn(`Quarantined "${toolName}" on "${serverName}" (approval source: ${token.source}): ${reason}`);
  }

  /** Called by discovery/analysis on every future scan to enforce the ban. */
  public async isQuarantined(toolName: string, serverName: string): Promise<boolean> {
    const records = await this.log.readAll();
    return records.some((r) => r.toolName === toolName && r.serverName === serverName);
  }

  /** Returns the full quarantine trail for the governance report / independent audit. */
  public async getFullLog(): Promise<QuarantineRecord[]> {
    return this.log.readAll();
  }

  /** Independently verifies the hash chain hasn't been tampered with. */
  public async verifyChainIntegrity(): Promise<{ valid: boolean; brokenAtIndex?: number }> {
    return this.log.verifyChainIntegrity();
  }
}
