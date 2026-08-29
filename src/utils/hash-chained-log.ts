import { createHash } from 'node:crypto';
import { readFile, mkdir, appendFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createLogger } from './logger.js';

const logger = createLogger('hash-chained-log');

/**
 * Generic append-only, hash-chained JSONL log: each record's "previous
 * hash" field (whatever it's actually called on T — see `getPreviousHash`
 * below) is the SHA-256 of the full JSON of the record before it (or of
 * the literal string "genesis" for the first record). Tampering with,
 * deleting, or reordering any past record breaks every subsequent link,
 * so the whole file — not just the latest entry — has to be internally
 * consistent for `verifyChainIntegrity()` to pass.
 *
 * This pattern was originally built once, directly inside
 * AttestationLedger, for the Ed25519 attestation ledger. It's extracted
 * here so any other tamper-evident append-only trail in this codebase
 * (currently: QuarantineRegistry) can reuse the exact same primitive
 * instead of re-deriving hash-chaining logic from scratch — see the
 * "extend the same hash-chain pattern... you already have the primitive
 * built" review note that prompted this extraction.
 *
 * Deliberately not tied to one specific field name for "previous hash" —
 * AttestationRecord calls it `previousRecordHash`, QuarantineRecord calls
 * it `previousHash`. The caller supplies `getPreviousHash` so both can
 * share this class without renaming an already-persisted, tested field.
 */
export class HashChainedLog<T> {
  constructor(private readonly logPath: string, private readonly getPreviousHash: (record: T) => string) {}

  private async ensureDir(): Promise<void> {
    await mkdir(dirname(this.logPath), { recursive: true });
  }

  public async readAll(): Promise<T[]> {
    let raw: string;
    try {
      raw = await readFile(this.logPath, 'utf-8');
    } catch (err: any) {
      const isFileNotFound = err?.code === 'ENOENT' || (err instanceof Error && /ENOENT/.test(err.message));
      if (isFileNotFound) return []; // genuinely doesn't exist yet — real empty state
      logger.error(`Failed to read hash-chained log at ${this.logPath} — refusing to treat as empty`, err);
      throw new Error(`Log at ${this.logPath} is unreadable: ${err.message}. Refusing to proceed with an unverifiable trail.`);
    }
    try {
      return raw
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line));
    } catch (err) {
      logger.error(`Log at ${this.logPath} contains invalid JSON — refusing to treat as empty`, err);
      throw new Error(`Log at ${this.logPath} is corrupted. Fix or restore it before proceeding.`);
    }
  }

  public async latestChainHash(): Promise<string> {
    const records = await this.readAll();
    if (records.length === 0) {
      return createHash('sha256').update('genesis').digest('hex');
    }
    return createHash('sha256').update(JSON.stringify(records[records.length - 1])).digest('hex');
  }

  /**
   * Appends via a single `appendFile` syscall, so each individual write is
   * atomic (POSIX guarantees O_APPEND writes below PIPE_BUF don't
   * interleave). This does NOT make read-then-decide-then-append
   * sequences atomic across concurrent processes — two processes can
   * still both read the same `latestChainHash()` and then both append,
   * producing two records that both claim the same previous-hash value.
   * That race is out of scope for this project's single-process CLI usage;
   * `verifyChainIntegrity()` below will detect the resulting fork if it
   * ever happens, even though this class doesn't prevent it.
   */
  public async append(record: T): Promise<void> {
    await this.ensureDir();
    await appendFile(this.logPath, JSON.stringify(record) + '\n', 'utf-8');
  }

  /**
   * Walks the whole file and confirms every record's previous-hash field
   * matches the hash of the record immediately before it (or "genesis"
   * for the first). Returns the index of the first broken link, if any.
   */
  public async verifyChainIntegrity(): Promise<{ valid: boolean; brokenAtIndex?: number }> {
    const records = await this.readAll();
    let expectedPreviousHash = createHash('sha256').update('genesis').digest('hex');
    for (let i = 0; i < records.length; i++) {
      if (this.getPreviousHash(records[i]) !== expectedPreviousHash) {
        return { valid: false, brokenAtIndex: i };
      }
      expectedPreviousHash = createHash('sha256').update(JSON.stringify(records[i])).digest('hex');
    }
    return { valid: true };
  }
}
