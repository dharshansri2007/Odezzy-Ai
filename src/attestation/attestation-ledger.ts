import { generateKeyPairSync, sign, verify, createHash, type KeyObject } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from '../utils/logger.js';
import { HashChainedLog } from '../utils/hash-chained-log.js';
import type { MCPToolSchema, VulnerabilityFinding, AttestationRecord } from '../types/index.js';

const logger = createLogger('attestation-ledger');
const LEDGER_DIR = process.env.ATTESTATION_LEDGER_DIR ?? '.odezzy/attestation';
const KEYS_PATH = join(LEDGER_DIR, 'keys.json');
const LOG_PATH = join(LEDGER_DIR, 'ledger.jsonl');

interface StoredKeys {
  publicKeyPem: string;
  privateKeyPem: string;
}

/**
 * Self-signed Ed25519 attestation ledger. Issues cryptographic attestations
 * for tools that scan clean across all analysis passes, and automatically
 * revokes them when drift is detected.
 *
 * This is deliberately self-signed and locally verifiable — not anchored
 * to an external CA or Sigstore/OIDC. The research this follows treats
 * external anchoring as a separate concern; this proves the concept.
 *
 * The append-only hash-chaining itself (readAll/latestChainHash/append)
 * is delegated to the shared HashChainedLog primitive in
 * utils/hash-chained-log.ts — this class only adds the Ed25519
 * signing/verification layer on top.
 */
export class AttestationLedger {
  private keysCache: StoredKeys | null = null;
  private readonly log = new HashChainedLog<AttestationRecord>(LOG_PATH, (r) => r.previousRecordHash);

  private async ensureDir(): Promise<void> {
    await mkdir(LEDGER_DIR, { recursive: true });
  }

  private async getOrCreateKeys(): Promise<StoredKeys> {
    if (this.keysCache) return this.keysCache;

    try {
      const raw = await readFile(KEYS_PATH, 'utf-8');
      this.keysCache = JSON.parse(raw);
      return this.keysCache!;
    } catch {
      await this.ensureDir();
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const keys: StoredKeys = {
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      };
      await writeFile(KEYS_PATH, JSON.stringify(keys, null, 2), 'utf-8');
      logger.info('Generated new Ed25519 attestation keypair — this is the ledger\'s root of trust for this project.');
      this.keysCache = keys;
      return keys;
    }
  }

  private canonicalToolDefinition(tool: MCPToolSchema): string {
    return JSON.stringify({
      name: tool.name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {},
    });
  }

  public async getLatest(toolName: string, serverName: string): Promise<AttestationRecord | null> {
    const records = await this.log.readAll();
    const matches = records.filter((r) => r.toolName === toolName && r.serverName === serverName);
    return matches.length > 0 ? matches[matches.length - 1] : null;
  }

  /**
   * Issues a signed attestation for a tool that scanned clean.
   * Refuses (returns null) if there are any open findings.
   */
  public async attest(
    tool: MCPToolSchema,
    serverName: string,
    findingsForThisTool: VulnerabilityFinding[]
  ): Promise<AttestationRecord | null> {
    if (findingsForThisTool.length > 0) {
      logger.info(`Not attesting "${tool.name}" on "${serverName}" — ${findingsForThisTool.length} open finding(s).`);
      return null;
    }

    const { privateKeyPem } = await this.getOrCreateKeys();
    const definitionHash = createHash('sha256').update(this.canonicalToolDefinition(tool)).digest('hex');
    const timestamp = new Date().toISOString();
    const previousRecordHash = await this.log.latestChainHash();

    const payload = `${tool.name}|${serverName}|${definitionHash}|${timestamp}|${previousRecordHash}`;
    const signature = sign(null, Buffer.from(payload), {
      key: privateKeyPem,
      format: 'pem',
    }).toString('base64');

    const record: AttestationRecord = {
      toolName: tool.name,
      serverName,
      definitionHash,
      timestamp,
      scanFindingsCount: 0,
      signature,
      previousRecordHash,
      status: 'attested',
    };

    await this.log.append(record);
    logger.info(`Attested "${tool.name}" on "${serverName}" — signature ${signature.slice(0, 16)}...`);
    return record;
  }

  /**
   * Revokes the most recent attestation for a tool. Called automatically
   * from drift-detector.ts when drift is detected.
   */
  public async revoke(toolName: string, serverName: string, reason: string): Promise<AttestationRecord | null> {
    const latest = await this.getLatest(toolName, serverName);
    if (!latest || latest.status === 'revoked') {
      return null;
    }

    const revokedRecord: AttestationRecord = {
      ...latest,
      status: 'revoked',
      revokedAt: new Date().toISOString(),
      revokedReason: reason,
    };

    await this.log.append(revokedRecord);
    logger.warn(`Revoked attestation for "${toolName}" on "${serverName}": ${reason}`);
    return revokedRecord;
  }

  /**
   * Independently verifies a record's signature against the stored public key.
   */
  public async verify(record: AttestationRecord): Promise<boolean> {
    const { publicKeyPem } = await this.getOrCreateKeys();
    const payload = `${record.toolName}|${record.serverName}|${record.definitionHash}|${record.timestamp}|${record.previousRecordHash}`;
    try {
      return verify(
        null,
        Buffer.from(payload),
        { key: publicKeyPem, format: 'pem' },
        Buffer.from(record.signature, 'base64')
      );
    } catch (err) {
      logger.error('Signature verification threw an error — treating as invalid', err);
      return false;
    }
  }

  /** Returns the full ledger for the governance report. */
  public async getFullLedger(): Promise<AttestationRecord[]> {
    return this.log.readAll();
  }

  /** Exposes the public key PEM for independent verification. */
  public async getPublicKey(): Promise<string> {
    const { publicKeyPem } = await this.getOrCreateKeys();
    return publicKeyPem;
  }
}