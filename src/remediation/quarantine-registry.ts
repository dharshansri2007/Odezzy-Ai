import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('quarantine-registry');
const REGISTRY_PATH = '.odezzy/quarantine.json';

interface QuarantineEntry {
  toolName: string;
  serverName: string;
  quarantinedAt: string;
  reason: string;
  findingId: string;
}

export class QuarantineRegistry {
  private async readAll(): Promise<QuarantineEntry[]> {
    let raw: string;
    try {
      raw = await readFile(REGISTRY_PATH, 'utf-8');
    } catch (err: any) {
      const isFileNotFound =
        err.code === 'ENOENT' || (err instanceof Error && /ENOENT/.test(err.message));
      if (isFileNotFound) {
        return []; // file genuinely doesn't exist yet — real empty state, fine
      }
      logger.error('Failed to read quarantine registry — refusing to treat as empty', err);
      throw new Error(`Quarantine registry unreadable: ${err.message}. Refusing to proceed with an unverifiable ban list.`);
    }
    try {
      return JSON.parse(raw);
    } catch (err) {
      logger.error('Quarantine registry contains invalid JSON — refusing to treat as empty', err);
      throw new Error('Quarantine registry is corrupted. Fix or restore .odezzy/quarantine.json before scanning.');
    }
  }

  /** Called only after TrueForge confirms a human approved this specific action. */
  public async quarantine(toolName: string, serverName: string, reason: string, findingId: string): Promise<void> {
    const entries = await this.readAll();
    if (entries.some(e => e.toolName === toolName && e.serverName === serverName)) return; 
    
    entries.push({ toolName, serverName, quarantinedAt: new Date().toISOString(), reason, findingId });
    await mkdir('.odezzy', { recursive: true });
    await writeFile(REGISTRY_PATH, JSON.stringify(entries, null, 2), 'utf-8');
    logger.warn(`Quarantined "${toolName}" on "${serverName}": ${reason}`);
  }

  /** Called by discovery/analysis on every future scan to enforce the ban. */
  public async isQuarantined(toolName: string, serverName: string): Promise<boolean> {
    const entries = await this.readAll();
    return entries.some(e => e.toolName === toolName && e.serverName === serverName);
  }
}