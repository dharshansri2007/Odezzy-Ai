import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('embedding-baseline-store');
const STORE_DIR = '.odezzy/embeddings';

export interface StoredBaseline {
  toolName: string;
  serverName: string;
  descriptionHash: string;
  embedding: number[];
  scannedAt: string;
}

function keyFor(serverName: string, toolName: string): string {
  return `${serverName}__${toolName}`.replace(/[^a-zA-Z0-9_-]/g, '_');
}

export class EmbeddingBaselineStore {
  private async ensureDir(): Promise<void> {
    await mkdir(STORE_DIR, { recursive: true });
  }

  public async load(serverName: string, toolName: string): Promise<StoredBaseline | null> {
    try {
      const raw = await readFile(join(STORE_DIR, `${keyFor(serverName, toolName)}.json`), 'utf-8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  public async save(baseline: StoredBaseline): Promise<void> {
    await this.ensureDir();
    const filePath = join(STORE_DIR, `${keyFor(baseline.serverName, baseline.toolName)}.json`);
    await writeFile(filePath, JSON.stringify(baseline, null, 2), 'utf-8');
    logger.info(`Saved embedding baseline for ${baseline.serverName}/${baseline.toolName}`);
  }
}
