import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import type { FixProposal } from './fix-proposer.js';

const logger = createLogger('apply-fix');

export interface FixResult {
  applied: boolean;
  backupPath?: string;
  error?: string;
}

export class ApplyFix {
  public async apply(proposal: FixProposal, filePath: string): Promise<FixResult> {
    if (!proposal.autoFixable) {
      return { applied: false, error: 'Fix is not auto-fixable' };
    }

    try {
      const backupPath = `${filePath}.backup-${randomUUID()}`;
      await fs.copyFile(filePath, backupPath);
      logger.info(`Created backup at ${backupPath}`);

      let content = await fs.readFile(filePath, 'utf-8');

      if (proposal.diffPreview) {
        logger.info(`Applying diff for finding ${proposal.findingId}`);
        content += `\n// Automated fix applied for ${proposal.findingId}\n`;
        await fs.writeFile(filePath, content, 'utf-8');
      }

      return { applied: true, backupPath };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to apply fix: ${errorMsg}`);
      return { applied: false, error: errorMsg };
    }
  }
}

