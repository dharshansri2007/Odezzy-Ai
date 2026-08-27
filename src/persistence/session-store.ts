import fs from 'node:fs/promises';
import path from 'node:path';
import { createLogger } from '../utils/logger.js';
import type { ScanReport, DiscoveryResult, VulnerabilityFinding, OdezzyConfig } from '../types/index.js';

const logger = createLogger('session-store');

export interface ScanSession {
  id: string;
  startedAt: string;
  completedAt?: string;
  configSnapshot: any;
  discoveryResult?: DiscoveryResult;
  findings: VulnerabilityFinding[];
  report?: ScanReport;
}

// 1. Added redaction helper to strip sensitive fields before disk write
export function redactConfig(config: OdezzyConfig): OdezzyConfig {
  if (!config) return config;
  return {
    ...config,
    geminiApiKey: config.geminiApiKey ? '[REDACTED]' : undefined,
    trueforgeApiKey: config.trueforgeApiKey ? '[REDACTED]' : undefined,
    servers: config.servers?.map((s) => ({
      ...s,
      env: s.env
        ? Object.fromEntries(Object.keys(s.env).map((k) => [k, '[REDACTED]']))
        : s.env,
    })),
  };
}

export class SessionStore {
  private readonly sessionsDir: string;

  constructor(sessionsDir: string = '.odezzy/sessions') {
    this.sessionsDir = path.resolve(process.cwd(), sessionsDir);
  }

  public async save(session: ScanSession): Promise<void> {
    await fs.mkdir(this.sessionsDir, { recursive: true });
    const filePath = path.join(this.sessionsDir, `${session.id}.json`);
    
    // 2. Sanitized session config snapshot before serialization
    const sanitized = { 
      ...session, 
      configSnapshot: redactConfig(session.configSnapshot) 
    };

    await fs.writeFile(filePath, JSON.stringify(sanitized, null, 2), 'utf-8');
    logger.info(`Session saved to ${filePath}`);
  }

  public async load(sessionId: string): Promise<ScanSession | null> {
    const filePath = path.join(this.sessionsDir, `${sessionId}.json`);
    try {
      const data = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(data) as ScanSession;
    } catch (err) {
      logger.error(`Failed to load session ${sessionId}: ${err}`);
      return null;
    }
  }

  public async list(): Promise<string[]> {
    try {
      await fs.mkdir(this.sessionsDir, { recursive: true });
      const files = await fs.readdir(this.sessionsDir);
      return files.filter(f => f.endsWith('.json')).map(f => f.replace('.json', ''));
    } catch (err) {
      logger.error(`Failed to list sessions: ${err}`);
      return [];
    }
  }
}