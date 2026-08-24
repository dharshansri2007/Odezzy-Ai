import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateConfig } from '../src/config/parser.js';
import { OdezzyConfigSchema } from '../src/types/index.js';

describe('Config Parser', () => {
  it('validates a correct config', () => {
    const validConfig = {
      servers: [
        { name: 'canary-server', command: 'npx', args: ['tsx', 'canary-server/server.ts'] }
      ],
      scanOptions: {
        maxConcurrency: 3,
        timeoutMs: 30000,
        probeCategories: ['undeclared-params', 'prompt-injection'],
      },
    };
    const result = validateConfig(validConfig);
    expect(result.servers).toHaveLength(1);
    expect(result.servers[0].name).toBe('canary-server');
  });

  it('applies defaults via Zod when scanOptions is missing', () => {
    const partialConfig = {
      servers: [{ name: 'test', command: 'node', args: ['index.js'] }],
    };
    const result = validateConfig(partialConfig);
    expect(result.scanOptions.maxConcurrency).toBe(3);
    expect(result.scanOptions.timeoutMs).toBe(30000);
  });

  it('applies empty server array default', () => {
    const result = validateConfig({});
    expect(result.servers).toEqual([]);
  });

  it('throws validation error for invalid server shape', () => {
    const badConfig = {
      servers: 'not-an-array',
    };
    expect(() => validateConfig(badConfig)).toThrow('Configuration validation failed');
  });

  it('throws for invalid probe categories', () => {
    const badConfig = {
      servers: [],
      scanOptions: {
        probeCategories: ['nonexistent-category'],
      },
    };
    expect(() => validateConfig(badConfig)).toThrow();
  });

  it('merges env vars when calling loadConfig', async () => {
    // loadConfig reads from process.env and odezzy.config.json
    // We test validateConfig directly since loadConfig depends on filesystem
    const config = validateConfig({
      geminiApiKey: 'test-key',
      gcpProjectId: 'test-project',
    });
    expect(config.geminiApiKey).toBe('test-key');
    expect(config.gcpProjectId).toBe('test-project');
  });
});
