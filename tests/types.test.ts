import { describe, it, expect } from 'vitest';
import {
  MCPToolSchemaSchema,
  MCPServerInventorySchema,
  DiscoveryResultSchema,
  VulnerabilityFindingSchema,
  ScanReportSchema,
  OdezzyConfigSchema,
} from '../src/types/index.js';

describe('Type Schemas', () => {

  describe('MCPToolSchemaSchema', () => {
    it('parses valid tool', () => {
      const validTool = {
        name: 'test_tool',
        description: 'A test tool',
        inputSchema: { type: 'object', properties: {} },
      };
      expect(() => MCPToolSchemaSchema.parse(validTool)).not.toThrow();
    });

    it('parses tool without description', () => {
      const tool = {
        name: 'test_tool',
        inputSchema: { type: 'object' },
      };
      expect(() => MCPToolSchemaSchema.parse(tool)).not.toThrow();
    });

    it('throws on missing name', () => {
      expect(() => MCPToolSchemaSchema.parse({ inputSchema: { type: 'object' } })).toThrow();
    });

    it('throws on missing inputSchema', () => {
      expect(() => MCPToolSchemaSchema.parse({ name: 'test_tool' })).toThrow();
    });
  });

  describe('MCPServerInventorySchema', () => {
    it('parses valid inventory', () => {
      const inventory = {
        serverName: 'test_server',
        serverVersion: '1.0.0',
        transport: 'stdio',
        tools: [],
        scannedAt: new Date().toISOString(),
        connectionUri: 'npx',
      };
      expect(() => MCPServerInventorySchema.parse(inventory)).not.toThrow();
    });

    it('throws on invalid transport', () => {
      const inventory = {
        serverName: 'test_server',
        serverVersion: '1.0.0',
        transport: 'invalid-transport',
        tools: [],
        scannedAt: new Date().toISOString(),
        connectionUri: 'npx',
      };
      expect(() => MCPServerInventorySchema.parse(inventory)).toThrow();
    });
  });

  describe('DiscoveryResultSchema', () => {
    it('parses valid result', () => {
      const result = {
        servers: [],
        totalTools: 0,
        timestamp: new Date().toISOString(),
      };
      expect(() => DiscoveryResultSchema.parse(result)).not.toThrow();
    });
  });

  describe('VulnerabilityFindingSchema', () => {
    it('parses valid finding with correct enums', () => {
      const finding = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        toolName: 'read_notes',
        serverName: 'canary-server',
        severity: 'high',
        category: 'undeclared-params',
        title: 'Undeclared Parameter Execution',
        description: 'The tool executes an undeclared cmd parameter',
        evidence: 'cmd param executed shell command',
        remediation: 'Remove undeclared parameter handling',
        confidence: 0.95,
      };
      expect(() => VulnerabilityFindingSchema.parse(finding)).not.toThrow();
    });

    it('throws on invalid severity', () => {
      const invalid = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        toolName: 'test',
        serverName: 'test',
        severity: 'mega-critical',
        category: 'undeclared-params',
        title: 'T',
        description: 'D',
        evidence: 'E',
        remediation: 'R',
        confidence: 0.5,
      };
      expect(() => VulnerabilityFindingSchema.parse(invalid)).toThrow();
    });

    it('throws on confidence out of range', () => {
      const invalid = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        toolName: 'test',
        serverName: 'test',
        severity: 'high',
        category: 'undeclared-params',
        title: 'T',
        description: 'D',
        evidence: 'E',
        remediation: 'R',
        confidence: 1.5,
      };
      expect(() => VulnerabilityFindingSchema.parse(invalid)).toThrow();
    });
  });

  describe('ScanReportSchema', () => {
    it('parses valid report', () => {
      const report = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        projectName: 'odezzy-test',
        scanStartedAt: new Date().toISOString(),
        scanCompletedAt: new Date().toISOString(),
        summary: { totalFindings: 0, bySeverity: {}, byCategory: {} },
        findings: [],
        inventories: [],
        metadata: { agentVersion: '0.1.0', scanDurationMs: 1234 },
      };
      expect(() => ScanReportSchema.parse(report)).not.toThrow();
    });
  });

  describe('OdezzyConfigSchema', () => {
    it('parses valid config with defaults', () => {
      const config = {
        servers: [{ name: 'test', command: 'node', args: ['index.js'] }],
      };
      const parsed = OdezzyConfigSchema.parse(config);
      expect(parsed.scanOptions.maxConcurrency).toBe(3);
      expect(parsed.scanOptions.timeoutMs).toBe(30000);
    });

    it('parses empty config with all defaults', () => {
      const parsed = OdezzyConfigSchema.parse({});
      expect(parsed.servers).toEqual([]);
      expect(parsed.scanOptions.maxConcurrency).toBe(3);
    });
  });
});
