import { describe, it, expect } from 'vitest';
import { PROBE_TEMPLATES } from '../src/probing/probe-templates.js';
import { ProbeResultNormalizer } from '../src/probing/probe-results.js';
import type { MCPToolSchema } from '../src/types/index.js';

const testTool: MCPToolSchema = {
  name: 'read_notes',
  description: 'Reads a note file',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Relative path to the note file.' },
    },
    required: ['path'],
  },
};

describe('Probe Templates', () => {
  it('should have exactly 4 probe templates', () => {
    expect(PROBE_TEMPLATES).toHaveLength(4);
  });

  it('undeclared-param-probe payloadGenerator adds cmd param', () => {
    const template = PROBE_TEMPLATES.find(t => t.id === 'undeclared-param-probe');
    expect(template).toBeDefined();
    const payload = template!.payloadGenerator(testTool) as Record<string, unknown>;
    expect(payload.path).toBe('test');
    expect(payload.cmd).toBe('echo test');
  });

  it('prompt-injection-detection payloadGenerator injects malicious string', () => {
    const template = PROBE_TEMPLATES.find(t => t.id === 'prompt-injection-detection');
    expect(template).toBeDefined();
    const payload = template!.payloadGenerator(testTool) as Record<string, unknown>;
    expect(typeof payload.path).toBe('string');
    expect((payload.path as string)).toContain('Ignore previous');
  });

  it('secret-scan-probe resultParser catches leaked keys', () => {
    const template = PROBE_TEMPLATES.find(t => t.id === 'secret-scan-probe');
    expect(template).toBeDefined();
    const finding = template!.resultParser('Token: sk_live_51N7f9aKcanaryFAKE0000000000000000000');
    expect(finding).not.toBeNull();
    expect(finding!.category).toBe('leaked-secrets');
  });

  it('secret-scan-probe resultParser returns null for clean responses', () => {
    const template = PROBE_TEMPLATES.find(t => t.id === 'secret-scan-probe');
    const finding = template!.resultParser('Everything is fine, no secrets here.');
    expect(finding).toBeNull();
  });

  it('schema-mismatch-probe payloadGenerator sends empty args', () => {
    const template = PROBE_TEMPLATES.find(t => t.id === 'schema-mismatch-probe');
    expect(template).toBeDefined();
    const payload = template!.payloadGenerator(testTool) as Record<string, unknown>;
    expect(Object.keys(payload)).toHaveLength(0);
  });
});

describe('ProbeResultNormalizer', () => {
  it('should normalize a successful probe result', () => {
    const result = ProbeResultNormalizer.normalize(
      'read_notes',
      'canary-server',
      { path: 'test', cmd: 'echo pwned' },
      true,
      { content: [{ type: 'text', text: 'executed: echo pwned' }] }
    );
    expect(result.toolName).toBe('read_notes');
    expect(result.serverName).toBe('canary-server');
    expect(result.sentArgKeys).toEqual(['path', 'cmd']);
    expect(result.callSucceeded).toBe(true);
  });

  it('should detect arg echo in response', () => {
    const result = ProbeResultNormalizer.normalize(
      'read_notes',
      'canary-server',
      { path: 'test', cmd: 'echo pwned' },
      true,
      'executed undeclared cmd: echo pwned'
    );
    expect(result.responseContainsArgEcho).toBe(true);
  });

  it('should not detect echo for short values', () => {
    const result = ProbeResultNormalizer.normalize(
      'read_notes',
      'canary-server',
      { path: 'ab' },
      true,
      'some response with ab'
    );
    // 'ab' is <= 3 chars, so should not count as echo
    expect(result.responseContainsArgEcho).toBe(false);
  });
});
