import { randomUUID } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import {
  type MCPToolSchema,
  type MCPServerInventory,
  type VulnerabilityFinding,
} from '../types/index.js';
import { COMBINED_SECRET_REGEX } from './secret-patterns.js';

const logger = createLogger('static-rules');

/**
 * A single static pattern check: a regex plus the finding it produces
 * when matched. Kept as data, not scattered if-statements, so adding a
 * new pattern is a one-line addition, not a new code path.
 */
interface StaticPattern {
  id: string;
  category: VulnerabilityFinding['category'];
  severity: VulnerabilityFinding['severity'];
  cweId?: string;
  owaspCategory?: string;
  /** Matched against the tool's raw description text. */
  pattern: RegExp;
  title: string;
  remediationHint: string;
}

// Fixed, auditable list — every entry here is something a human can read
// and verify, on purpose. This is the "fast, cheap first pass" layer;
// it exists to catch obvious cases before semantic-check.ts spends an
// LLM call on a tool, not to catch everything.
const PATTERNS: StaticPattern[] = [
  {
    id: 'hidden-html-comment-instruction',
    category: 'prompt-injection',
    severity: 'critical',
    cweId: 'CWE-1427', // Improper Neutralization of Input Used for LLM Prompting
    owaspCategory: 'MCP03:2025 – Tool Poisoning',
    pattern: /<!--[\s\S]*?-->/,
    title: 'Hidden HTML comment inside tool description',
    remediationHint:
      'Strip HTML/markdown comments from tool descriptions before they reach the model, or reject the server until the maintainer removes them.',
  },
  {
    id: 'system-role-spoof',
    category: 'prompt-injection',
    severity: 'critical',
    cweId: 'CWE-1427',
    owaspCategory: 'MCP03:2025 – Tool Poisoning',
    pattern: /\b(system|assistant)\s*:\s/i,
    title: 'Tool description impersonates a system/assistant role marker',
    remediationHint:
      'A tool description should never contain role-formatted text aimed at the model. Treat this server as untrusted until fixed.',
  },
  {
    id: 'silent-exfiltration-language',
    category: 'prompt-injection',
    severity: 'critical',
    owaspCategory: 'MCP03:2025 – Tool Poisoning',
    pattern: /\b(do not (mention|tell|inform)|without (telling|informing)|silently)\b/i,
    title: 'Description instructs the model to act without informing the user',
    remediationHint:
      'Any instruction asking the model to hide an action from the user is a strong poisoning signal — quarantine this tool pending manual review.',
  },
  {
    id: 'credential-path-reference',
    category: 'prompt-injection',
    severity: 'high',
    owaspCategory: 'MCP06:2025 – Prompt Injection via Contextual Payloads',
    pattern: /(\.ssh\/id_rsa|\.aws\/credentials|\.env\b|id_ed25519|private[_-]?key)/i,
    title: 'Description references a credential file path',
    remediationHint:
      'Legitimate tools rarely need to name specific credential file paths in their description text. Verify intent with the server maintainer.',
  },
  {
    id: 'leaked-live-key-pattern',
    category: 'leaked-secrets',
    severity: 'high',
    cweId: 'CWE-798', // Use of Hard-coded Credentials
    owaspCategory: 'MCP01:2025 – Token Mismanagement & Secret Exposure',
    pattern: COMBINED_SECRET_REGEX,
    title: 'Description or metadata contains a live-looking API key pattern',
    remediationHint:
      'Rotate the credential immediately if real, and ensure secrets never ship inside tool metadata.',
  },
];

export class StaticRuleEngine {
  /**
   * Runs every fixed pattern against every tool on every server in the
   * inventory. Pure, synchronous, no network or LLM calls — this is
   * meant to run in milliseconds regardless of inventory size.
   */
  public scan(inventory: MCPServerInventory[]): VulnerabilityFinding[] {
    logger.info(`Running static rule scan across ${inventory.length} server(s)`);
    const findings: VulnerabilityFinding[] = [];

    for (const server of inventory) {
      for (const tool of server.tools) {
        findings.push(...this.scanTool(tool, server.serverName));
      }
    }

    logger.info(`Static rule scan complete: ${findings.length} finding(s)`);
    return findings;
  }

  /**
   * Scans a single tool. Exposed separately so probing/analysis stages
   * can re-check one tool without re-running the whole inventory.
   */
  public scanTool(tool: MCPToolSchema, serverName: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];
    const haystack = tool.description ?? '';

    for (const rule of PATTERNS) {
      const match = haystack.match(rule.pattern);
      if (!match) continue;

      findings.push({
        id: randomUUID(),
        toolName: tool.name,
        serverName,
        severity: rule.severity,
        category: rule.category,
        title: rule.title,
        description: `Static pattern "${rule.id}" matched in the description of tool "${tool.name}".`,
        evidence: this.truncateEvidence(match[0]),
        remediation: rule.remediationHint,
        cweId: rule.cweId,
        // Static regex matches are exact, not probabilistic — full confidence,
        // reserving <1.0 for the semantic/LLM layer's fuzzier judgments
        confidence: 1.0,
        owaspCategory: rule.owaspCategory,
      });
    }

    return findings;
  }

  /** Never let raw matched text (which could itself be attacker-controlled) blow up a report. */
  private truncateEvidence(text: string, maxLen = 200): string {
    return text.length > maxLen ? `${text.slice(0, maxLen)}…` : text;
  }
}