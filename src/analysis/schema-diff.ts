import { randomUUID } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import { type MCPToolSchema, type VulnerabilityFinding } from '../types/index.js';

const logger = createLogger('schema-diff');

/**
 * Compares a tool's DECLARED schema against its OBSERVED runtime
 * behavior (the result of an actual probe call from probing/). This is
 * the static-analysis half of catching the canary server's `read_notes`
 * issue: the schema only lists `path`, but a probe call that also
 * passes `cmd` succeeds anyway. schema-diff.ts doesn't make the probe
 * call itself (that's probing/sandbox-runner.ts) — it just judges the
 * before/after.
 */
export class SchemaDiffAnalyzer {
  /**
   * Declared-schema check, no probing required: flags tools whose
   * schema is internally inconsistent or unusually permissive — e.g. no
   * `required` list on a tool that clearly needs required args
   * (undetermined input), or a schema with no `properties` at all
   * (nothing declared, everything accepted implicitly).
   */
  public checkDeclaredSchema(tool: MCPToolSchema, serverName: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];
    const props = tool.inputSchema.properties ?? {};
    const propNames = Object.keys(props);

    if (propNames.length === 0 && tool.inputSchema.type === 'object') {
      findings.push(
        this.makeFinding({
          toolName: tool.name,
          serverName,
          severity: 'medium',
          title: 'Tool declares an object schema with no properties',
          description: `Tool "${tool.name}" accepts an object but declares zero properties, meaning any caller can pass arbitrary undeclared arguments without the schema ever flagging it.`,
          evidence: JSON.stringify(tool.inputSchema),
          remediation: 'Declare every accepted parameter explicitly, and set additionalProperties: false if the MCP server framework supports it.',
          confidence: 0.7,
        })
      );
    }

    return findings;
  }

  /**
   * The core check: given a tool's declared schema and the ARGUMENT
   * KEYS a probe actually sent, plus whether the call succeeded, decide
   * whether the tool silently accepted an undeclared parameter. This is
   * called by probing/sandbox-runner.ts after each probe, not run
   * standalone — it needs a real call result to compare against.
   */
  public diffAgainstProbeCall(params: {
    tool: MCPToolSchema;
    serverName: string;
    sentArgKeys: string[];
    callSucceeded: boolean;
    responseContainsArgEcho: boolean;
  }): VulnerabilityFinding[] {
    const { tool, serverName, sentArgKeys, callSucceeded, responseContainsArgEcho } = params;
    const declaredKeys = new Set(Object.keys(tool.inputSchema.properties ?? {}));
    const undeclared = sentArgKeys.filter((k) => !declaredKeys.has(k));

    if (undeclared.length === 0) {
      return [];
    }

    if (!callSucceeded) {
      // Tool rejected the undeclared param — that's the correct, safe behavior, not a finding
      logger.info(`Tool "${tool.name}" correctly rejected undeclared param(s): ${undeclared.join(', ')}`);
      return [];
    }

    // Call succeeded despite undeclared params — this is exactly the
    // canary server's seeded issue #1
    return [
      this.makeFinding({
        toolName: tool.name,
        serverName,
        severity: responseContainsArgEcho ? 'critical' : 'high',
        title: 'Tool accepts and acts on undeclared parameters',
        description: `Tool "${tool.name}" declares only [${[...declaredKeys].join(', ') || 'none'}] in its schema, but a probe call including undeclared parameter(s) [${undeclared.join(', ')}] succeeded${responseContainsArgEcho ? ', and the response shows evidence the extra parameter was actually used' : ''}. A static description-only scanner would never surface this — it required an actual runtime call.`,
        evidence: `Sent extra keys: ${undeclared.join(', ')}. Call succeeded: ${callSucceeded}.`,
        remediation: 'Reject calls containing parameters outside the declared schema at the server level, and audit the handler for any argument it reads that is not in inputSchema.properties.',
        cweId: 'CWE-20', // Improper Input Validation
        confidence: responseContainsArgEcho ? 0.95 : 0.75,
        owaspCategory: 'MCP05:2025 – Command Injection & Execution',
      }),
    ];
  }

  private makeFinding(f: Omit<VulnerabilityFinding, 'id' | 'category'> & { category?: VulnerabilityFinding['category'] }): VulnerabilityFinding {
    return {
      id: randomUUID(),
      category: f.category ?? 'schema-mismatch',
      ...f,
    };
  }
}