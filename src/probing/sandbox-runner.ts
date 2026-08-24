import { randomUUID } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import { 
  ProbeTemplate, 
  MCPToolSchema, 
  VulnerabilityFinding
} from '../types/index.js';
import { ServerConfig, MCPConnector } from '../discovery/mcp-connector.js';
import { ProbeResultNormalizer } from './probe-results.js';
import { SchemaDiffAnalyzer } from '../analysis/schema-diff.js';

const logger = createLogger('sandbox-runner');

export class SandboxRunner {
  private schemaDiff: SchemaDiffAnalyzer;

  constructor() {
    this.schemaDiff = new SchemaDiffAnalyzer();
  }

  /**
   * Executes a probe template against a specific tool.
   * TODO: TrueForge sandboxing should replace direct execution once SDK methods are verified.
   * For now, this runs directly against the MCPConnector per hard constraints.
   */
  public async runProbe(
    template: ProbeTemplate,
    tool: MCPToolSchema,
    serverConfig: ServerConfig
  ): Promise<VulnerabilityFinding[]> {
    logger.info(`Running probe ${template.id} against tool ${tool.name} on ${serverConfig.name}`);
    
    const connector = new MCPConnector(serverConfig);
    const findings: VulnerabilityFinding[] = [];

    try {
      await connector.connect();

      const args = template.payloadGenerator(tool) as Record<string, any>;
      let callSucceeded = false;
      let rawResponse: unknown = null;

      try {
        rawResponse = await connector.callTool(tool.name, args);
        callSucceeded = true;
      } catch (err) {
        callSucceeded = false;
        rawResponse = err instanceof Error ? err.message : String(err);
      }

      const normalizedResult = ProbeResultNormalizer.normalize(
        tool.name,
        serverConfig.name,
        args,
        callSucceeded,
        rawResponse
      );

      // 1. Let the Schema Diff analyzer look at the result if applicable
      if (template.probeType === 'schema-diff' && template.id === 'undeclared-param-probe') {
        const diffFindings = this.schemaDiff.diffAgainstProbeCall({
          tool,
          serverName: serverConfig.name,
          sentArgKeys: normalizedResult.sentArgKeys,
          callSucceeded: normalizedResult.callSucceeded,
          responseContainsArgEcho: normalizedResult.responseContainsArgEcho,
        });
        findings.push(...diffFindings);
      }

      // Handle schema-mismatch-probe specifically here if it succeeds when missing required args
      if (template.id === 'schema-mismatch-probe' && normalizedResult.callSucceeded && (tool.inputSchema.required || []).length > 0) {
        findings.push({
          id: randomUUID(),
          toolName: tool.name,
          serverName: serverConfig.name,
          severity: 'medium',
          category: 'schema-mismatch',
          title: 'Tool accepted request despite missing required parameters',
          description: `The tool declares required parameters but a probe omitting all of them succeeded.`,
          evidence: `Required: ${(tool.inputSchema.required || []).join(',')}, Sent: None. Call succeeded.`,
          remediation: 'Enforce schema validation strictly on the server side.',
          confidence: 0.9,
        });
      }

      // 2. Let the template's resultParser analyze the output
      const templateFinding = template.resultParser(rawResponse);
      if (templateFinding) {
        findings.push({
          ...templateFinding,
          id: randomUUID(),
          toolName: tool.name,
          serverName: serverConfig.name,
        });
      }

    } catch (err) {
      logger.error(`Probe execution failed for ${template.id} on ${tool.name}`, err);
    } finally {
      await connector.disconnect();
    }

    return findings;
  }
}
