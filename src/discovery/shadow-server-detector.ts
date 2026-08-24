import { randomUUID } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import type { VulnerabilityFinding, OdezzyConfig, ErroredTool } from '../types/index.js';

const logger = createLogger('shadow-server-detector');

export interface ShadowServerResult {
  findings: VulnerabilityFinding[];
  erroredTools: ErroredTool[];
}

/**
 * Cross-references TrueForge's authorized MCP server list against Odezzy's
 * local scan configuration. Detects two types of shadow servers:
 *
 * 1. **Unmonitored servers**: Authorized in TrueForge but absent from
 *    Odezzy's config — these are live, trusted by the platform, but
 *    invisible to security scanning.
 *
 * 2. **Unregistered servers**: In Odezzy's config but not authorized in
 *    TrueForge — these are being scanned but may not be governed by the
 *    platform's authorization controls.
 *
 * Maps to OWASP MCP09:2025 — Shadow MCP Servers.
 *
 * Requires a TrueForge client instance. When TrueForge is unavailable,
 * fails visible (returns erroredTools) rather than silently skipping.
 */
export class ShadowServerDetector {
  /**
   * Runs the cross-reference check.
   * @param trueforgeClient Any object with an `mcpServers.list()` method (the TrueForge SDK client).
   * @param config Odezzy's local configuration with the list of servers to scan.
   */
  public async detect(
    trueforgeClient: { mcpServers: { list: () => Promise<{ data: { name: string }[] }> } } | null,
    config: OdezzyConfig
  ): Promise<ShadowServerResult> {
    if (!trueforgeClient) {
      logger.info('Shadow server detection skipped — no TrueForge client configured');
      return { findings: [], erroredTools: [] };
    }

    const findings: VulnerabilityFinding[] = [];
    const erroredTools: ErroredTool[] = [];

    try {
      const { data: registeredServers } = await trueforgeClient.mcpServers.list();
      const registeredNames = new Set(registeredServers.map((s: { name: string }) => s.name));
      const localNames = new Set(config.servers.map((s) => s.name));

      // 1. Servers in TrueForge but NOT in Odezzy's scan config
      for (const name of registeredNames) {
        if (!localNames.has(name)) {
          findings.push({
            id: randomUUID(),
            toolName: '(server-level)',
            serverName: name,
            severity: 'high',
            category: 'shadow-server',
            title: `Unmonitored MCP server: "${name}" is authorized in TrueForge but absent from scan config`,
            description:
              `TrueForge has authorized an MCP server named "${name}", but Odezzy's scan configuration ` +
              `does not include it. This server is live and trusted by the platform but invisible to ` +
              `security scanning — a shadow server.`,
            evidence: `TrueForge registry contains "${name}"; odezzy.config.json does not.`,
            remediation:
              'Add this server to odezzy.config.json so it is included in future scans, or ' +
              'remove its authorization from TrueForge if it should not be trusted.',
            confidence: 1.0,
            owaspCategory: 'MCP09:2025 \u2013 Shadow MCP Servers',
          });
        }
      }

      // 2. Servers in Odezzy's config but NOT in TrueForge
      for (const name of localNames) {
        if (!registeredNames.has(name)) {
          findings.push({
            id: randomUUID(),
            toolName: '(server-level)',
            serverName: name,
            severity: 'medium',
            category: 'shadow-server',
            title: `Unregistered MCP server: "${name}" is scanned by Odezzy but not authorized in TrueForge`,
            description:
              `Odezzy scans a server named "${name}", but TrueForge's MCP registry has no record of it. ` +
              `This server is not governed by TrueForge's authorization controls.`,
            evidence: `odezzy.config.json contains "${name}"; TrueForge registry does not.`,
            remediation:
              'Authorize this server in TrueForge (Settings \u2192 Connectors) so it is governed ' +
              'by the platform\u2019s access controls, or confirm it is intentionally unregistered.',
            confidence: 0.9,
            owaspCategory: 'MCP09:2025 \u2013 Shadow MCP Servers',
          });
        }
      }

      logger.info(
        `Shadow server detection complete: ${findings.length} finding(s) ` +
        `(${registeredNames.size} in TrueForge, ${localNames.size} in config)`
      );
    } catch (err) {
      logger.error('Shadow server detection failed', err);
      erroredTools.push({
        toolName: '(registry-check)',
        serverName: '(all)',
        stage: 'shadow-detection',
        error: err instanceof Error ? err.message : String(err),
      });
    }

    return { findings, erroredTools };
  }
}
