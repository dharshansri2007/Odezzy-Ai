import { createLogger } from '../utils/logger.js';
import { SandboxRunner } from '../probing/sandbox-runner.js';
import { PROBE_TEMPLATES } from '../probing/probe-templates.js';
import type { MCPServerInventory, VulnerabilityFinding } from '../types/index.js';
import type { ServerConfig } from '../discovery/mcp-connector.js';

const logger = createLogger('subagent');

/**
 * Runs all fixed probe templates against every tool on one server.
 * Called once per server, in parallel, from root-agent.ts.
 *
 * INTENTIONALLY DOES NOT GO THROUGH TRUEFORGE (verified, not guessed —
 * see agent/trueforge-client.ts's module doc): TrueForge's sandbox only
 * executes as a side effect of an agent's own LLM-driven tool calls.
 * Probing needs to send exact, adversarial argument payloads computed
 * ahead of time by PROBE_TEMPLATES — that's not something an LLM tool
 * call gives you control over. So probing keeps using MCPConnector
 * directly, same as it always has; only the remediation approval step
 * (approval-gate.ts) is TrueForge-native.
 *
 * This is also intentionally a plain async function, not a TrueForge
 * subagent — nested TrueForge subagent delegation isn't a concept in
 * the confirmed SDK surface, and there's no need for it here since this
 * fan-out never touches TrueForge in the first place.
 */
export async function runProbesForServers(
  servers: MCPServerInventory[],
  serverConfigs: Map<string, ServerConfig>
): Promise<VulnerabilityFinding[]> {
  logger.info(`Fanning out probing across ${servers.length} server(s)`);

  const results = await Promise.all(
    servers.map((server) => runProbesForOneServer(server, serverConfigs.get(server.serverName)))
  );

  return results.flat();
}

async function runProbesForOneServer(
  server: MCPServerInventory,
  serverConfig: ServerConfig | undefined
): Promise<VulnerabilityFinding[]> {
  if (!serverConfig) {
    logger.warn(`No original ServerConfig found for "${server.serverName}" — skipping probing for this server`);
    return [];
  }

  const runner = new SandboxRunner();
  const findings: VulnerabilityFinding[] = [];

  for (const tool of server.tools) {
    for (const template of PROBE_TEMPLATES) {
      try {
        const templateFindings = await runner.runProbe(template, tool, serverConfig);
        findings.push(...templateFindings);
      } catch (err) {
        logger.error(`Probe ${template.id} failed for tool ${tool.name} on ${server.serverName}`, err);
      }
    }
  }

  return findings;
}
