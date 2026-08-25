import { randomUUID } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import { createTrueForgeClient, createOdezzyScanSession, narrateScanPhase } from './trueforge-client.js';
import { ShadowServerDetector } from '../discovery/shadow-server-detector.js';
import { InventoryBuilder } from '../discovery/inventory.js';
import { AnalysisOrchestrator } from '../analysis/index.js';
import { RiskCalculator } from '../scoring/risk-formula.js';
import { classifyRisk } from '../scoring/risk-classifier.js';
import { FixProposer } from '../remediation/fix-proposer.js';
import { ApprovalGate } from '../remediation/approval-gate.js';
import { buildGraph } from '../report/graph-builder.js';
import { SessionStore } from '../persistence/session-store.js';
import { runProbesForServers } from './subagent.js';
import type { ServerConfig } from '../discovery/mcp-connector.js';
import type { OdezzyConfig, VulnerabilityFinding, DiscoveryResult } from '../types/index.js';

const logger = createLogger('root-agent');

/**
 * The TrueForge-native entry point for a full Odezzy AI scan. Wraps the
 * existing, already-working pipeline (discovery -> analysis -> probing
 * -> scoring -> remediation -> report) so the remediation-approval step
 * of the run is a real TrueForge agent turn, gated by TrueForge's own
 * tool-call approval mechanism — not a bare Node CLI prompt.
 *
 * ONE-TIME MANUAL SETUP REQUIRED, confirmed not automatable via the SDK
 * (McpServersClient only exposes list/authorize/deleteAuthorization/
 * listTools — there is no "register a new server" call): before
 * remediation approval will actually pause for a human, register an MCP
 * server under TrueForge's Settings → Connectors that exposes an
 * `apply_fix(findingId: string)` tool, and pass its configured name as
 * `remediationMcpServerName` below. Until that connector exists,
 * ApprovalGate fails closed (treats every fix as rejected) rather than
 * silently applying anything — see approval-gate.ts.
 *
 * Discovery, analysis, and probing intentionally do NOT go through
 * TrueForge (verified, not guessed — see trueforge-client.ts and
 * subagent.ts module docs for why); only remediation approval is
 * TrueForge-native.
 */
export class RootAgent {
  private config: OdezzyConfig;
  private remediationMcpServerName?: string;

  constructor(config: OdezzyConfig, opts: { remediationMcpServerName?: string } = {}) {
    this.config = config;
    this.remediationMcpServerName = opts.remediationMcpServerName;
  }

  public async runFullScan(): Promise<{ findings: VulnerabilityFinding[]; sessionId: string; erroredTools: any[] }> {
    const runId = randomUUID();
    logger.info(`Starting TrueForge-backed scan, run ${runId}`);

    // 1. Open a TrueForge session at scan START (Lever 3: session narration)
    const client = createTrueForgeClient(this.config);
    const { sessionId } = await createOdezzyScanSession(client, this.config, {
      remediationMcpServerName: this.remediationMcpServerName,
    });
    let lastTurnId: string | undefined;

    lastTurnId = await narrateScanPhase(
      client, sessionId, 'Scan Started',
      `Run ID: ${runId}. Scanning ${this.config.servers.length} configured server(s).`,
      lastTurnId
    );

    // 2. Discovery
    const inventory: DiscoveryResult = await new InventoryBuilder(this.config).buildInventory();
    lastTurnId = await narrateScanPhase(
      client, sessionId, 'Discovery Complete',
      `Found ${inventory.servers.length} server(s) with ${inventory.totalTools} total tool(s).`,
      lastTurnId
    );

    // 3. Analysis (includes static, schema, semantic, drift, attestation)
    const analysisFindings = await new AnalysisOrchestrator(this.config).runAnalysis(inventory);
    lastTurnId = await narrateScanPhase(
      client, sessionId, 'Analysis Complete',
      `Analysis pipeline produced ${analysisFindings.findings.length} finding(s), ${analysisFindings.erroredTools.length} tool(s) errored.`,
      lastTurnId
    );

    // 4. Shadow server detection (Lever 1: TrueForge registry cross-reference)
    const shadowDetector = new ShadowServerDetector();
    const shadowResult = await shadowDetector.detect(client as any, this.config);
    if (shadowResult.findings.length > 0) {
      lastTurnId = await narrateScanPhase(
        client, sessionId, 'Shadow Server Detection',
        `Detected ${shadowResult.findings.length} shadow server finding(s) via TrueForge registry cross-reference.`,
        lastTurnId
      );
    }

    // 5. Probing
    const serverConfigs = new Map<string, ServerConfig>(
      (this.config.servers as ServerConfig[]).map((s) => [s.name, s])
    );
    const probingFindings = await runProbesForServers(inventory.servers, serverConfigs);
    lastTurnId = await narrateScanPhase(
      client, sessionId, 'Probing Complete',
      `Adversarial probing produced ${probingFindings.length} finding(s).`,
      lastTurnId
    );

    const allFindings = [
      ...analysisFindings.findings,
      ...shadowResult.findings,
      ...probingFindings,
    ];
    const allErroredTools = [
      ...analysisFindings.erroredTools,
      ...shadowResult.erroredTools,
    ];

    // 6. Scoring
    const scores = inventory.servers.map((s) =>
      RiskCalculator.calculate(
        s.serverName,
        'server',
        allFindings.filter((f) => f.serverName === s.serverName)
      )
    );
    scores.map(classifyRisk);

    // 7. Remediation
    const proposals = new FixProposer().proposeFixes(allFindings);
    const gate = new ApprovalGate(client, sessionId);
    for (const proposal of proposals) {
      const finding = allFindings.find((f) => f.id === proposal.findingId);
      if (!finding) continue;
      const decision = await gate.requestApproval(proposal, finding);
      logger.info(`Approval decision for ${finding.id}: ${decision.approved ? 'approved' : decision.reason}`);
    }

    // 8. Report + persistence
    buildGraph(inventory, allFindings, scores);
    await new SessionStore().save({
      id: runId,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      configSnapshot: this.config,
      discoveryResult: inventory,
      findings: allFindings,
    });

    // 9. Final narration
    await narrateScanPhase(
      client, sessionId, 'Scan Complete',
      `Total: ${allFindings.length} finding(s), ${allErroredTools.length} errored tool(s). ` +
      `TrueForge session ${sessionId}. Run ID: ${runId}.`,
      lastTurnId
    );

    logger.info(`Scan complete. ${allFindings.length} finding(s), TrueForge session ${sessionId}`);
    return { findings: allFindings, sessionId, erroredTools: allErroredTools };
  }
}
