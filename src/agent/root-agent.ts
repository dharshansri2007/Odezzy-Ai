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
  private skipNarration: boolean;

  constructor(config: OdezzyConfig, opts: { remediationMcpServerName?: string; skipNarration?: boolean } = {}) {
    this.config = config;
    this.remediationMcpServerName = opts.remediationMcpServerName;
    // Narration turns are purely cosmetic (they make the scan visible in
    // TrueForge's own chat UI) but consume from the SAME account-wide
    // Groq TPM budget the approval turns need — and on a free-tier
    // account, that budget is the actual bottleneck, not model choice.
    // Default false to preserve existing behavior; pass true when quota
    // is tight and you'd rather every available token go to approvals.
    this.skipNarration = opts.skipNarration ?? false;
  }

  private async narrate(
    client: ReturnType<typeof createTrueForgeClient>,
    sessionId: string,
    phase: string,
    detail: string,
    previousTurnId?: string
  ): Promise<string | undefined> {
    if (this.skipNarration) return previousTurnId;
    return narrateScanPhase(client, sessionId, phase, detail, previousTurnId);
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

    lastTurnId = await this.narrate(
      client, sessionId, 'Scan Started',
      `Run ID: ${runId}. Scanning ${this.config.servers.length} configured server(s).`,
      lastTurnId
    );

    // 2. Discovery
    const inventory: DiscoveryResult = await new InventoryBuilder(this.config).buildInventory();
    lastTurnId = await this.narrate(
      client, sessionId, 'Discovery Complete',
      `Found ${inventory.servers.length} server(s) with ${inventory.totalTools} total tool(s).`,
      lastTurnId
    );

    // 3. Analysis (includes static, schema, semantic, drift, attestation)
    const analysisFindings = await new AnalysisOrchestrator(this.config).runAnalysis(inventory);
    lastTurnId = await this.narrate(
      client, sessionId, 'Analysis Complete',
      `Analysis pipeline produced ${analysisFindings.findings.length} finding(s), ${analysisFindings.erroredTools.length} tool(s) errored.`,
      lastTurnId
    );

    // 4. Shadow server detection (Lever 1: TrueForge registry cross-reference)
    const shadowDetector = new ShadowServerDetector();
    const shadowResult = await shadowDetector.detect(client as any, this.config);
    if (shadowResult.findings.length > 0) {
      lastTurnId = await this.narrate(
        client, sessionId, 'Shadow Server Detection',
        `Detected ${shadowResult.findings.length} shadow server finding(s) via TrueForge registry cross-reference.`,
        lastTurnId
      );
    }

    // 5. Probing — use the quarantine-filtered server list, not the raw inventory
    const serverConfigs = new Map<string, ServerConfig>(
      (this.config.servers as ServerConfig[]).map((s) => [s.name, s])
    );
    const probingFindings = await runProbesForServers(analysisFindings.activeServers, serverConfigs);
    lastTurnId = await this.narrate(
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
    let plumbingUnresolvedCount = 0;
    const gateSummary = { totalRequests: 0, approved: 0, deniedReviewed: 0, noRequest: 0, plumbingUnresolved: 0, pending: 0 };
    for (const proposal of proposals) {
      const finding = allFindings.find((f) => f.id === proposal.findingId);
      if (!finding) continue;
      // A small delay between approval requests, NOT because more speed is
      // unsafe, but because Groq's free-tier TPM limit (8000 tokens/minute)
      // is per-ORGANIZATION, not per-model — swapping models never fixes
      // this, since every model on the same account shares one bucket.
      // Firing 19 approval turns back-to-back reliably exhausts that
      // bucket in seconds, which is why every turn was landing on
      // "running" (rate-limited, never reached "done") rather than an
      // actual approval/denial. This delay is a mitigation, not a fix —
      // the real fix is a paid tier or fewer LLM-backed turns per run.
      if (gateSummary.totalRequests > 0 && this.config.approvalRequestDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.config.approvalRequestDelayMs));
      }
      let decision: { approved: boolean; reason?: string; gateStatus: 'plumbing-unresolved' | 'no-request' | 'pending' };
      try {
        decision = await gate.requestApproval(proposal, finding);
      } catch (err) {
        // A single TrueForge-side failure (rate limit, a stuck thread from
        // a PRIOR finding's turn never resolving, transient 5xx, etc.)
        // must not discard every finding already gathered by discovery /
        // analysis / probing. Treat this finding's approval as unresolved
        // — same fail-closed semantics as a non-"done" turn state — and
        // move on to the next finding rather than crashing the whole run.
        logger.error(`Approval request for finding ${finding.id} threw — treating as unresolved, continuing scan`, err);
        decision = { approved: false, reason: `Approval request errored: ${err instanceof Error ? err.message : String(err)}`, gateStatus: 'plumbing-unresolved' };
      }
      logger.info(`Approval decision for ${finding.id}: ${decision.approved ? 'approved' : decision.reason}`);
      gateSummary.totalRequests++;
      if (decision.gateStatus === 'plumbing-unresolved') {
        plumbingUnresolvedCount++;
        gateSummary.plumbingUnresolved++;
      } else if (decision.gateStatus === 'no-request') {
        gateSummary.noRequest++;
      } else if (decision.gateStatus === 'pending') {
        gateSummary.pending++;
      } else if (decision.approved) {
        gateSummary.approved++;
      } else {
        gateSummary.deniedReviewed++;
      }
    }
    if (plumbingUnresolvedCount > 0) {
      // This is the exact ambiguity the last review flagged: without this
      // line, "N findings, all failed closed" reads identically whether
      // TrueForge genuinely reviewed and rejected everything, or the
      // approval gate was unreachable the whole run. Make it impossible
      // to miss which one actually happened.
      logger.warn(
        `⚠️  ${plumbingUnresolvedCount}/${proposals.length} approval request(s) this run did NOT reach a ` +
          `resolved state (TrueForge turn stayed non-"done") — these were failed closed as unresolved, ` +
          `NOT reviewed and denied. Check that a remediation-tools MCP connector with ` +
          `requireApprovalForTools is registered in TrueForge before trusting this run's approval outcomes.`
      );
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
      approvalGateSummary: gateSummary,
    });

    // 9. Final narration
    await this.narrate(
      client, sessionId, 'Scan Complete',
      `Total: ${allFindings.length} finding(s), ${allErroredTools.length} errored tool(s). ` +
      `TrueForge session ${sessionId}. Run ID: ${runId}.`,
      lastTurnId
    );

    logger.info(`Scan complete. ${allFindings.length} finding(s), TrueForge session ${sessionId}`);
    return { findings: allFindings, sessionId, erroredTools: allErroredTools };
  }
}