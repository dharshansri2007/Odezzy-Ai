import { createLogger } from '../utils/logger.js';
import { randomUUID } from 'node:crypto';
import { 
  type DiscoveryResult, 
  type VulnerabilityFinding, 
  type OdezzyConfig,
  type ErroredTool,
  type AnalysisPipelineResult
} from '../types/index.js';
import { StaticRuleEngine } from './static-rules.js';
import { SchemaDiffAnalyzer } from './schema-diff.js';
import { SemanticCheckAnalyzer } from './semantic-check.js';
import { DriftDetector } from './drift-detector.js';
import { AttestationLedger } from '../attestation/attestation-ledger.js';
import { QuarantineRegistry } from '../remediation/quarantine-registry.js';

const logger = createLogger('analysis-orchestrator');

export class AnalysisOrchestrator {
  private config: OdezzyConfig;
  private staticEngine: StaticRuleEngine;
  private schemaDiff: SchemaDiffAnalyzer;
  private semanticCheck: SemanticCheckAnalyzer | null;
  private driftDetector: DriftDetector | null;
  private ledger = new AttestationLedger();
  private quarantine = new QuarantineRegistry();

  constructor(config: OdezzyConfig) {
    this.config = config;
    this.staticEngine = new StaticRuleEngine();
    this.schemaDiff = new SchemaDiffAnalyzer();
    this.semanticCheck = config.gcpProjectId ? new SemanticCheckAnalyzer(config) : null;
    this.driftDetector = config.gcpProjectId ? new DriftDetector(config) : null;
  }

  public async runAnalysis(discovery: DiscoveryResult): Promise<AnalysisPipelineResult> {
    logger.info('Starting analysis pipeline');
    const allFindings: VulnerabilityFinding[] = [];
    const allErroredTools: ErroredTool[] = [];
    const skippedStages: string[] = [];
    const quarantinedKeys = new Set<string>();

    // 0. Quarantine check — tools a human already approved for quarantine
    // are excluded from active re-analysis (no point re-flagging or
    // re-spending API calls on something already banned) and get a single
    // honest 'quarantined' finding instead, so it's still visible in the report.
    const activeServers: DiscoveryResult['servers'] = [];
    for (const server of discovery.servers) {
      const activeTools = [];
      for (const tool of server.tools) {
        if (await this.quarantine.isQuarantined(tool.name, server.serverName)) {
          quarantinedKeys.add(`${server.serverName}:${tool.name}`);
          allFindings.push({
            id: randomUUID(),
            toolName: tool.name,
            serverName: server.serverName,
            severity: 'critical',
            category: 'quarantined',
            title: `Tool "${tool.name}" is quarantined`,
            description: 'This tool was previously quarantined via an approved remediation and is excluded from active analysis and attestation.',
            evidence: 'Present in .odezzy/quarantine.json',
            remediation: 'Review the quarantine record before considering this tool trustworthy again.',
            confidence: 1,
          });
          logger.warn(`Skipping active analysis for quarantined tool "${tool.name}" on "${server.serverName}"`);
        } else {
          activeTools.push(tool);
        }
      }
      activeServers.push({ ...server, tools: activeTools });
    }

    // 1. Static Rules Pass (quarantined tools excluded)
    const staticFindings = this.staticEngine.scan(activeServers);
    allFindings.push(...staticFindings);

    const semanticTargets = [];

    for (const server of activeServers) {
      for (const tool of server.tools) {
        // 2. Schema Diff (Declared) Pass
        const schemaFindings = this.schemaDiff.checkDeclaredSchema(tool, server.serverName);
        allFindings.push(...schemaFindings);
        
        semanticTargets.push({ tool, serverName: server.serverName });
      }
    }

    // 3. Semantic Check Pass (if configured)
    if (this.semanticCheck) {
      logger.info('Running semantic checks');
      const semanticResult = await this.semanticCheck.batchAnalyze(semanticTargets);
      allFindings.push(...semanticResult.findings);
      allErroredTools.push(...semanticResult.erroredTools);
    } else {
      logger.info('Skipping semantic checks (no gcpProjectId configured — Vertex AI requires a project)');
      skippedStages.push('semantic-check');
    }

    // 4. Drift Detection Pass (if configured)
    if (this.driftDetector) {
      logger.info('Running drift detection');
      const driftTargets = [];
      for (const server of activeServers) {
        for (const tool of server.tools) {
          driftTargets.push({ tool, serverName: server.serverName });
        }
      }
      const driftResult = await this.driftDetector.batchCheckDrift(driftTargets);
      allFindings.push(...driftResult.findings);
      allErroredTools.push(...driftResult.erroredTools);
    } else {
      logger.info('Skipping drift detection (no gcpProjectId configured — Vertex AI requires a project)');
      skippedStages.push('drift-detection');
    }

    // 5. Attestation — certify tools that passed all checks.
    // Quarantined tools are never re-attested: their trust was already
    // and deliberately revoked, and re-running clean checks on an
    // excluded tool would produce nothing to attest against anyway.
    for (const server of activeServers) {
      for (const tool of server.tools) {
        const findingsForThisTool = allFindings.filter(
          (f) => f.toolName === tool.name && f.serverName === server.serverName
        );
        // Don't attest tools that errored during analysis — we can't confirm they're clean
        const toolErrored = allErroredTools.some(
          (e) => e.toolName === tool.name && e.serverName === server.serverName
        );
        if (!toolErrored) {
          await this.ledger.attest(tool, server.serverName, findingsForThisTool);
        } else {
          logger.info(`Not attesting "${tool.name}" on "${server.serverName}" — analysis was incomplete (tool errored).`);
        }
      }
    }

    logger.info(`Analysis pipeline complete. Total findings: ${allFindings.length}, errored tools: ${allErroredTools.length}, quarantined tools skipped: ${quarantinedKeys.size}`);
    return { findings: allFindings, erroredTools: allErroredTools };
  }
}