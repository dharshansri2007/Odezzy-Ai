import { createLogger } from '../utils/logger.js';
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

const logger = createLogger('analysis-orchestrator');

export class AnalysisOrchestrator {
  private config: OdezzyConfig;
  private staticEngine: StaticRuleEngine;
  private schemaDiff: SchemaDiffAnalyzer;
  private semanticCheck: SemanticCheckAnalyzer | null;
  private driftDetector: DriftDetector | null;
  private ledger = new AttestationLedger();

  constructor(config: OdezzyConfig) {
    this.config = config;
    this.staticEngine = new StaticRuleEngine();
    this.schemaDiff = new SchemaDiffAnalyzer();
    this.semanticCheck = config.geminiApiKey ? new SemanticCheckAnalyzer(config) : null;
    this.driftDetector = config.geminiApiKey ? new DriftDetector(config) : null;
  }

  public async runAnalysis(discovery: DiscoveryResult): Promise<AnalysisPipelineResult> {
    logger.info('Starting analysis pipeline');
    const allFindings: VulnerabilityFinding[] = [];
    const allErroredTools: ErroredTool[] = [];
    const skippedStages: string[] = [];

    // 1. Static Rules Pass
    const staticFindings = this.staticEngine.scan(discovery.servers);
    allFindings.push(...staticFindings);

    const semanticTargets = [];

    for (const server of discovery.servers) {
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
      logger.info('Skipping semantic checks (no geminiApiKey configured)');
      skippedStages.push('semantic-check');
    }

    // 4. Drift Detection Pass (if configured)
    if (this.driftDetector) {
      logger.info('Running drift detection');
      const driftTargets = [];
      for (const server of discovery.servers) {
        for (const tool of server.tools) {
          driftTargets.push({ tool, serverName: server.serverName });
        }
      }
      const driftResult = await this.driftDetector.batchCheckDrift(driftTargets);
      allFindings.push(...driftResult.findings);
      allErroredTools.push(...driftResult.erroredTools);
    } else {
      logger.info('Skipping drift detection (no geminiApiKey configured)');
      skippedStages.push('drift-detection');
    }

    // 5. Attestation — certify tools that passed all checks
    for (const server of discovery.servers) {
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

    logger.info(`Analysis pipeline complete. Total findings: ${allFindings.length}, errored tools: ${allErroredTools.length}`);
    return { findings: allFindings, erroredTools: allErroredTools };
  }
}
