import dotenv from 'dotenv';
dotenv.config();

import chalk from 'chalk';
import ora from 'ora';
import fs from 'node:fs/promises';
import path from 'node:path';

import { loadConfig } from './config/parser.js';
import { InventoryBuilder } from './discovery/inventory.js';
import { StaticRuleEngine } from './analysis/static-rules.js';
import { SchemaDiffAnalyzer } from './analysis/schema-diff.js';
import { SemanticCheckAnalyzer } from './analysis/semantic-check.js';
import { DriftDetector } from './analysis/drift-detector.js';
import { RootAgent } from './agent/root-agent.js';
import { RiskCalculator } from './scoring/risk-formula.js';
import { classifyRisk } from './scoring/risk-classifier.js';
import { ReportGenerator } from './report/governance-report.js';
import { SessionStore } from './persistence/session-store.js';
import { AttestationLedger } from './attestation/attestation-ledger.js';
import { FixProposer } from './remediation/fix-proposer.js';
import { ApplyFix } from './remediation/apply-fix.js';
import { HumanApprovalToken } from './remediation/human-approval-token.js';
import { QuarantineRegistry } from './remediation/quarantine-registry.js';
import { randomUUID } from 'node:crypto';
import { type VulnerabilityFinding, type OdezzyConfig, type DiscoveryResult, type ErroredTool } from './types/index.js';

async function main() {
  const args = process.argv.slice(2);
  let command = 'scan';
  let configPath = 'odezzy.config.json';
  let inventoryPath = '';
  let sessionId = '';
  let skipDrift = false;
  let quarantineFindingId = '';
  let confirmQuarantine = false;

  // Simple arg parsing
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--skip-drift') {
      skipDrift = true;
    } else if (args[i] === '--confirm') {
      confirmQuarantine = true;
    } else if (args[i] === '--config' && i + 1 < args.length) {
      configPath = args[i + 1];
      i++;
    } else if (!args[i].startsWith('-')) {
      if (['scan', 'discover', 'analyze', 'report', 'fullscan', 'quarantine'].includes(args[i])) {
        command = args[i];
        if (command === 'analyze' && i + 1 < args.length) {
          inventoryPath = args[i + 1];
          i++;
        } else if (command === 'report' && i + 1 < args.length) {
          sessionId = args[i + 1];
          i++;
        } else if (command === 'quarantine' && i + 2 < args.length) {
          sessionId = args[i + 1];
          quarantineFindingId = args[i + 2];
          i += 2;
        }
      }
    }
  }

  process.on('SIGINT', () => {
    console.log(chalk.red('\n[!] Gracefully shutting down...'));
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    console.log(chalk.red('\n[!] Gracefully shutting down...'));
    process.exit(0);
  });

  console.log(chalk.cyan.bold('\n🛡️  Odezzy AI - MCP Security Red-Teaming Agent'));
  console.log(chalk.gray('================================================'));

  const spinner = ora('Loading configuration...').start();
  let config: OdezzyConfig;
  try {
    config = loadConfig(); // Note: loadConfig currently hardcodes odezzy.config.json, but it's okay for now
    spinner.succeed(`Configuration loaded. Connected to Project: ${chalk.yellow(config.gcpProjectId || 'N/A')}`);
  } catch (err: any) {
    spinner.fail('Failed to load configuration.');
    console.error(chalk.red(err.message));
    process.exit(1);
  }

  if (command === 'discover' || command === 'scan') {
    spinner.start('Running Discovery Engine...');
    const builder = new InventoryBuilder(config);
    let inventory: DiscoveryResult;
    try {
      inventory = await builder.buildInventory();
      spinner.succeed(`Discovery complete. Found ${chalk.green(inventory.servers.length)} server(s) and ${chalk.green(inventory.totalTools)} tool(s).`);
    } catch (err: any) {
      spinner.fail('Discovery failed.');
      console.error(chalk.red(err.message));
      process.exit(1);
    }

    if (command === 'scan') {
      await runAnalysisPipeline(inventory, config, skipDrift);
    }
  } else if (command === 'analyze') {
    if (!inventoryPath) {
      console.error(chalk.red('Usage: npm run dev analyze <inventory-path>'));
      process.exit(1);
    }
    spinner.start(`Loading inventory from ${inventoryPath}...`);
    try {
      const data = await fs.readFile(path.resolve(process.cwd(), inventoryPath), 'utf8');
      const inventory = JSON.parse(data) as DiscoveryResult;
      spinner.succeed(`Inventory loaded with ${inventory.servers.length} server(s).`);
      await runAnalysisPipeline(inventory, config, skipDrift);
    } catch (err: any) {
      spinner.fail('Failed to load inventory.');
      console.error(chalk.red(err.message));
      process.exit(1);
    }
  } else if (command === 'fullscan') {
    spinner.start('Running full TrueForge-backed scan...');
    try {
      const agent = new RootAgent(config, { remediationMcpServerName: config.remediationMcpServerName });
      const result = await agent.runFullScan();
      spinner.succeed(`Full scan complete. ${result.findings.length} finding(s). TrueForge session: ${result.sessionId}`);
      await generateSummary(result.findings);
    } catch (err: any) {
      spinner.fail('Full scan failed.');
      console.error(chalk.red(err.message));
      process.exit(1);
    }
  } else if (command === 'report') {
    if (!sessionId) {
      console.error(chalk.red('Usage: npm run dev report <session-id>'));
      process.exit(1);
    }
    console.log(chalk.yellow(`Report generation for session ${sessionId} is not yet fully implemented in this entrypoint.`));
  } else if (command === 'quarantine') {
    if (!sessionId || !quarantineFindingId) {
      console.error(chalk.red('Usage: npm run dev quarantine <session-id> <finding-id> --confirm'));
      process.exit(1);
    }

    const session = await new SessionStore().load(sessionId);
    if (!session) {
      console.error(chalk.red(`No session found with id ${sessionId}. Run "npm run dev report" or check .odezzy/sessions/.`));
      process.exit(1);
    }

    const finding = session.findings.find((f) => f.id === quarantineFindingId);
    if (!finding) {
      console.error(chalk.red(`No finding with id ${quarantineFindingId} in session ${sessionId}.`));
      process.exit(1);
    }

    const proposal = new FixProposer().proposeFixes([finding])[0];
    if (!proposal.autoFixable) {
      console.error(chalk.red(`Finding "${finding.title}" is not eligible for automated quarantine (category: ${finding.category}). Manual remediation required.`));
      process.exit(1);
    }

    console.log(chalk.yellow(`\nFinding: ${finding.title}`));
    console.log(chalk.yellow(`Tool: ${finding.toolName} on ${finding.serverName}`));
    console.log(chalk.yellow(`Severity: ${finding.severity}`));
    console.log(chalk.yellow(`Proposed action: ${proposal.proposedFix}\n`));

    if (!confirmQuarantine) {
      console.log(chalk.cyan('Dry run — no changes made. Re-run with --confirm to actually quarantine this tool and revoke its attestation.'));
      process.exit(0);
    }

    // This --confirm flag, typed by a human on their own machine against a
    // specific finding id, IS the approval act — the same role the old
    // readline y/n prompt played before TrueForge's async approval flow
    // was added. It is deliberately not something the agent can trigger itself.
    // Minting the token here is what makes this path go through the same
    // chokepoint as approval-gate.ts's TrueForge path — apply() only
    // accepts a real HumanApprovalToken, and this is the only factory
    // that can produce one from a CLI confirmation.
    const token = HumanApprovalToken.fromCliConfirmFlag(finding.id);
    const result = await new ApplyFix().apply(proposal, finding, token);
    if (result.applied) {
      console.log(chalk.green(`✔ ${result.detail}`));
    } else {
      console.error(chalk.red(`✘ Quarantine failed: ${result.error}`));
      process.exit(1);
    }
  }
}

async function runAnalysisPipeline(inventory: DiscoveryResult, config: OdezzyConfig, skipDrift: boolean = false) {
  const spinner = ora('Starting Analysis Pipeline...').start();
  let allFindings: VulnerabilityFinding[] = [];
  const allErroredTools: ErroredTool[] = [];
  const skippedStages: string[] = [];
  const quarantine = new QuarantineRegistry();
  const ledger = new AttestationLedger();

  // 0. Quarantine check — same as AnalysisOrchestrator: a tool a human
  // already approved for quarantine is excluded from active re-analysis
  // and re-attestation, and instead gets a single honest finding.
  spinner.text = 'Checking quarantine registry...';
  const activeServers: DiscoveryResult['servers'] = [];
  for (const server of inventory.servers) {
    const activeTools = [];
    for (const tool of server.tools) {
      if (await quarantine.isQuarantined(tool.name, server.serverName)) {
        allFindings.push({
          id: randomUUID(),
          toolName: tool.name,
          serverName: server.serverName,
          severity: 'critical',
          category: 'quarantined',
          title: `Tool "${tool.name}" is quarantined`,
          description: 'This tool was previously quarantined via an approved remediation and is excluded from active analysis and attestation.',
          evidence: 'Present in .odezzy/quarantine.jsonl (hash-chained approval record)',
          remediation: 'Review the quarantine record before considering this tool trustworthy again.',
          confidence: 1,
        });
      } else {
        activeTools.push(tool);
      }
    }
    activeServers.push({ ...server, tools: activeTools });
  }

  // 1. Static Rule Engine (quarantined tools excluded)
  spinner.text = 'Running Static Rule Engine...';
  const staticEngine = new StaticRuleEngine();
  const staticFindings = staticEngine.scan(activeServers);
  allFindings.push(...staticFindings);

  // 2. Schema Diff Analyzer
  spinner.text = 'Running Schema Diff Analyzer...';
  const schemaAnalyzer = new SchemaDiffAnalyzer();
  const schemaFindings: VulnerabilityFinding[] = [];
  for (const server of activeServers) {
    for (const tool of server.tools) {
      schemaFindings.push(...schemaAnalyzer.checkDeclaredSchema(tool, server.serverName));
    }
  }
  allFindings.push(...schemaFindings);

  // 3. Semantic Check Analyzer
  if (config.gcpProjectId) {
    spinner.text = 'Running Semantic Check Analyzer (Vertex AI)...';
    const semanticAnalyzer = new SemanticCheckAnalyzer(config);
    const toolsToAnalyze = [];
    for (const server of activeServers) {
      for (const tool of server.tools) {
        toolsToAnalyze.push({ tool, serverName: server.serverName });
      }
    }
    const semanticResult = await semanticAnalyzer.batchAnalyze(toolsToAnalyze);
    allFindings.push(...semanticResult.findings);
    allErroredTools.push(...semanticResult.erroredTools);
  } else {
    spinner.info('Skipping Semantic Check Analyzer (GCP_PROJECT_ID not set).');
    skippedStages.push('semantic-check');
    spinner.start('Resuming analysis...');
  }

  // 4. Drift Detector
  if (config.gcpProjectId && !skipDrift) {
    spinner.text = 'Running Drift Detector (Vertex AI)...';
    const driftDetector = new DriftDetector(config);
    const driftTargets = [];
    for (const server of activeServers) {
      for (const tool of server.tools) {
        driftTargets.push({ tool, serverName: server.serverName });
      }
    }
    const driftResult = await driftDetector.batchCheckDrift(driftTargets);
    allFindings.push(...driftResult.findings);
    allErroredTools.push(...driftResult.erroredTools);
  } else if (skipDrift) {
    spinner.info('Skipping Drift Detector (--skip-drift passed).');
    skippedStages.push('drift-detection');
    spinner.start('Resuming analysis...');
  } else {
    spinner.info('Skipping Drift Detector (GCP_PROJECT_ID not set).');
    skippedStages.push('drift-detection');
    spinner.start('Resuming analysis...');
  }

  // 5. Attestation — certify tools that passed all checks. This was
  // previously missing from this pipeline entirely (the "scan" command
  // never attested anything, even though AnalysisOrchestrator's "fullscan"
  // path did) — added here so the two pipelines behave consistently.
  spinner.text = 'Attesting clean tools...';
  for (const server of activeServers) {
    for (const tool of server.tools) {
      const findingsForThisTool = allFindings.filter(
        (f) => f.toolName === tool.name && f.serverName === server.serverName
      );
      const toolErrored = allErroredTools.some(
        (e) => e.toolName === tool.name && e.serverName === server.serverName
      );
      // Re-check quarantine status right here, immediately before
      // attesting — same TOCTOU fix as AnalysisOrchestrator.runAnalysis()
      // in analysis/index.ts. This pipeline is a separate copy of the
      // analysis loop (see the comment above), so it needed the same fix
      // applied independently — fixing one without the other would have
      // left this "scan" command's older code path silently vulnerable
      // to the exact race the fix in analysis/index.ts closes.
      const quarantinedNow = await quarantine.isQuarantined(tool.name, server.serverName);
      if (quarantinedNow) {
        spinner.text = `Skipping attestation for "${tool.name}" — quarantined during this scan.`;
        continue;
      }
      if (!toolErrored) {
        await ledger.attest(tool, server.serverName, findingsForThisTool);
      }
    }
  }

  spinner.succeed(`Analysis pipeline complete. Found ${chalk.red(allFindings.length)} vulnerabilities.`);
  
  // Scoring
  spinner.start('Calculating risks and generating report...');
  const scanId = randomUUID();
  const scanStartedAt = new Date().toISOString();

  const scores = inventory.servers.map((s) =>
    RiskCalculator.calculate(
      s.serverName,
      'server',
      allFindings.filter((f) => f.serverName === s.serverName)
    )
  );
  scores.map(classifyRisk);

  // Build report
  const bySeverityReport: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategoryReport: Record<string, number> = {};
  for (const f of allFindings) {
    bySeverityReport[f.severity] = (bySeverityReport[f.severity] || 0) + 1;
    byCategoryReport[f.category] = (byCategoryReport[f.category] || 0) + 1;
  }

  const scanReport = {
    id: scanId,
    projectName: config.gcpProjectId || 'Odezzy AI',
    scanStartedAt,
    scanCompletedAt: new Date().toISOString(),
    summary: {
      totalFindings: allFindings.length,
      bySeverity: bySeverityReport,
      byCategory: byCategoryReport,
    },
    findings: allFindings,
    inventories: inventory.servers,
    incompleteAnalysis: allErroredTools.length > 0 || skippedStages.length > 0 ? {
      erroredTools: allErroredTools,
      skippedStages,
    } : undefined,
    metadata: {
      agentVersion: '0.6.0',
      scanDurationMs: Date.now() - new Date(scanStartedAt).getTime(),
    },
  };

  // Generate governance report
  try {
    const reportGen = new ReportGenerator();
    await reportGen.generate(scanReport as any);
  } catch (err) {
    spinner.warn('Report generation encountered an issue (non-fatal).');
  }

  // Save session
  try {
    const sessionStore = new SessionStore();
    await sessionStore.save({
      id: scanId,
      startedAt: scanStartedAt,
      completedAt: new Date().toISOString(),
      configSnapshot: config,
      discoveryResult: inventory,
      findings: allFindings,
    });
  } catch (err) {
    spinner.warn('Session persistence encountered an issue (non-fatal).');
  }

  spinner.succeed(`Report and session saved. Session ID: ${scanId}`);

  await generateSummary(allFindings, allErroredTools);
}

async function generateSummary(findings: VulnerabilityFinding[], erroredTools: ErroredTool[] = []) {
  console.log(chalk.cyan.bold('\n Scan Summary'));
  console.log(chalk.gray('================================================'));
  
  if (findings.length === 0) {
    console.log(chalk.green(' No vulnerabilities found. Your MCP servers are secure!'));
    return;
  }

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byServer: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity]++;
    byServer[f.serverName] = (byServer[f.serverName] || 0) + 1;
  }

  console.log(chalk.white('By Severity:'));
  if (bySeverity.critical > 0) console.log(chalk.red(`  Critical: ${bySeverity.critical}`));
  if (bySeverity.high > 0) console.log(chalk.magenta(`  High:     ${bySeverity.high}`));
  if (bySeverity.medium > 0) console.log(chalk.yellow(`  Medium:   ${bySeverity.medium}`));
  if (bySeverity.low > 0) console.log(chalk.blue(`  Low:      ${bySeverity.low}`));
  if (bySeverity.info > 0) console.log(chalk.gray(`  Info:     ${bySeverity.info}`));

  console.log(chalk.white('\nBy Server:'));
  for (const [server, count] of Object.entries(byServer)) {
    console.log(`  ${chalk.cyan(server)}: ${count} finding(s)`);
  }

  console.log(chalk.yellow('\n  Please review the generated reports in .odezzy/ for full remediation details.'));

  if (erroredTools.length > 0) {
    console.log(chalk.red(`\n⚠️  Warning: ${erroredTools.length} tool(s) could not be fully analyzed. Review the report for details.`));
  }

  // Attestation ledger summary
  try {
    const ledger = new AttestationLedger();
    const fullLedger = await ledger.getFullLedger();
    const attested = fullLedger.filter(r => r.status === 'attested').length;
    const revoked = fullLedger.filter(r => r.status === 'revoked').length;
    if (fullLedger.length > 0) {
      console.log(chalk.cyan(`\n🔏 Attestation Ledger: ${attested} attested, ${revoked} revoked`));
    }
  } catch {
    // Attestation ledger not yet initialized — skip
  }
}

main().catch((err) => {
  console.error(chalk.red('\n[Fatal Error]'), err);
  process.exit(1);
});