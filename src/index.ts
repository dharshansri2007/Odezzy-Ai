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
import { randomUUID } from 'node:crypto';
import { type VulnerabilityFinding, type OdezzyConfig, type DiscoveryResult, type ErroredTool } from './types/index.js';

async function main() {
  const args = process.argv.slice(2);
  let command = 'scan';
  let configPath = 'odezzy.config.json';
  let inventoryPath = '';
  let sessionId = '';
  let skipDrift = false;

  // Simple arg parsing
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--skip-drift') {
      skipDrift = true;
    } else if (args[i] === '--config' && i + 1 < args.length) {
      configPath = args[i + 1];
      i++;
    } else if (!args[i].startsWith('-')) {
      if (['scan', 'discover', 'analyze', 'report', 'fullscan'].includes(args[i])) {
        command = args[i];
        if (command === 'analyze' && i + 1 < args.length) {
          inventoryPath = args[i + 1];
          i++;
        } else if (command === 'report' && i + 1 < args.length) {
          sessionId = args[i + 1];
          i++;
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
      const agent = new RootAgent(config);
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
  }
}

async function runAnalysisPipeline(inventory: DiscoveryResult, config: OdezzyConfig, skipDrift: boolean = false) {
  const spinner = ora('Starting Analysis Pipeline...').start();
  let allFindings: VulnerabilityFinding[] = [];
  const allErroredTools: ErroredTool[] = [];
  const skippedStages: string[] = [];

  // 1. Static Rule Engine
  spinner.text = 'Running Static Rule Engine...';
  const staticEngine = new StaticRuleEngine();
  const staticFindings = staticEngine.scan(inventory.servers);
  allFindings.push(...staticFindings);

  // 2. Schema Diff Analyzer
  spinner.text = 'Running Schema Diff Analyzer...';
  const schemaAnalyzer = new SchemaDiffAnalyzer();
  const schemaFindings: VulnerabilityFinding[] = [];
  for (const server of inventory.servers) {
    for (const tool of server.tools) {
      schemaFindings.push(...schemaAnalyzer.checkDeclaredSchema(tool, server.serverName));
    }
  }
  allFindings.push(...schemaFindings);

  // 3. Semantic Check Analyzer
  if (config.geminiApiKey) {
    spinner.text = 'Running Semantic Check Analyzer (Gemini)...';
    const semanticAnalyzer = new SemanticCheckAnalyzer(config);
    const toolsToAnalyze = [];
    for (const server of inventory.servers) {
      for (const tool of server.tools) {
        toolsToAnalyze.push({ tool, serverName: server.serverName });
      }
    }
    const semanticResult = await semanticAnalyzer.batchAnalyze(toolsToAnalyze);
    allFindings.push(...semanticResult.findings);
    allErroredTools.push(...semanticResult.erroredTools);
  } else {
    spinner.info('Skipping Semantic Check Analyzer (GEMINI_API_KEY not set).');
    skippedStages.push('semantic-check');
    spinner.start('Resuming analysis...');
  }

  // 4. Drift Detector
  if (config.geminiApiKey && !skipDrift) {
    spinner.text = 'Running Drift Detector (Gemini)...';
    const driftDetector = new DriftDetector(config);
    const driftTargets = [];
    for (const server of inventory.servers) {
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
    spinner.info('Skipping Drift Detector (GEMINI_API_KEY not set).');
    skippedStages.push('drift-detection');
    spinner.start('Resuming analysis...');
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