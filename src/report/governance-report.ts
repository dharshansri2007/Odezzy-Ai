import fs from 'node:fs/promises';
import path from 'node:path';
import { createLogger } from '../utils/logger.js';
import type { ScanReport } from '../types/index.js';
import { AttestationLedger } from '../attestation/attestation-ledger.js';

const logger = createLogger('governance-report');

export class ReportGenerator {
  private readonly reportsDir: string;

  constructor(reportsDir: string = '.odezzy/reports') {
    this.reportsDir = path.resolve(process.cwd(), reportsDir);
  }

  public async generate(report: ScanReport): Promise<void> {
    await fs.mkdir(this.reportsDir, { recursive: true });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const jsonPath = path.join(this.reportsDir, `${timestamp}.json`);
    const mdPath = path.join(this.reportsDir, `${timestamp}.md`);

    await fs.writeFile(jsonPath, JSON.stringify(report, null, 2), 'utf-8');
    logger.info(`Generated JSON report at ${jsonPath}`);

    const mdContent = this.generateMarkdown(report);
    
    // Append attestation ledger section
    let attestationSection = '';
    try {
      const ledger = new AttestationLedger();
      const fullLedger = await ledger.getFullLedger();
      const publicKey = await ledger.getPublicKey();

      if (fullLedger.length > 0) {
        attestationSection = [
          '',
          '## Cryptographic Attestation Ledger',
          '',
          'Public verification key (Ed25519, PEM):',
          '```',
          publicKey.trim(),
          '```',
          '',
          '| Tool | Server | Status | Timestamp | Signature (truncated) |',
          '|---|---|---|---|---|',
          ...fullLedger.map(r =>
            `| ${r.toolName} | ${r.serverName} | ${r.status === 'attested' ? '✅ Attested' : `🔴 Revoked (${r.revokedReason})`} | ${r.timestamp} | \`${r.signature.slice(0, 24)}...\` |`
          ),
          '',
          'Every record above is Ed25519-signed and hash-chained to the previous entry — any tampering',
          'with this log breaks the chain and is independently detectable by re-hashing from genesis.',
        ].join('\n');
      }
    } catch (err) {
      logger.warn('Could not include attestation ledger in report (non-fatal)');
    }

    await fs.writeFile(mdPath, mdContent + attestationSection, 'utf-8');
    logger.info(`Generated Markdown report at ${mdPath}`);
  }

  private generateMarkdown(report: ScanReport): string {
    const lines = [
      `# Odezzy Security Scan Report: ${report.projectName}`,
      '',
      `**Scan ID:** \`${report.id}\``,
      `**Started:** ${report.scanStartedAt}`,
      `**Completed:** ${report.scanCompletedAt}`,
      `**Duration:** ${report.metadata.scanDurationMs}ms`,
      '',
      '## Executive Summary',
      '',
      `- **Total Findings:** ${report.summary.totalFindings}`,
      '',
    ];

    // Fail-visible: warn about incomplete analysis
    if (report.incompleteAnalysis && (
      report.incompleteAnalysis.erroredTools.length > 0 ||
      report.incompleteAnalysis.skippedStages.length > 0
    )) {
      lines.push(
        '',
        '> ⚠️ **Incomplete Analysis Warning**',
        '>',
        '> This scan could not fully analyze all tools. The findings below may',
        '> undercount real vulnerabilities. A security tool that silently reports',
        '> fewer findings than it should is failing in the most dangerous direction.',
        ''
      );
      if (report.incompleteAnalysis.erroredTools.length > 0) {
        lines.push('### Tools That Could Not Be Analyzed', '');
        lines.push('| Tool | Server | Stage | Error |', '|---|---|---|---|');
        for (const et of report.incompleteAnalysis.erroredTools) {
          lines.push(`| ${et.toolName} | ${et.serverName} | ${et.stage} | ${et.error.slice(0, 100)} |`);
        }
        lines.push('');
      }
      if (report.incompleteAnalysis.skippedStages.length > 0) {
        lines.push(
          `**Skipped stages:** ${report.incompleteAnalysis.skippedStages.join(', ')}`,
          ''
        );
      }
    }

    lines.push(
      '### Findings by Severity',
      ...Object.entries(report.summary.bySeverity).map(([sev, count]) => `- **${sev.toUpperCase()}**: ${count}`),
      '',
      '## Vulnerability Details',
      '',
    );

    if (report.findings.length === 0) {
      lines.push('No vulnerabilities found! 🎉');
    } else {
      for (const finding of report.findings) {
        lines.push(
          `### ${finding.title}`,
          `- **Severity:** ${finding.severity.toUpperCase()}`,
          `- **Category:** ${finding.category}`,
          `- **Server / Tool:** ${finding.serverName} / ${finding.toolName}`,
          ...(finding.cweId ? [`- **CWE:** ${finding.cweId}`] : []),
          '',
          `**Description:** ${finding.description}`,
          '',
          `**Evidence:**\n\`\`\`\n${finding.evidence}\n\`\`\``,
          '',
          `**Remediation:** ${finding.remediation}`,
          '',
          '---'
        );
      }

      const owaspGroups = new Map<string, typeof report.findings>();
      for (const finding of report.findings) {
        const cat = finding.owaspCategory || 'Uncategorized';
        if (!owaspGroups.has(cat)) owaspGroups.set(cat, []);
        owaspGroups.get(cat)!.push(finding);
      }

      lines.push('', '## OWASP MCP Top 10 Mapping', '');
      for (const [category, findings] of owaspGroups) {
        lines.push(`### ${category}`, `- **Findings:** ${findings.length}`, '');
        for (const f of findings) {
          lines.push(`  - ${f.title} (${f.severity}) — ${f.toolName}`);
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }
}