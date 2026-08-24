import { VulnerabilityFinding } from '../types/index.js';

export interface FixProposal {
  findingId: string;
  proposedFix: string;
  autoFixable: boolean;
  diffPreview?: string;
  risk: 'safe' | 'moderate' | 'breaking';
}

export class FixProposer {
  public proposeFixes(findings: VulnerabilityFinding[]): FixProposal[] {
    return findings.map(finding => this.proposeFix(finding));
  }

  private proposeFix(finding: VulnerabilityFinding): FixProposal {
    switch (finding.category) {
      case 'undeclared-params':
        return {
          findingId: finding.id,
          proposedFix: 'Update the tool schema to declare all accepted parameters, or reject undeclared parameters in the tool implementation.',
          autoFixable: false,
          risk: 'breaking',
        };
      case 'prompt-injection':
        return {
          findingId: finding.id,
          proposedFix: 'Remove hidden HTML comments, role spoofing, or secretive instructions from the tool description.',
          autoFixable: true,
          diffPreview: '- ' + finding.evidence + '\n+ (removed)',
          risk: 'safe',
        };
      case 'leaked-secrets':
        return {
          findingId: finding.id,
          proposedFix: 'Remove the leaked API key or secret from the tool description or metadata. Rotate the secret immediately.',
          autoFixable: true,
          diffPreview: '- ' + finding.evidence + '\n+ [REDACTED]',
          risk: 'moderate',
        };
      case 'schema-mismatch':
        return {
          findingId: finding.id,
          proposedFix: 'Ensure the tool schema properties are defined explicitly.',
          autoFixable: false,
          risk: 'moderate',
        };
      case 'shadow-server':
        return {
          findingId: finding.id,
          proposedFix:
            'Reconcile the TrueForge MCP registry with odezzy.config.json: either add ' +
            'the missing server to both, or remove the stale entry from the source that has it.',
          autoFixable: false,
          risk: 'moderate',
        };
      default:
        return {
          findingId: finding.id,
          proposedFix: finding.remediation || 'Manual review required.',
          autoFixable: false,
          risk: 'moderate',
        };
    }
  }
}

