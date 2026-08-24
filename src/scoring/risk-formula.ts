import { VulnerabilityFinding, RiskScore } from '../types/index.js';

export class RiskCalculator {
  private static readonly WEIGHTS: Record<string, number> = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 1,
  };

  /**
   * Calculates a risk score based on findings.
   * Can be used for a single tool or an entire server.
   */
  public static calculate(
    entityName: string,
    entityType: 'server' | 'tool',
    findings: VulnerabilityFinding[]
  ): RiskScore {
    let rawScore = 0;
    let highestSeverity: RiskScore['highestSeverity'] = 'none';
    const severities = ['critical', 'high', 'medium', 'low', 'info'];

    for (const finding of findings) {
      const weight = this.WEIGHTS[finding.severity] || 0;
      // Score = weight * confidence
      rawScore += weight * finding.confidence;
      
      // Update highest severity
      if (highestSeverity === 'none' || severities.indexOf(finding.severity) < severities.indexOf(highestSeverity)) {
        highestSeverity = finding.severity;
      }
    }

    // Convert raw sum to a 0-100 scale. We cap at 100.
    const normalizedScore = Math.min(Math.round(rawScore * 10), 100);

    return {
      entityName,
      entityType,
      score: normalizedScore,
      grade: this.getGrade(normalizedScore),
      findingCount: findings.length,
      highestSeverity,
    };
  }

  private static getGrade(score: number): RiskScore['grade'] {
    if (score === 0) return 'A';
    if (score < 25) return 'B';
    if (score < 50) return 'C';
    if (score < 75) return 'D';
    return 'F';
  }
}
