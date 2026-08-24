import type { VulnerabilityFinding, RiskScore } from '../types/index.js';
import type { ScanSession } from './session-store.js';

export interface ScoreChange {
  entityName: string;
  previousScore: number;
  currentScore: number;
  previousGrade: string;
  currentGrade: string;
}

export interface DriftReport {
  newFindings: VulnerabilityFinding[];
  resolvedFindings: VulnerabilityFinding[];
  changedScores: ScoreChange[];
  overallTrend: 'improving' | 'stable' | 'degrading';
}

/**
 * Compares current scan results against the last saved session to detect
 * security drift — new findings, resolved findings, and score changes.
 */
export class DriftTracker {
  /**
   * Compares the current findings against a previous session.
   * @param previous - The prior scan session (null if this is the first scan)
   * @param currentFindings - Current scan's vulnerability findings
   * @returns A drift report showing what changed
   */
  public compare(previous: ScanSession | null, currentFindings: VulnerabilityFinding[]): DriftReport {
    if (!previous) {
      return {
        newFindings: currentFindings,
        resolvedFindings: [],
        changedScores: [],
        overallTrend: currentFindings.length > 0 ? 'degrading' : 'stable',
      };
    }

    // Match findings by their composite key (toolName + serverName + title + category)
    // since UUIDs are regenerated each scan
    const makeKey = (f: VulnerabilityFinding) =>
      `${f.serverName}::${f.toolName}::${f.category}::${f.title}`;

    const prevKeys = new Set(previous.findings.map(makeKey));
    const currKeys = new Set(currentFindings.map(makeKey));

    const newFindings = currentFindings.filter(f => !prevKeys.has(makeKey(f)));
    const resolvedFindings = previous.findings.filter(f => !currKeys.has(makeKey(f)));

    let trend: DriftReport['overallTrend'] = 'stable';
    if (newFindings.length > resolvedFindings.length) {
      trend = 'degrading';
    } else if (resolvedFindings.length > newFindings.length) {
      trend = 'improving';
    }

    return {
      newFindings,
      resolvedFindings,
      changedScores: [],
      overallTrend: trend,
    };
  }
}
