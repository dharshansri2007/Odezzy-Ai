import { RiskScore, RiskClassification } from '../types/index.js';

/**
 * Takes the risk scores from risk-formula and classifies them into risk levels:
 * green (<25), yellow (25-49), orange (50-74), red (>=75).
 */
export function classifyRisk(score: RiskScore): RiskClassification {
  let level: RiskClassification['level'] = 'green';

  if (score.score >= 75) {
    level = 'red';
  } else if (score.score >= 50) {
    level = 'orange';
  } else if (score.score >= 25) {
    level = 'yellow';
  }

  return {
    level,
    score,
  };
}
