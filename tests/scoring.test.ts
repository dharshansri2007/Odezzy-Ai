import { describe, it, expect } from 'vitest';
import { RiskCalculator } from '../src/scoring/risk-formula.js';
import { classifyRisk } from '../src/scoring/risk-classifier.js';
import type { VulnerabilityFinding } from '../src/types/index.js';
import { randomUUID } from 'node:crypto';

function makeFinding(severity: VulnerabilityFinding['severity'], confidence = 1.0): VulnerabilityFinding {
  return {
    id: randomUUID(),
    toolName: 'test-tool',
    serverName: 'test-server',
    severity,
    category: 'schema-mismatch',
    title: 'Test finding',
    description: 'A test finding',
    evidence: 'Test evidence',
    remediation: 'Fix it',
    confidence,
  };
}

describe('RiskCalculator', () => {
  it('should calculate score 0 and grade A for no findings', () => {
    const result = RiskCalculator.calculate('test-server', 'server', []);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('A');
    expect(result.highestSeverity).toBe('none');
    expect(result.findingCount).toBe(0);
  });

  it('should calculate weighted scores correctly', () => {
    const findings = [
      makeFinding('high', 1.0),   // 7 * 1.0 = 7
      makeFinding('medium', 0.5), // 4 * 0.5 = 2
    ];
    const result = RiskCalculator.calculate('test-server', 'server', findings);
    // raw = 9, normalized = min(9 * 10, 100) = 90
    expect(result.score).toBe(90);
    expect(result.grade).toBe('F');
    expect(result.findingCount).toBe(2);
    expect(result.highestSeverity).toBe('high');
  });

  it('should cap score at 100', () => {
    const findings = [
      makeFinding('critical', 1.0), // 10
      makeFinding('critical', 1.0), // 10
    ];
    const result = RiskCalculator.calculate('test-server', 'server', findings);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('F');
  });

  it('should handle single info finding correctly', () => {
    const result = RiskCalculator.calculate('test-tool', 'tool', [makeFinding('info', 1.0)]);
    // raw = 1, normalized = min(1 * 10, 100) = 10
    expect(result.score).toBe(10);
    expect(result.grade).toBe('B');
  });

  it('should apply confidence multiplier', () => {
    const result = RiskCalculator.calculate('test-tool', 'tool', [makeFinding('high', 0.5)]);
    // raw = 7 * 0.5 = 3.5, normalized = min(35, 100) = 35
    expect(result.score).toBe(35);
    expect(result.grade).toBe('C');
  });
});

describe('classifyRisk', () => {
  it('should classify score < 25 as green', () => {
    const score = RiskCalculator.calculate('s', 'server', [makeFinding('info', 1.0)]);
    const classification = classifyRisk(score);
    expect(classification.level).toBe('green');
  });

  it('should classify score >= 25 as yellow', () => {
    const score = RiskCalculator.calculate('s', 'server', [makeFinding('high', 0.5)]);
    // score = 35
    const classification = classifyRisk(score);
    expect(classification.level).toBe('yellow');
  });

  it('should classify score >= 50 as orange', () => {
    const score = RiskCalculator.calculate('s', 'server', [makeFinding('high', 1.0)]);
    // score = 70
    const classification = classifyRisk(score);
    expect(classification.level).toBe('orange');
  });

  it('should classify score >= 75 as red', () => {
    const score = RiskCalculator.calculate('s', 'server', [
      makeFinding('critical', 1.0),
      makeFinding('high', 1.0),
    ]);
    // score = min((10 + 7) * 10, 100) = 100
    const classification = classifyRisk(score);
    expect(classification.level).toBe('red');
  });
});
