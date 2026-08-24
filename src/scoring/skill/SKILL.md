# Odezzy AI Scoring Rubric

This skill documents the methodology used by Odezzy AI to evaluate and score the security risks of MCP servers and tools.

## Severity Weights
Each vulnerability finding has a severity, which carries a specific base weight in the risk formula:
- **Critical**: 10
- **High**: 7
- **Medium**: 4
- **Low**: 2
- **Info**: 1

## Confidence Adjustment
The actual score contribution of a finding is the severity weight multiplied by the confidence (0.0 to 1.0).
Static matches and successful exploits generally have 0.9 - 1.0 confidence. LLM/semantic evaluations typically range between 0.5 - 0.8.

## The 0-100 Scale
The raw adjusted scores are summed across all findings for a given entity (tool or server). The total is then scaled (multiplied by 10) and capped at a maximum of `100`.
For example, one guaranteed critical finding yields 10 * 1.0 = 10 -> scaled to 100.

## Grade Mapping
Based on the final 0-100 score, entities are assigned a letter grade representing their security posture:
- **A** (Score 0): Perfect score, no findings.
- **B** (Score 1-24): Minor issues, low risk.
- **C** (Score 25-49): Moderate issues, needs attention.
- **D** (Score 50-74): High risk, serious vulnerabilities present.
- **F** (Score 75-100): Critical risk, immediate action required.

## Risk Classifications (Colors)
For executive dashboards and rapid triage, grades map into color-coded risk levels:
- **Green (<25)**: Safe for general use (Grades A, B).
- **Yellow (25-49)**: Use with caution (Grade C).
- **Orange (50-74)**: Quarantine recommended (Grade D).
- **Red (>=75)**: Do not use. Known critical exploit vectors (Grade F).
