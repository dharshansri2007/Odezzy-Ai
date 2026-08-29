import { randomUUID } from 'node:crypto';
import { GoogleGenAI } from '@google/genai';
import { createHash } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import { EmbeddingBaselineStore } from '../persistence/embedding-baseline-store.js';
import { AttestationLedger } from '../attestation/attestation-ledger.js';
import type { MCPToolSchema, VulnerabilityFinding, OdezzyConfig, ErroredTool, AnalysisPipelineResult } from '../types/index.js';

const logger = createLogger('drift-detector');

const DRIFT_STABLE_THRESHOLD = 0.1;
const DRIFT_WARNING_THRESHOLD = 0.25;

export class DriftDetector {
  private client: GoogleGenAI;
  private store = new EmbeddingBaselineStore();
  private ledger = new AttestationLedger();

  constructor(config: OdezzyConfig) {
    if (!config.gcpProjectId) {
      throw new Error('DriftDetector requires gcpProjectId (Vertex AI + ADC) — none was provided.');
    }
    this.client = new GoogleGenAI({
      vertexai: true,
      project: config.gcpProjectId,
      location: config.gcpLocation,
    });
  }

  public async checkDrift(tool: MCPToolSchema, serverName: string): Promise<VulnerabilityFinding[]> {
    const description = tool.description ?? '';
    const hash = createHash('sha256').update(description).digest('hex');

    const baseline = await this.store.load(serverName, tool.name);

    if (!baseline) {
      const embedding = await this.embed(description);
      await this.store.save({ toolName: tool.name, serverName, descriptionHash: hash, embedding, scannedAt: new Date().toISOString() });
      logger.info(`Established drift baseline for ${serverName}/${tool.name}`);
      return [];
    }

    if (baseline.descriptionHash === hash) {
      return [];
    }

    const currentEmbedding = await this.embed(description);
    const distance = this.cosineDistance(baseline.embedding, currentEmbedding);

    if (distance < DRIFT_STABLE_THRESHOLD) {
      // Small change, not meaningful — update baseline to current
      await this.store.save({ toolName: tool.name, serverName, descriptionHash: hash, embedding: currentEmbedding, scannedAt: new Date().toISOString() });
      return [];
    }

    // Drift detected — do NOT update baseline (preserve the original clean version)
    // Revoke any existing attestation for this tool
    await this.ledger.revoke(
      tool.name,
      serverName,
      `Semantic drift detected: cosine distance ${distance.toFixed(4)} exceeds threshold`
    );

    const severity: VulnerabilityFinding['severity'] = distance >= DRIFT_WARNING_THRESHOLD ? 'high' : 'medium';

    return [
      {
        id: randomUUID(),
        toolName: tool.name,
        serverName,
        severity,
        category: 'semantic-drift',
        title: `Tool description semantically drifted since last scan (cosine distance ${distance.toFixed(3)})`,
        description:
          `The description for "${tool.name}" changed in a way that shifted its embedded meaning, not just its wording. ` +
          `This is exactly the "rug pull" pattern — a tool approved once, then quietly changed after the fact — and it ` +
          `would not be caught by a plain text diff.`,
        evidence: `Cosine distance from baseline: ${distance.toFixed(4)} (stable < ${DRIFT_STABLE_THRESHOLD}, warning ${DRIFT_STABLE_THRESHOLD}–${DRIFT_WARNING_THRESHOLD}, critical > ${DRIFT_WARNING_THRESHOLD})`,
        remediation:
          'Manually review the description change against the tool\'s actual server-side implementation before trusting it. A meaning-level shift after approval is a strong poisoning signal, even without a syntactic red flag.',
        confidence: Math.min(0.6 + distance, 0.95),
        owaspCategory: 'MCP03:2025 – Tool Poisoning (rug pull sub-technique)',
      },
    ];
  }

  public async batchCheckDrift(
    tools: { tool: MCPToolSchema; serverName: string }[]
  ): Promise<AnalysisPipelineResult> {
    const findings: VulnerabilityFinding[] = [];
    const erroredTools: ErroredTool[] = [];
    for (const { tool, serverName } of tools) {
      try {
        const result = await this.checkDrift(tool, serverName);
        findings.push(...result);
      } catch (err) {
        logger.error(`Drift check failed for tool "${tool.name}" on "${serverName}"`, err);
        erroredTools.push({
          toolName: tool.name,
          serverName,
          stage: 'drift-detection',
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    logger.info(`Drift detection complete: ${findings.length} finding(s), ${erroredTools.length} errored across ${tools.length} tool(s)`);
    return { findings, erroredTools, activeServers: [] };
  }

  private async embed(text: string): Promise<number[]> {
    const result = await this.client.models.embedContent({
      model: 'text-embedding-004',
      contents: text || '(empty description)',
    });
    const values = result.embeddings?.[0]?.values;
    if (!values) {
      throw new Error('Embedding API returned no embedding values');
    }
    return values;
  }

  private cosineDistance(a: number[], b: number[]): number {
    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    if (denom === 0) return 1;
    const similarity = dot / denom;
    return 1 - similarity;
  }
}