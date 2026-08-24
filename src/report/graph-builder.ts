import type { DiscoveryResult, VulnerabilityFinding, RiskScore } from '../types/index.js';

export interface GraphNode {
  id: string;
  label: string;
  type: 'server' | 'tool';
  riskLevel: string;
  score?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  summary: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * Builds a graph data structure linking servers, tools, and vulnerability
 * findings for risk visualization. Each server is a node, each tool is a
 * child node, and findings create edges between them.
 */
export function buildGraph(
  discovery: DiscoveryResult,
  findings: VulnerabilityFinding[],
  scores: RiskScore[] = []
): GraphData {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  
  const scoreMap = new Map(scores.map(s => [s.entityName, s.score]));
  const gradeMap = new Map(scores.map(s => [s.entityName, s.grade]));

  for (const server of discovery.servers) {
    nodes.push({
      id: `server-${server.serverName}`,
      label: server.serverName,
      type: 'server',
      riskLevel: gradeMap.get(server.serverName) || 'UNKNOWN',
      score: scoreMap.get(server.serverName),
    });

    for (const tool of server.tools) {
      const toolId = `tool-${server.serverName}-${tool.name}`;
      const toolScore = scores.find(s => s.entityName === tool.name && s.entityType === 'tool');
      nodes.push({
        id: toolId,
        label: tool.name,
        type: 'tool',
        riskLevel: toolScore ? toolScore.grade : 'UNKNOWN',
        score: toolScore?.score,
      });

      edges.push({
        source: `server-${server.serverName}`,
        target: toolId,
        summary: 'exposes tool',
      });
    }
  }

  for (const finding of findings) {
    const toolId = `tool-${finding.serverName}-${finding.toolName}`;
    edges.push({
      source: toolId,
      target: `server-${finding.serverName}`,
      summary: `Finding: ${finding.title} (${finding.severity})`,
    });
  }

  return { nodes, edges };
}
