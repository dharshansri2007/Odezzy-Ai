export const GITHUB_URL = 'https://github.com/dharshansri2007/Odezzy-Ai';

export const PIPELINE = [
  {
    id: 'discovery',
    name: 'Discovery',
    desc: 'Real MCP client connections via stdio/HTTP transports, plus a TrueForge registry cross-reference that catches shadow servers not authorized in your platform.',
  },
  {
    id: 'analysis',
    name: 'Analysis',
    badge: '4 layers',
    desc: 'Static regex rules (CWE-1427, CWE-798), declared-schema diff inspection, LLM semantic reading via Gemini 2.5 Flash on Vertex AI, and embedding-based drift detection using text-embedding-004 — four independent analysis layers.',
  },
  {
    id: 'probing',
    name: 'Probing',
    desc: 'Actually calls suspicious tools inside a sandbox with adversarial payloads — prompt injection, secret leaks, schema mismatches, and undeclared params — not just reading descriptions.',
  },
  {
    id: 'scoring',
    name: 'Scoring',
    desc: 'Every finding becomes a weighted risk score (severity × confidence) mapped to A-F grades, with OWASP MCP Top 10 category classification.',
  },
  {
    id: 'attestation',
    name: 'Attestation',
    desc: 'Clean tools get a real Ed25519-signed, hash-chained cryptographic attestation record. Drift detection automatically revokes attestations when a tool\'s behavior changes.',
  },
  {
    id: 'remediation',
    name: 'Remediation',
    desc: 'Proposed fixes pause for real human approval via TrueForge\'s gated tool-call mechanism before anything is quarantined. HumanApprovalToken tracks who authorized what.',
  },
  {
    id: 'report',
    name: 'Report',
    desc: 'Findings, risk scores, grades, attestation state, and quarantine records collected into a single governance report with fail-visible incomplete analysis tracking.',
  },
] as const;

export const COMPARISON: { capability: string; static: string; odezzy: string }[] = [
  {
    capability: 'Tool inspection',
    static: 'Reads descriptions only',
    odezzy: 'Actually probes tools with adversarial payloads',
  },
  {
    capability: 'Cadence',
    static: 'One-time check',
    odezzy: 'Continuous drift monitoring via Vertex AI embeddings',
  },
  {
    capability: 'Trust record',
    static: 'No cryptographic trust record',
    odezzy: 'Ed25519 attestation with auto-revocation',
  },
  {
    capability: 'Remediation',
    static: 'Manual review only',
    odezzy: 'Human-in-the-loop via TrueForge approval gating',
  },
  {
    capability: 'Semantic analysis',
    static: 'Pattern matching only',
    odezzy: 'Gemini 2.5 Flash reads LLM-targeted intent',
  },
  {
    capability: 'Shadow detection',
    static: 'No registry cross-reference',
    odezzy: 'TrueForge registry cross-reference catches unregistered servers',
  },
  {
    capability: 'Access',
    static: 'Enterprise contract required',
    odezzy: 'Open-source, dev-tool scale',
  },
];

export const VULNERABILITY_CATEGORIES = [
  { id: 'undeclared-params', name: 'Undeclared Parameters', icon: '🔓', desc: 'Tools accepting fields not in their declared schema' },
  { id: 'prompt-injection', name: 'Prompt Injection', icon: '💉', desc: 'Hidden HTML comments and role-spoofing payloads targeting LLMs' },
  { id: 'leaked-secrets', name: 'Leaked Secrets', icon: '🔑', desc: 'API keys and credentials exposed in tool descriptions or configs' },
  { id: 'schema-mismatch', name: 'Schema Mismatch', icon: '📋', desc: 'Differences between declared and runtime tool behavior' },
  { id: 'semantic-drift', name: 'Semantic Drift', icon: '📈', desc: 'Tool meaning changes detected via embedding cosine distance' },
  { id: 'shadow-server', name: 'Shadow Server', icon: '👻', desc: 'MCP servers not registered in TrueForge platform registry' },
  { id: 'excessive-permissions', name: 'Excessive Permissions', icon: '⚠️', desc: 'Tools requesting more access than their stated purpose needs' },
] as const;
