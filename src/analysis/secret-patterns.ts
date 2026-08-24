/**
 * Shared secret-detection patterns — the single source of truth used by
 * both static-rules.ts (description scanning) and probe-templates.ts
 * (response scanning). Extracted into its own file after v5 revealed that
 * having two copies of these regexes led to one getting fixed and the
 * other staying broken (the `sk_live_` pattern in probe-templates was
 * weaker than the one in static-rules). This file makes that entire bug
 * class impossible to recur.
 */

export interface SecretPattern {
  /** Human-readable label for reports. */
  label: string;
  /** The regex to match against. Always uses word boundaries. */
  pattern: RegExp;
}

/**
 * Individual patterns, exported for cases where the caller needs to know
 * which specific pattern matched (e.g. static-rules.ts).
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  { label: 'Stripe live key', pattern: /\bsk_live_[A-Za-z0-9]{10,}\b/ },
  { label: 'OpenAI / generic sk- key', pattern: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { label: 'GitHub personal access token', pattern: /\bghp_[A-Za-z0-9]{30,}\b/ },
  { label: 'Google API key', pattern: /\bAIza[A-Za-z0-9_-]{30,}\b/ },
];

/**
 * Combined regex — a single match attempt that covers every pattern above.
 * Used by probe-templates.ts's resultParser where we just need a yes/no
 * "was any secret found?" answer, not the individual pattern identity.
 */
export const COMBINED_SECRET_REGEX =
  /\b(sk_live_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AIza[A-Za-z0-9_-]{30,})\b/;
