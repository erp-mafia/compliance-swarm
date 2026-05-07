import { minimatch } from 'minimatch';
import type { Finding } from './schema.js';

export interface SuppressionRule {
  id?: string | undefined;
  control_ref: string;
  path: string;
  justification: string;
  expires?: string | undefined;
  risk_id?: string | undefined;
}

export interface SuppressionResult {
  findings: Finding[];
  expired: SuppressionRule[];
  applied_count: number;
}

const REQUIRED_RISK_ID_FRAMEWORKS = new Set(['iso-27001', 'soc-2']);

export interface SuppressionApplyOptions {
  /** Today's date in ISO YYYY-MM-DD; injectable for tests. */
  today?: string;
  /** Frameworks where suppressions must reference a Risk Register entry. */
  riskIdRequiredFrameworks?: Set<string>;
}

export function applySuppressions(
  findings: Finding[],
  rules: SuppressionRule[],
  opts: SuppressionApplyOptions = {},
): SuppressionResult {
  const today = opts.today ?? new Date().toISOString().slice(0, 10);
  const riskRequired = opts.riskIdRequiredFrameworks ?? REQUIRED_RISK_ID_FRAMEWORKS;

  const expired: SuppressionRule[] = [];
  const validRules: SuppressionRule[] = [];

  for (const rule of rules) {
    if (rule.expires && rule.expires < today) {
      expired.push(rule);
      continue;
    }
    validRules.push(rule);
  }

  let appliedCount = 0;
  const out = findings.map((f) => {
    if (f.status !== 'fail') return f;
    for (const rule of validRules) {
      if (rule.control_ref !== f.control_ref) continue;
      if (!minimatch(f.location.file, rule.path)) continue;
      if (riskRequired.has(f.framework) && !rule.risk_id) {
        // Requires Risk Register binding; do NOT apply.
        continue;
      }
      appliedCount++;
      return {
        ...f,
        status: 'pass' as const,
        blocking: false,
        suppressed_by: rule.id ?? `${rule.control_ref}|${rule.path}`,
      };
    }
    return f;
  });

  return { findings: out, expired, applied_count: appliedCount };
}
