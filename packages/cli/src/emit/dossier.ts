import type { Finding } from '../findings/schema.js';
import type { MergedFinding } from '../findings/dedup.js';
import type { SuppressionRule } from '../findings/suppress.js';

export interface Dossier {
  schema_version: '0.1';
  generated_at: string;
  mode: 'pr' | 'swarm';
  exit_code: 0 | 1 | 2;
  summary: {
    total: number;
    by_status: Record<string, number>;
    by_severity: Record<string, number>;
    by_framework: Record<string, number>;
    blocking: number;
  };
  findings: Array<Finding | MergedFinding>;
  expired_suppressions: SuppressionRule[];
  suppressions_applied: number;
  skills_executed: string[];
  errors: Array<{ skill: string; message: string }>;
}

export interface DossierInput {
  mode: 'pr' | 'swarm';
  exit_code: 0 | 1 | 2;
  findings: Array<Finding | MergedFinding>;
  expired_suppressions: SuppressionRule[];
  suppressions_applied: number;
  skills_executed: string[];
  errors: Array<{ skill: string; message: string }>;
}

export function toDossier(input: DossierInput): Dossier {
  const summary = {
    total: input.findings.length,
    by_status: tally(input.findings, (f) => f.status),
    by_severity: tally(input.findings, (f) => f.severity),
    by_framework: tally(input.findings, (f) => f.framework),
    blocking: input.findings.filter((f) => f.blocking && f.status === 'fail').length,
  };
  return {
    schema_version: '0.1',
    generated_at: new Date().toISOString(),
    mode: input.mode,
    exit_code: input.exit_code,
    summary,
    findings: input.findings,
    expired_suppressions: input.expired_suppressions,
    suppressions_applied: input.suppressions_applied,
    skills_executed: input.skills_executed,
    errors: input.errors,
  };
}

function tally<T>(items: T[], by: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) {
    const k = by(it);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
