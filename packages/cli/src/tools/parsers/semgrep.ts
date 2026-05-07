import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col?: number };
  end?: { line: number };
  extra: {
    message: string;
    severity: string; // ERROR | WARNING | INFO
    metadata?: Record<string, unknown>;
    fix?: string;
    lines?: string;
  };
}

interface SemgrepReport {
  results?: SemgrepResult[];
  errors?: Array<{ message: string }>;
}

export const semgrepParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: SemgrepReport;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    const findings: Finding[] = [];
    for (const r of report.results ?? []) {
      const meta = r.extra.metadata ?? {};
      const cwe = Array.isArray(meta.cwe) ? meta.cwe.join(',') : (meta.cwe as string | undefined);
      const owasp = Array.isArray(meta.owasp) ? meta.owasp[0] : (meta.owasp as string | undefined);
      const asvsRef = (meta as { asvs?: string }).asvs;
      const controlRef = asvsRef ?? owasp ?? cwe ?? r.check_id;

      findings.push(
        finalize({
          framework: fx.framework,
          control_ref: controlRef,
          rule_id: `semgrep.${r.check_id}`,
          severity: applyDefaultSeverity(ctx.manifest, r.extra.severity, 'medium'),
          status: 'fail',
          modality: 'deterministic',
          source_tool: 'semgrep',
          location: {
            file: r.path,
            line: r.start.line,
            ...(r.end?.line !== undefined && { endLine: r.end.line }),
            ...(r.start.col !== undefined && { column: r.start.col }),
          },
          message: r.extra.message,
          evidence: r.extra.lines ?? '',
          remediation: r.extra.fix ?? '',
          cross_framework: fx.cross_framework,
          blocking: ctx.defaultBlocking,
        }),
      );
    }
    return findings;
  },
};
