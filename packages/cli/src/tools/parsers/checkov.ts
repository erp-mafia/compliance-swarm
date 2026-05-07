import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface CheckovFailedCheck {
  check_id: string;
  bc_check_id?: string;
  check_name: string;
  check_result: { result: 'FAILED' | 'PASSED' };
  file_path: string;
  file_line_range?: [number, number];
  resource: string;
  severity?: string;
  guideline?: string;
}

interface CheckovReport {
  results?: { failed_checks?: CheckovFailedCheck[] };
  // Newer multi-runner format wraps in arrays; handle both.
}

type CheckovInput = CheckovReport | CheckovReport[];

export const checkovParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: CheckovInput;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const reports = Array.isArray(report) ? report : [report];
    const findings: Finding[] = [];
    const fx = ctx.manifest.finding_extraction;

    for (const r of reports) {
      for (const c of r.results?.failed_checks ?? []) {
        const range = c.file_line_range ?? [1, 1];
        findings.push(
          finalize({
            framework: fx.framework,
            control_ref: c.check_id,
            rule_id: `checkov.${c.check_id}`,
            severity: applyDefaultSeverity(ctx.manifest, c.severity ?? 'medium', 'medium'),
            status: 'fail',
            modality: 'deterministic',
            source_tool: 'checkov',
            location: { file: c.file_path, line: range[0], endLine: range[1] },
            message: `${c.check_name} (${c.resource})`,
            remediation: c.guideline ?? 'See Checkov guideline.',
            cross_framework: fx.cross_framework,
            blocking: ctx.defaultBlocking,
          }),
        );
      }
    }
    return findings;
  },
};
