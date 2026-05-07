import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface OrtViolation {
  rule: string;
  pkg?: string;
  license?: string;
  license_source?: string;
  severity: 'ERROR' | 'WARNING' | 'HINT';
  message: string;
  how_to_fix?: string;
}

interface OrtEvaluatorOutput {
  evaluator?: { violations?: OrtViolation[] };
}

export const ortParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: OrtEvaluatorOutput;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    return (report.evaluator?.violations ?? []).map((v) =>
      finalize({
        framework: fx.framework,
        control_ref: v.license ? `SPDX:${v.license}` : v.rule,
        rule_id: `ort.${v.rule}`,
        severity: applyDefaultSeverity(
          ctx.manifest,
          v.severity === 'ERROR' ? 'critical' : v.severity === 'WARNING' ? 'high' : 'medium',
          'high',
        ),
        status: 'fail',
        modality: 'deterministic',
        source_tool: 'ort',
        location: { file: v.pkg ? `dependency:${v.pkg}` : 'manifest' },
        message: v.message,
        remediation: v.how_to_fix ?? 'See ORT rule guidance in rules.kts.',
        cross_framework: fx.cross_framework,
        blocking: ctx.defaultBlocking,
      }),
    );
  },
};
