import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface HelsinkiViolation {
  rule: string;
  url?: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence?: string;
}

interface HelsinkiReport {
  url: string;
  violations?: HelsinkiViolation[];
}

export const helsinkiParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: HelsinkiReport;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    return (report.violations ?? []).map((v) =>
      finalize({
        framework: fx.framework,
        control_ref: 'Art.6(1)(a)',
        rule_id: `helsinki.${v.rule}`,
        severity: applyDefaultSeverity(ctx.manifest, v.severity, 'high'),
        status: 'fail',
        modality: 'deterministic',
        source_tool: 'helsinki',
        location: { file: v.url ?? report.url ?? 'frontend' },
        message: v.description,
        evidence: v.evidence ?? '',
        remediation: 'Block the script until consent is granted; review CMP integration.',
        cross_framework: fx.cross_framework,
        blocking: ctx.defaultBlocking,
      }),
    );
  },
};
