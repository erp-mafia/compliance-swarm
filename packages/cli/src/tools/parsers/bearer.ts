import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface BearerFinding {
  id: string;
  rule_id?: string;
  cwe_ids?: string[];
  severity: string; // critical | high | medium | low | warning
  title: string;
  description?: string;
  filename: string;
  line_number: number;
  full_filename?: string;
  fingerprint?: string;
}

interface BearerReport {
  critical?: BearerFinding[];
  high?: BearerFinding[];
  medium?: BearerFinding[];
  low?: BearerFinding[];
  warning?: BearerFinding[];
}

export const bearerParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: BearerReport;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    const all = [
      ...(report.critical ?? []).map((f) => ({ ...f, _bucket: 'critical' })),
      ...(report.high ?? []).map((f) => ({ ...f, _bucket: 'high' })),
      ...(report.medium ?? []).map((f) => ({ ...f, _bucket: 'medium' })),
      ...(report.low ?? []).map((f) => ({ ...f, _bucket: 'low' })),
      ...(report.warning ?? []).map((f) => ({ ...f, _bucket: 'low' })),
    ];

    return all.map((b) =>
      finalize({
        framework: fx.framework,
        control_ref: b.rule_id ?? b.id,
        rule_id: `bearer.${b.id}`,
        severity: applyDefaultSeverity(ctx.manifest, b._bucket, 'medium'),
        status: 'fail',
        modality: 'deterministic',
        source_tool: 'bearer',
        location: { file: b.full_filename ?? b.filename, line: b.line_number },
        message: b.title + (b.description ? ` — ${b.description}` : ''),
        remediation: 'See Bearer rule documentation.',
        cross_framework: fx.cross_framework,
        blocking: ctx.defaultBlocking,
      }),
    );
  },
};
