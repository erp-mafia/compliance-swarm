import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface ScanCodeFile {
  path: string;
  detected_license_expression?: string;
  license_detections?: Array<{ license_expression?: string; matches?: Array<{ score?: number }> }>;
  copyrights?: Array<{ copyright?: string; start_line?: number; end_line?: number }>;
}

interface ScanCodeReport {
  files?: ScanCodeFile[];
}

const HIGH_RISK_LICENSES = new Set([
  'AGPL-3.0',
  'AGPL-3.0-only',
  'AGPL-3.0-or-later',
  'SSPL-1.0',
  'BSL-1.1',
  'GPL-3.0',
  'GPL-3.0-only',
  'GPL-3.0-or-later',
  'GPL-2.0',
  'GPL-2.0-only',
  'GPL-2.0-or-later',
]);

export const scancodeParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: ScanCodeReport;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    const findings: Finding[] = [];

    for (const f of report.files ?? []) {
      const lic = f.detected_license_expression;
      if (!lic) continue;
      const isHighRisk = HIGH_RISK_LICENSES.has(lic) || /AGPL|SSPL|BSL/i.test(lic);
      if (!isHighRisk) continue;

      findings.push(
        finalize({
          framework: fx.framework,
          control_ref: `SPDX:${lic}`,
          rule_id: `scancode.high-risk-license`,
          severity: applyDefaultSeverity(ctx.manifest, 'high', 'high'),
          status: 'fail',
          modality: 'deterministic',
          source_tool: 'scancode',
          location: { file: f.path },
          message: `High-risk license detected: ${lic}`,
          evidence: lic,
          remediation: 'Confirm distribution model is compatible (or replace dependency / dual-license).',
          cross_framework: fx.cross_framework,
          blocking: ctx.defaultBlocking,
        }),
      );
    }
    return findings;
  },
};
