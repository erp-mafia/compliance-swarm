import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface PrivadoFlow {
  source?: { id?: string; name?: string; sourceType?: string; lineNumber?: number; fileName?: string };
  sink?: { id?: string; name?: string; nodeType?: string; lineNumber?: number; fileName?: string };
  pathSize?: number;
  isInferred?: boolean;
}

interface PrivadoFinding {
  flowName?: string;
  category?: string;
  flows?: PrivadoFlow[];
}

interface PrivadoReport {
  dataflows?: Record<string, PrivadoFinding>;
  violations?: Array<{
    policyId: string;
    policyName: string;
    severity: string;
    message: string;
    affectedDataElements?: string[];
    file?: string;
    line?: number;
  }>;
}

export const privadoParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: PrivadoReport;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    const findings: Finding[] = [];

    // Privado violations have explicit policy mapping → straight conversion.
    for (const v of report.violations ?? []) {
      findings.push(
        finalize({
          framework: fx.framework,
          control_ref: v.policyId,
          rule_id: `privado.${v.policyId}`,
          severity: applyDefaultSeverity(ctx.manifest, v.severity, 'medium'),
          status: 'fail',
          modality: 'deterministic',
          source_tool: 'privado',
          location: { file: v.file ?? 'data-flow', ...(v.line && { line: v.line }) },
          message: v.message,
          evidence: (v.affectedDataElements ?? []).join(', '),
          remediation: 'Update RoPA or restrict the data flow.',
          cross_framework: fx.cross_framework,
          blocking: ctx.defaultBlocking,
        }),
      );
    }

    // Dataflows: inform but don't block by default.
    for (const [flowKey, df] of Object.entries(report.dataflows ?? {})) {
      for (const flow of df.flows ?? []) {
        if (!flow.source || !flow.sink) continue;
        findings.push(
          finalize({
            framework: fx.framework,
            control_ref: 'Art.30',
            rule_id: `privado.flow.${flowKey}`,
            severity: applyDefaultSeverity(ctx.manifest, 'info', 'info'),
            status: 'fail',
            modality: 'deterministic',
            source_tool: 'privado',
            location: {
              file: flow.sink.fileName ?? flow.source.fileName ?? 'unknown',
              ...(flow.sink.lineNumber && { line: flow.sink.lineNumber }),
            },
            message: `Data flow: ${flow.source.name ?? flow.source.id} → ${flow.sink.name ?? flow.sink.id}`,
            remediation: 'Verify this flow is documented in RoPA.',
            cross_framework: fx.cross_framework,
            blocking: false,
          }),
        );
      }
    }

    return findings;
  },
};
