import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface SarifResult {
  ruleId?: string;
  level?: 'error' | 'warning' | 'note' | 'none';
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; endLine?: number; startColumn?: number };
    };
  }>;
  properties?: Record<string, unknown>;
}

interface SarifRun {
  tool?: { driver?: { name?: string } };
  results?: SarifResult[];
}

interface SarifLog {
  version?: string;
  runs?: SarifRun[];
}

const LEVEL_TO_SEVERITY: Record<string, string> = {
  error: 'high',
  warning: 'medium',
  note: 'low',
  none: 'info',
};

/**
 * Generic parser for any tool emitting SARIF 2.1.0. Used as the default parser
 * for OPA/Conftest, REUSE, Steampipe, and any "json" tool whose output is SARIF.
 */
export const sarifParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let log: SarifLog;
    try {
      log = JSON.parse(raw);
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    const findings: Finding[] = [];

    for (const run of log.runs ?? []) {
      const tool = run.tool?.driver?.name ?? ctx.stepId;
      for (const r of run.results ?? []) {
        const file = r.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? 'unknown';
        const region = r.locations?.[0]?.physicalLocation?.region;
        const sevSrc = r.level ? LEVEL_TO_SEVERITY[r.level] : 'medium';

        findings.push(
          finalize({
            framework: fx.framework,
            control_ref: r.ruleId ?? ctx.stepId,
            rule_id: `${tool}.${r.ruleId ?? 'unknown'}`,
            severity: applyDefaultSeverity(ctx.manifest, sevSrc, 'medium'),
            status: 'fail',
            modality: 'deterministic',
            source_tool: tool,
            location: {
              file,
              ...(region?.startLine !== undefined && { line: region.startLine }),
              ...(region?.endLine !== undefined && { endLine: region.endLine }),
              ...(region?.startColumn !== undefined && { column: region.startColumn }),
            },
            message: r.message?.text ?? `${r.ruleId ?? 'finding'} from ${tool}`,
            remediation: '',
            cross_framework: fx.cross_framework,
            blocking: ctx.defaultBlocking,
          }),
        );
      }
    }
    return findings;
  },
};
