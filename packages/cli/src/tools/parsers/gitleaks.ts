import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser } from './index.js';

interface GitleaksFinding {
  RuleID: string;
  Description: string;
  StartLine?: number;
  EndLine?: number;
  File: string;
  Match?: string;
  Secret?: string;
}

export const gitleaksParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let items: GitleaksFinding[];
    try {
      const parsed: unknown = JSON.parse(raw);
      items = Array.isArray(parsed) ? (parsed as GitleaksFinding[]) : [];
    } catch {
      return [];
    }

    const fx = ctx.manifest.finding_extraction;
    return items.map((g) =>
      finalize({
        framework: fx.framework,
        control_ref: 'V13.3',
        rule_id: `gitleaks.${g.RuleID}`,
        severity: applyDefaultSeverity(ctx.manifest, 'high', 'high'),
        status: 'fail',
        modality: 'deterministic',
        source_tool: 'gitleaks',
        location: {
          file: g.File,
          ...(g.StartLine !== undefined && { line: g.StartLine }),
          ...(g.EndLine !== undefined && { endLine: g.EndLine }),
        },
        message: g.Description,
        evidence: g.Match ?? g.Secret ?? '',
        remediation: 'Rotate the secret immediately and remove it from history (git filter-repo or BFG).',
        cross_framework: fx.cross_framework,
        blocking: ctx.defaultBlocking,
      }),
    );
  },
};
