import { finalize, type Finding } from '../../findings/schema.js';
import { applyDefaultSeverity, type Parser, type ParseContext } from './index.js';

interface TrivyResult {
  Target: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: Array<{
    VulnerabilityID: string;
    PkgName: string;
    InstalledVersion?: string;
    FixedVersion?: string;
    Severity: string;
    Title?: string;
    Description?: string;
    PrimaryURL?: string;
  }>;
  Misconfigurations?: Array<{
    ID: string;
    AVDID?: string;
    Severity: string;
    Title: string;
    Description?: string;
    Resolution?: string;
    CauseMetadata?: { StartLine?: number; EndLine?: number; Resource?: string };
    PrimaryURL?: string;
  }>;
  Secrets?: Array<{
    RuleID: string;
    Severity: string;
    Title?: string;
    Match?: string;
    StartLine?: number;
    EndLine?: number;
  }>;
}

interface TrivyReport {
  Results?: TrivyResult[];
}

export const trivyParser: Parser = {
  parse(raw, ctx) {
    if (!raw.trim()) return [];
    let report: TrivyReport;
    try {
      report = JSON.parse(raw);
    } catch {
      return [];
    }

    const findings: Finding[] = [];
    for (const r of report.Results ?? []) {
      const file = r.Target;
      for (const v of r.Vulnerabilities ?? []) {
        findings.push(toFinding(ctx, {
          rule_id: `trivy.${v.VulnerabilityID}`,
          severity: v.Severity,
          message: `${v.VulnerabilityID} in ${v.PkgName}@${v.InstalledVersion ?? '?'}: ${v.Title ?? v.Description ?? ''}`.trim(),
          remediation: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion}` : 'See advisory.',
          file,
          control_ref: 'V13.1', // overridden by manifest cross_framework when applicable
        }));
      }
      for (const m of r.Misconfigurations ?? []) {
        findings.push(toFinding(ctx, {
          rule_id: `trivy.${m.ID}`,
          severity: m.Severity,
          message: m.Title + (m.Description ? ` — ${m.Description}` : ''),
          remediation: m.Resolution ?? '',
          file,
          line: m.CauseMetadata?.StartLine,
          endLine: m.CauseMetadata?.EndLine,
          control_ref: m.AVDID ?? m.ID,
        }));
      }
      for (const s of r.Secrets ?? []) {
        findings.push(toFinding(ctx, {
          rule_id: `trivy.${s.RuleID}`,
          severity: s.Severity,
          message: s.Title ?? `Secret detected: ${s.RuleID}`,
          remediation: 'Rotate the secret and remove from source.',
          file,
          line: s.StartLine,
          endLine: s.EndLine,
          control_ref: 'V13.3',
        }));
      }
    }
    return findings;
  },
};

function toFinding(
  ctx: ParseContext,
  input: {
    rule_id: string;
    severity: string;
    message: string;
    remediation: string;
    file: string;
    line?: number | undefined;
    endLine?: number | undefined;
    control_ref: string;
  },
): Finding {
  const fx = ctx.manifest.finding_extraction;
  return finalize({
    framework: fx.framework,
    control_ref: input.control_ref,
    rule_id: input.rule_id,
    severity: applyDefaultSeverity(ctx.manifest, input.severity, 'medium'),
    status: 'fail',
    modality: 'deterministic',
    source_tool: 'trivy',
    location: {
      file: input.file,
      ...(input.line !== undefined && { line: input.line }),
      ...(input.endLine !== undefined && { endLine: input.endLine }),
    },
    message: input.message,
    remediation: input.remediation,
    cross_framework: fx.cross_framework,
    blocking: ctx.defaultBlocking,
  });
}
