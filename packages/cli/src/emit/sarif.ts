import type { Finding, Severity } from '../findings/schema.js';
import type { MergedFinding } from '../findings/dedup.js';

const SEVERITY_TO_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  info: 'note',
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: {
    framework: string;
    control_ref: string;
    cross_framework: Array<{ tag: string; control: string }>;
    modality: string;
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number; endLine?: number };
    };
  }>;
  partialFingerprints: { primaryLocationLineHash?: string; complianceFindingId: string };
  properties: {
    severity: string;
    status: string;
    suppressed_by?: string;
    related_controls?: Array<{ framework: string; control_ref: string }>;
  };
  suppressions?: Array<{ kind: 'inSource' | 'external'; justification: string }>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export function toSarif(findings: Array<Finding | MergedFinding>, version = '0.1.0'): SarifLog {
  const byFramework = new Map<string, Array<Finding | MergedFinding>>();
  for (const f of findings) {
    const arr = byFramework.get(f.framework) ?? [];
    arr.push(f);
    byFramework.set(f.framework, arr);
  }

  const runs: SarifRun[] = [];
  for (const [framework, items] of byFramework) {
    const rulesMap = new Map<string, SarifRule>();
    const results: SarifResult[] = [];

    for (const f of items) {
      const ruleId = `${framework}/${f.control_ref}`;
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: f.control_ref,
          shortDescription: { text: `${framework.toUpperCase()} ${f.control_ref}` },
          fullDescription: { text: f.message || `${framework} ${f.control_ref} requirement` },
          defaultConfiguration: { level: SEVERITY_TO_LEVEL[f.severity] },
          properties: {
            framework,
            control_ref: f.control_ref,
            cross_framework: f.cross_framework,
            modality: f.modality,
          },
        });
      }

      const result: SarifResult = {
        ruleId,
        level: f.status === 'pass' ? 'none' : SEVERITY_TO_LEVEL[f.severity],
        message: { text: f.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.location.file },
              ...(f.location.line !== undefined && {
                region: {
                  startLine: f.location.line || 1,
                  ...(f.location.endLine !== undefined && { endLine: f.location.endLine }),
                  ...(f.location.column !== undefined && { startColumn: f.location.column }),
                },
              }),
            },
          },
        ],
        partialFingerprints: { complianceFindingId: f.id },
        properties: {
          severity: f.severity,
          status: f.status,
          ...(f.suppressed_by && { suppressed_by: f.suppressed_by }),
          ...('related_controls' in f && { related_controls: f.related_controls }),
        },
        ...(f.suppressed_by && {
          suppressions: [{ kind: 'external', justification: `Suppressed by rule: ${f.suppressed_by}` }],
        }),
      };
      results.push(result);
    }

    runs.push({
      tool: {
        driver: {
          name: `compliance-swarm:${framework}`,
          version,
          informationUri: 'https://github.com/erp-mafia/erp-base',
          rules: Array.from(rulesMap.values()),
        },
      },
      results,
    });
  }

  return {
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs,
  };
}
