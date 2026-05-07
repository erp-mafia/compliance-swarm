import { describe, expect, it } from 'vitest';
import { finalize, type Finding } from '../../src/findings/schema.js';
import { dedup } from '../../src/findings/dedup.js';
import { toSarif } from '../../src/emit/sarif.js';
import { toMarkdown } from '../../src/emit/markdown.js';
import { toDossier } from '../../src/emit/dossier.js';

const fAsvs: Finding = finalize({
  framework: 'asvs',
  control_ref: 'V13.3',
  rule_id: 'gitleaks.aws-key',
  severity: 'critical',
  status: 'fail',
  modality: 'deterministic',
  source_tool: 'gitleaks',
  location: { file: 'src/secret.ts', line: 12 },
  message: 'AWS access key in source',
  evidence: 'AKIA...',
  remediation: 'Rotate the key.',
  cross_framework: [{ tag: 'soc-2', control: 'CC6.1' }],
  blocking: true,
});

const fGdpr: Finding = finalize({
  framework: 'gdpr',
  control_ref: 'Art.5(1)(f)',
  rule_id: 'semgrep.email-log',
  severity: 'medium',
  status: 'fail',
  modality: 'deterministic',
  source_tool: 'semgrep',
  location: { file: 'src/api.ts', line: 99 },
  message: 'Logging email in plaintext.',
  evidence: 'logger.info(user.email)',
  remediation: 'Redact PII.',
  cross_framework: [{ tag: 'asvs', control: 'V16.1' }],
  blocking: false,
});

describe('SARIF emitter', () => {
  it('emits valid SARIF 2.1.0 with one run per framework', () => {
    const log = toSarif([fAsvs, fGdpr]);
    expect(log.version).toBe('2.1.0');
    expect(log.runs).toHaveLength(2);

    const asvsRun = log.runs.find((r) => r.tool.driver.name.includes('asvs'));
    const gdprRun = log.runs.find((r) => r.tool.driver.name.includes('gdpr'));
    expect(asvsRun).toBeDefined();
    expect(gdprRun).toBeDefined();
    expect(asvsRun?.results).toHaveLength(1);
    expect(asvsRun?.results[0]?.ruleId).toBe('asvs/V13.3');
    expect(asvsRun?.results[0]?.level).toBe('error');
    expect(gdprRun?.results[0]?.level).toBe('warning');
  });

  it('marks suppressed findings level=none with suppressions block', () => {
    const suppressed = finalize({
      ...fAsvs,
      status: 'pass',
      blocking: false,
      suppressed_by: 'rule-1',
    });
    const log = toSarif([suppressed]);
    expect(log.runs[0]?.results[0]?.level).toBe('none');
    expect(log.runs[0]?.results[0]?.suppressions).toBeDefined();
  });

  it('round-trips merged findings with related_controls', () => {
    const merged = dedup([
      fAsvs,
      finalize({
        ...fAsvs,
        framework: 'soc-2',
        control_ref: 'CC6.1',
        rule_id: 'checkov.iam',
        source_tool: 'checkov',
        cross_framework: [{ tag: 'asvs', control: 'V13.3' }],
      }),
    ]);
    expect(merged).toHaveLength(1);
    const log = toSarif(merged);
    const result = log.runs[0]?.results[0];
    expect(result?.properties.related_controls).toBeDefined();
  });
});

describe('Markdown emitter', () => {
  it('produces a clean-state summary when no active findings', () => {
    const passed = finalize({ ...fAsvs, status: 'pass', blocking: false });
    const md = toMarkdown([passed], { mode: 'pr' });
    expect(md).toContain('No active findings');
  });

  it('lists active findings grouped by framework', () => {
    const md = toMarkdown([fAsvs, fGdpr], { mode: 'pr' });
    expect(md).toContain('OWASP ASVS v5');
    expect(md).toContain('GDPR');
    expect(md).toContain('V13.3');
    expect(md).toContain('Art.5(1)(f)');
    expect(md).toContain('Rotate the key');
  });

  it('respects GitHub byte limit', () => {
    const big = Array.from({ length: 500 }, (_, i) =>
      finalize({ ...fAsvs, location: { file: `src/file${i}.ts`, line: i }, message: 'x'.repeat(500) }),
    );
    const md = toMarkdown(big, { mode: 'pr' });
    expect(Buffer.byteLength(md, 'utf8')).toBeLessThanOrEqual(60_000);
  });

  it('warns about expired suppressions', () => {
    const md = toMarkdown([fAsvs], { mode: 'pr', expiredSuppressionCount: 2 });
    expect(md).toContain('expired suppression');
  });
});

describe('Dossier emitter', () => {
  it('builds a structured JSON report', () => {
    const dossier = toDossier({
      mode: 'swarm',
      exit_code: 1,
      findings: [fAsvs, fGdpr],
      expired_suppressions: [],
      suppressions_applied: 0,
      skills_executed: ['asvs', 'gdpr'],
      errors: [],
    });
    expect(dossier.schema_version).toBe('0.1');
    expect(dossier.summary.total).toBe(2);
    expect(dossier.summary.by_framework).toEqual({ asvs: 1, gdpr: 1 });
    expect(dossier.summary.by_severity).toEqual({ critical: 1, medium: 1 });
    expect(dossier.summary.blocking).toBe(1);
    expect(dossier.skills_executed).toEqual(['asvs', 'gdpr']);
  });
});
