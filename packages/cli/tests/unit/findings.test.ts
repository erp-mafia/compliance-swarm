import { describe, expect, it } from 'vitest';
import { dedup } from '../../src/findings/dedup.js';
import { finalize, type Finding, makeFindingId, meetsThreshold } from '../../src/findings/schema.js';
import { applySuppressions } from '../../src/findings/suppress.js';

function fixture(overrides: Partial<Finding>): Finding {
  return finalize({
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
    remediation: 'Rotate the key and move to env vars.',
    cross_framework: [
      { tag: 'soc-2', control: 'CC6.1' },
      { tag: 'iso-27001', control: 'A.8.24' },
    ],
    blocking: true,
    ...overrides,
  });
}

describe('finalize / id', () => {
  it('produces stable ids for identical findings', () => {
    const a = fixture({});
    const b = fixture({});
    expect(a.id).toBe(b.id);
  });
  it('produces distinct ids when location differs', () => {
    const a = fixture({});
    const b = fixture({ location: { file: 'src/secret.ts', line: 13 } });
    expect(a.id).not.toBe(b.id);
  });
  it('makeFindingId is deterministic', () => {
    const id = makeFindingId({
      framework: 'gdpr',
      control_ref: 'Art.5(1)(f)',
      rule_id: 'semgrep.email-log',
      source_tool: 'semgrep',
      location: { file: 'a.ts', line: 1 },
    });
    expect(id).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('meetsThreshold', () => {
  it.each([
    ['critical', 'high', true],
    ['high', 'high', true],
    ['medium', 'high', false],
    ['critical', 'low', true],
    ['info', 'low', false],
  ] as const)('%s vs threshold %s = %s', (sev, thr, expected) => {
    expect(meetsThreshold(sev, thr)).toBe(expected);
  });
});

describe('dedup', () => {
  it('keeps unrelated findings separate', () => {
    const a = fixture({});
    const b = fixture({
      framework: 'gdpr',
      control_ref: 'Art.5(1)(f)',
      rule_id: 'semgrep.email-log',
      source_tool: 'semgrep',
      location: { file: 'src/api.ts', line: 99 },
      cross_framework: [],
    });
    const result = dedup([a, b]);
    expect(result).toHaveLength(2);
  });

  it('collapses exact duplicates from the same tool', () => {
    const a = fixture({});
    const b = fixture({});
    const result = dedup([a, b]);
    expect(result).toHaveLength(1);
  });

  it('merges cross-framework matches at the same location', () => {
    const aws = fixture({}); // asvs V13.3 with cross_framework to soc-2 CC6.1
    const soc2Same = fixture({
      framework: 'soc-2',
      control_ref: 'CC6.1',
      rule_id: 'checkov.iam',
      source_tool: 'checkov',
      cross_framework: [{ tag: 'asvs', control: 'V13.3' }],
    });
    const result = dedup([aws, soc2Same]);
    expect(result).toHaveLength(1);
    const [merged] = result;
    expect(merged?.related_controls).toEqual([
      { framework: 'asvs', control_ref: 'V13.3' },
      { framework: 'soc-2', control_ref: 'CC6.1' },
    ]);
    // Cross-framework union should include both originals
    const tags = new Set(merged?.cross_framework.map((c) => `${c.tag}/${c.control}`));
    expect(tags.has('soc-2/CC6.1')).toBe(true);
    expect(tags.has('iso-27001/A.8.24')).toBe(true);
  });

  it('does not merge cross-framework matches at different locations', () => {
    const a = fixture({ location: { file: 'a.ts', line: 1 } });
    const b = fixture({
      framework: 'soc-2',
      control_ref: 'CC6.1',
      rule_id: 'checkov.iam',
      source_tool: 'checkov',
      location: { file: 'b.ts', line: 5 },
      cross_framework: [{ tag: 'asvs', control: 'V13.3' }],
    });
    const result = dedup([a, b]);
    expect(result).toHaveLength(2);
  });

  it('preserves the highest severity when collapsing exact dupes', () => {
    const a = fixture({ severity: 'low' });
    const b = fixture({ severity: 'critical' });
    const result = dedup([a, b]);
    expect(result[0]?.severity).toBe('critical');
  });

  it('promotes blocking when any merged finding was blocking', () => {
    const a = fixture({ blocking: false, severity: 'high' });
    const b = fixture({ blocking: true, severity: 'low' });
    const result = dedup([a, b]);
    expect(result[0]?.blocking).toBe(true);
  });
});

describe('applySuppressions', () => {
  it('applies a matching, unexpired suppression', () => {
    const finding = fixture({
      framework: 'asvs',
      control_ref: 'V13.3',
      location: { file: 'extensions/example-logger/log.ts', line: 4 },
    });
    const result = applySuppressions(
      [finding],
      [
        {
          id: 'r1',
          control_ref: 'V13.3',
          path: 'extensions/example-logger/**',
          justification: 'Reference impl',
          expires: '2099-01-01',
        },
      ],
      { today: '2026-05-07' },
    );
    expect(result.findings[0]?.status).toBe('pass');
    expect(result.findings[0]?.blocking).toBe(false);
    expect(result.findings[0]?.suppressed_by).toBe('r1');
    expect(result.applied_count).toBe(1);
  });

  it('reports expired rules and does not apply them', () => {
    const finding = fixture({});
    const expired = {
      control_ref: 'V13.3',
      path: 'src/**',
      justification: 'old',
      expires: '2020-01-01',
    };
    const result = applySuppressions([finding], [expired], { today: '2026-05-07' });
    expect(result.findings[0]?.status).toBe('fail');
    expect(result.expired).toEqual([expired]);
  });

  it('rejects ISO/SOC2 suppressions without risk_id', () => {
    const finding = fixture({
      framework: 'iso-27001',
      control_ref: 'A.8.24',
      location: { file: 'tf/main.tf', line: 10 },
    });
    const noRiskId = applySuppressions(
      [finding],
      [{ control_ref: 'A.8.24', path: 'tf/**', justification: 'pending' }],
    );
    expect(noRiskId.findings[0]?.status).toBe('fail'); // not applied
    const withRiskId = applySuppressions(
      [finding],
      [{ control_ref: 'A.8.24', path: 'tf/**', justification: 'pending', risk_id: 'RISK-1' }],
    );
    expect(withRiskId.findings[0]?.status).toBe('pass');
  });

  it('does not suppress findings outside the path glob', () => {
    const finding = fixture({ location: { file: 'src/core/secret.ts', line: 1 } });
    const result = applySuppressions(
      [finding],
      [{ control_ref: 'V13.3', path: 'extensions/**', justification: 'x' }],
    );
    expect(result.findings[0]?.status).toBe('fail');
  });
});
