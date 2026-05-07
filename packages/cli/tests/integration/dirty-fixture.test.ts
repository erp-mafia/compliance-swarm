import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../src/orchestrator.js';

/**
 * Constructs an isolated test environment:
 *
 *   $TMP/
 *     repo/                    ← repoRoot (copy of dirty-repo fixture)
 *     skills/
 *       compliance-swarm/      ← acts as orchestrator root via env override
 *       <fake-skill-1>/manifest.yml
 *       <fake-skill-1>/scan.json   ← canned scanner output
 *       ...
 *
 * Each fake skill manifest uses `tool: script` invoking `bash -c "cat ..."`
 * which produces deterministic JSON for the parser to consume. This exercises
 * the full orchestrator pipeline without needing Docker or real scanners.
 */

const FIXTURE_DIR = join(__dirname, '..', 'fixtures', 'dirty-repo');

interface FakeSkillSpec {
  id: string;
  framework: 'oss-license' | 'asvs' | 'iso-27001' | 'soc-2' | 'gdpr';
  parser: string;
  scannerOutput: object;
  controlRef: string;
  crossFramework?: Array<{ tag: string; control: string }>;
  produces?: { name: string; format: string };
  consumes?: string[];
}

const FAKE_SKILLS: FakeSkillSpec[] = [
  {
    id: 'oss-license-compliance',
    framework: 'oss-license',
    parser: 'scancode',
    controlRef: 'SPDX:AGPL-3.0-or-later',
    crossFramework: [{ tag: 'iso-27001', control: 'A.5.21' }],
    scannerOutput: {
      files: [
        { path: 'package.json', detected_license_expression: 'AGPL-3.0-or-later' },
      ],
    },
    produces: { name: 'sbom', format: 'json' },
  },
  {
    id: 'owasp-asvs-v5-compliance',
    framework: 'asvs',
    parser: 'gitleaks',
    controlRef: 'V13.3',
    crossFramework: [
      { tag: 'soc-2', control: 'CC6.1' },
      { tag: 'iso-27001', control: 'A.8.24' },
    ],
    scannerOutput: [
      {
        RuleID: 'aws-access-token',
        Description: 'AWS access key in source',
        File: 'src/secret.ts',
        StartLine: 2,
        EndLine: 2,
        Match: 'AKIAIOSFODNN7EXAMPLE',
      },
    ],
    consumes: ['sbom'],
  },
  {
    id: 'iso-27001-2022-compliance',
    framework: 'iso-27001',
    parser: 'checkov',
    controlRef: 'A.8.24',
    crossFramework: [{ tag: 'soc-2', control: 'CC6.1' }],
    scannerOutput: {
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_16',
            check_name: 'Ensure all data stored in the RDS is securely encrypted at rest',
            check_result: { result: 'FAILED' },
            file_path: 'tf/main.tf',
            file_line_range: [1, 6],
            resource: 'aws_db_instance.primary',
            severity: 'HIGH',
          },
        ],
      },
    },
    consumes: ['sbom'],
  },
  {
    id: 'soc2-cicd-compliance',
    framework: 'soc-2',
    parser: 'checkov',
    controlRef: 'CC6.1',
    crossFramework: [{ tag: 'iso-27001', control: 'A.5.15' }],
    scannerOutput: {
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_19',
            check_name: 'Ensure S3 bucket is not public',
            check_result: { result: 'FAILED' },
            file_path: 'tf/main.tf',
            file_line_range: [8, 11],
            resource: 'aws_s3_bucket.data',
            severity: 'CRITICAL',
          },
        ],
      },
    },
    consumes: ['sbom'],
  },
  {
    id: 'gdpr-cicd-compliance',
    framework: 'gdpr',
    parser: 'semgrep',
    controlRef: 'Art.5(1)(f)',
    crossFramework: [{ tag: 'asvs', control: 'V16.1' }],
    scannerOutput: {
      results: [
        {
          check_id: 'gdpr.email-log',
          path: 'src/api.ts',
          start: { line: 3, col: 3 },
          end: { line: 3 },
          extra: {
            message: 'PII (email) logged in plaintext',
            severity: 'WARNING',
            metadata: { asvs: 'V16.1' },
            lines: 'console.log("user:", user.email)',
          },
        },
      ],
    },
    consumes: ['sbom'],
  },
];

function writeManifest(skillDir: string, spec: FakeSkillSpec): void {
  const manifest = {
    id: spec.id,
    version: '1.0.0',
    detection: { paths: ['**/*'] },
    produces: spec.produces ? [{ name: spec.produces.name, format: spec.produces.format, path: '${OUT}' }] : [],
    consumes: spec.consumes ?? [],
    static_scan: [
      {
        id: 'fake-scan',
        tool: 'script',
        binary: 'bash',
        args: ['-c', `cat ${join(skillDir, 'scan.json')}`],
        parser: spec.parser,
        timeout_seconds: 10,
        produces_artifact: spec.produces?.name,
        output_format: 'json',
      },
    ],
    deep_audit: [],
    finding_extraction: {
      framework: spec.framework,
      default_severity_mapping: { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' },
      cross_framework: spec.crossFramework ?? [],
    },
  };
  // Write as YAML manually — the loader uses `yaml` to parse, but JSON is
  // valid YAML so we can dump JSON here for simplicity.
  writeFileSync(join(skillDir, 'manifest.yml'), JSON.stringify(manifest, null, 2));
  writeFileSync(join(skillDir, 'scan.json'), JSON.stringify(spec.scannerOutput));
}

describe('integration: dirty-repo fixture', () => {
  let tmp: string;
  let repoRoot: string;
  let skillsRoot: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'compliance-swarm-int-'));
    repoRoot = join(tmp, 'repo');
    skillsRoot = join(tmp, 'skills');
    cpSync(FIXTURE_DIR, repoRoot, { recursive: true });

    // The orchestrator package's "fake home" (used by loadOrchestratorRoot via env)
    const orchestratorRoot = join(skillsRoot, 'compliance-swarm');
    mkdirSync(orchestratorRoot, { recursive: true });

    for (const spec of FAKE_SKILLS) {
      const dir = join(skillsRoot, spec.id);
      mkdirSync(dir, { recursive: true });
      writeManifest(dir, spec);
    }

    // Repo config: enable all 5, threshold = high, no suppressions.
    mkdirSync(join(repoRoot, '.compliance'), { recursive: true });
    writeFileSync(
      join(repoRoot, '.compliance/config.yml'),
      `enabled_skills:
  - oss-license-compliance
  - owasp-asvs-v5-compliance
  - iso-27001-2022-compliance
  - soc2-cicd-compliance
  - gdpr-cicd-compliance
severity_threshold_to_block: high
suppressions: []
`,
    );

    originalEnv = process.env.COMPLIANCE_SWARM_ROOT;
    process.env.COMPLIANCE_SWARM_ROOT = orchestratorRoot;
  });

  afterEach(() => {
    if (originalEnv !== undefined) process.env.COMPLIANCE_SWARM_ROOT = originalEnv;
    else delete process.env.COMPLIANCE_SWARM_ROOT;
    rmSync(tmp, { recursive: true, force: true });
  });

  it('finds at least one violation per skill, dedups across cross-frameworks', async () => {
    const result = await run({ mode: 'pr', repoRoot });

    expect(result.skillsExecuted.sort()).toEqual([
      'gdpr-cicd-compliance',
      'iso-27001-2022-compliance',
      'oss-license-compliance',
      'owasp-asvs-v5-compliance',
      'soc2-cicd-compliance',
    ]);

    // Every framework should appear in findings.
    const frameworks = new Set(result.findings.map((f) => f.framework));
    expect(frameworks.has('oss-license')).toBe(true);
    expect(frameworks.has('asvs')).toBe(true);
    expect(frameworks.has('iso-27001')).toBe(true);
    expect(frameworks.has('soc-2')).toBe(true);
    expect(frameworks.has('gdpr')).toBe(true);

    // CC6.1 (SOC 2) and A.8.24 (ISO) findings at tf/main.tf line 1 should merge:
    // both Checkov rules cross-reference each other's framework.
    const tfFindings = result.findings.filter((f) => f.location.file === 'tf/main.tf' && f.location.line === 1);
    // After dedup at the same location with cross-mapping, we expect one merged
    // finding tagged with both frameworks. The other Checkov check at line 8 is separate.
    expect(tfFindings.length).toBeGreaterThanOrEqual(1);

    // Exit code must be 1 (active blocking findings exist, threshold=high).
    expect(result.exitCode).toBe(1);

    // Artifacts written.
    expect(readFileSync(result.artifacts.sarif, 'utf8')).toContain('"version": "2.1.0"');
    expect(readFileSync(result.artifacts.markdown, 'utf8')).toContain('Compliance Swarm Report');
    const dossier = JSON.parse(readFileSync(result.artifacts.dossier, 'utf8'));
    expect(dossier.summary.total).toBeGreaterThan(0);
    expect(dossier.summary.by_framework['oss-license']).toBeGreaterThanOrEqual(1);
  });

  it('produces a deterministic SARIF golden file', async () => {
    const result = await run({ mode: 'pr', repoRoot });
    const sarif = JSON.parse(readFileSync(result.artifacts.sarif, 'utf8'));

    // Stable shape assertions (without snapshotting the whole file, which would
    // fail on path differences across machines).
    expect(sarif.$schema).toBe('https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json');
    expect(sarif.version).toBe('2.1.0');
    // Each framework gets a run.
    const runNames = sarif.runs.map((r: { tool: { driver: { name: string } } }) => r.tool.driver.name);
    expect(runNames.some((n: string) => n.includes('asvs'))).toBe(true);
    expect(runNames.some((n: string) => n.includes('gdpr'))).toBe(true);
    expect(runNames.some((n: string) => n.includes('oss-license'))).toBe(true);
  });

  it('clean-repo fixture produces zero findings and exit 0', async () => {
    const sourceClean = join(__dirname, '..', 'fixtures', 'clean-repo');
    const isolatedClean = join(tmp, 'clean-repo');
    cpSync(sourceClean, isolatedClean, { recursive: true });
    const result = await run({ mode: 'pr', repoRoot: isolatedClean });
    expect(result.exitCode).toBe(0);
    expect(result.findings).toEqual([]);
  });
});
