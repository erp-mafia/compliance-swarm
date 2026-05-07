import { describe, expect, it } from 'vitest';
import { SkillManifestSchema, type SkillManifest } from '../../src/skills/manifest.js';
import { trivyParser } from '../../src/tools/parsers/trivy.js';
import { gitleaksParser } from '../../src/tools/parsers/gitleaks.js';
import { semgrepParser } from '../../src/tools/parsers/semgrep.js';
import { checkovParser } from '../../src/tools/parsers/checkov.js';
import { scancodeParser } from '../../src/tools/parsers/scancode.js';
import { ortParser } from '../../src/tools/parsers/ort.js';
import { privadoParser } from '../../src/tools/parsers/privado.js';
import { bearerParser } from '../../src/tools/parsers/bearer.js';
import { helsinkiParser } from '../../src/tools/parsers/helsinki.js';
import { sarifParser } from '../../src/tools/parsers/sarif.js';

function makeManifest(framework: 'oss-license' | 'asvs' | 'iso-27001' | 'soc-2' | 'gdpr'): SkillManifest {
  return SkillManifestSchema.parse({
    id: `${framework}-test`,
    version: '1.0.0',
    detection: { paths: [] },
    finding_extraction: {
      framework,
      default_severity_mapping: { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' },
      cross_framework: [{ tag: 'iso-27001', control: 'A.8.24' }],
    },
  });
}

const ctx = (framework: 'oss-license' | 'asvs' | 'iso-27001' | 'soc-2' | 'gdpr') => ({
  manifest: makeManifest(framework),
  stepId: 'step1',
  defaultBlocking: true,
});

describe('parsers', () => {
  it('trivy: parses misconfig + vuln + secret', () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: 'tf/main.tf',
          Class: 'config',
          Type: 'terraform',
          Misconfigurations: [
            {
              ID: 'AVD-AWS-0028',
              AVDID: 'AVD-AWS-0028',
              Severity: 'HIGH',
              Title: 'RDS storage not encrypted',
              Resolution: 'Set storage_encrypted = true',
              CauseMetadata: { StartLine: 12, EndLine: 18 },
            },
          ],
        },
        {
          Target: 'package-lock.json',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'lodash',
              InstalledVersion: '4.17.20',
              FixedVersion: '4.17.21',
              Severity: 'HIGH',
              Title: 'Prototype pollution',
            },
          ],
        },
        {
          Target: 'src/.env',
          Secrets: [
            {
              RuleID: 'aws-access-key-id',
              Severity: 'CRITICAL',
              Title: 'AWS access key',
              StartLine: 1,
              EndLine: 1,
            },
          ],
        },
      ],
    });
    const findings = trivyParser.parse(raw, ctx('iso-27001'));
    expect(findings).toHaveLength(3);
    const misconfig = findings.find((f) => f.source_tool === 'trivy' && f.control_ref.startsWith('AVD'));
    expect(misconfig?.severity).toBe('high');
    expect(misconfig?.location.line).toBe(12);
    const vuln = findings.find((f) => f.rule_id.includes('CVE'));
    expect(vuln?.remediation).toContain('4.17.21');
    const secret = findings.find((f) => f.control_ref === 'V13.3');
    expect(secret?.severity).toBe('critical');
  });

  it('gitleaks: parses array of findings', () => {
    const raw = JSON.stringify([
      {
        RuleID: 'aws-access-token',
        Description: 'AWS access key found',
        File: 'src/secret.ts',
        StartLine: 12,
        EndLine: 12,
        Match: 'AKIAIOSFODNN7EXAMPLE',
      },
    ]);
    const findings = gitleaksParser.parse(raw, ctx('asvs'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.control_ref).toBe('V13.3');
    expect(findings[0]?.evidence).toContain('AKIA');
  });

  it('semgrep: extracts asvs metadata when present', () => {
    const raw = JSON.stringify({
      results: [
        {
          check_id: 'gdpr.email-log',
          path: 'src/api.ts',
          start: { line: 99, col: 5 },
          end: { line: 99 },
          extra: {
            message: 'PII logged',
            severity: 'WARNING',
            metadata: { asvs: 'V16.1' },
            lines: 'logger.info(user.email)',
          },
        },
      ],
    });
    const findings = semgrepParser.parse(raw, ctx('gdpr'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.control_ref).toBe('V16.1');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('checkov: handles failed_checks shape', () => {
    const raw = JSON.stringify({
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_19',
            check_name: 'S3 bucket has server-side encryption',
            check_result: { result: 'FAILED' },
            file_path: '/tf/main.tf',
            file_line_range: [10, 25],
            resource: 'aws_s3_bucket.foo',
            severity: 'HIGH',
          },
        ],
      },
    });
    const findings = checkovParser.parse(raw, ctx('iso-27001'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.control_ref).toBe('CKV_AWS_19');
    expect(findings[0]?.location.line).toBe(10);
  });

  it('scancode: flags AGPL detections', () => {
    const raw = JSON.stringify({
      files: [
        { path: 'node_modules/foo/LICENSE', detected_license_expression: 'AGPL-3.0-or-later' },
        { path: 'node_modules/bar/LICENSE', detected_license_expression: 'MIT' },
      ],
    });
    const findings = scancodeParser.parse(raw, ctx('oss-license'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.file).toContain('foo');
    expect(findings[0]?.control_ref).toContain('AGPL');
  });

  it('ort: maps evaluator violations to findings', () => {
    const raw = JSON.stringify({
      evaluator: {
        violations: [
          { rule: 'COPYLEFT_LICENSE_DETECTED', pkg: 'GPL-2.0-pkg:1.0', license: 'GPL-2.0', severity: 'ERROR', message: 'GPL-2.0 detected' },
        ],
      },
    });
    const findings = ortParser.parse(raw, ctx('oss-license'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('privado: separates explicit policy violations from data flows', () => {
    const raw = JSON.stringify({
      violations: [
        {
          policyId: 'PRIVADO_PII_LEAK',
          policyName: 'PII to third-party',
          severity: 'high',
          message: 'Email sent to unverified third-party',
          affectedDataElements: ['user.contact.email'],
          file: 'src/api/marketing.ts',
          line: 22,
        },
      ],
      dataflows: {
        'user.contact.email': {
          flowName: 'email-flow',
          flows: [
            {
              source: { id: 'src1', name: 'user.email', fileName: 'src/model.ts', lineNumber: 5 },
              sink: { id: 'sink1', name: 'logger.info', fileName: 'src/api.ts', lineNumber: 90 },
            },
          ],
        },
      },
    });
    const findings = privadoParser.parse(raw, ctx('gdpr'));
    expect(findings).toHaveLength(2);
    const violation = findings.find((f) => f.rule_id === 'privado.PRIVADO_PII_LEAK');
    expect(violation?.blocking).toBe(true);
    const flow = findings.find((f) => f.rule_id.startsWith('privado.flow.'));
    expect(flow?.blocking).toBe(false);
  });

  it('bearer: handles bucketed severity output', () => {
    const raw = JSON.stringify({
      high: [
        {
          id: 'ruby_lang_session_cookie',
          rule_id: 'session-cookie',
          severity: 'high',
          title: 'Insecure session cookie',
          filename: 'app/controllers/session_controller.rb',
          line_number: 14,
        },
      ],
    });
    const findings = bearerParser.parse(raw, ctx('gdpr'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('helsinki: parses cookie-banner violations', () => {
    const raw = JSON.stringify({
      url: 'https://example.com',
      violations: [
        {
          rule: 'pre-consent-tracker',
          url: 'https://example.com',
          category: 'consent',
          severity: 'high',
          description: 'Google Analytics fired before consent.',
          evidence: '<script src="https://www.googletagmanager.com/gtag/...">',
        },
      ],
    });
    const findings = helsinkiParser.parse(raw, ctx('gdpr'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.control_ref).toBe('Art.6(1)(a)');
  });

  it('sarif: generic parser for OPA/Steampipe-like tools', () => {
    const raw = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'opa' } },
          results: [
            {
              ruleId: 'OPA_NO_PUBLIC_S3',
              level: 'error',
              message: { text: 'S3 bucket is public.' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'tf/main.tf' },
                    region: { startLine: 5 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const findings = sarifParser.parse(raw, ctx('soc-2'));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.location.line).toBe(5);
  });

  it('returns empty array on invalid JSON', () => {
    expect(trivyParser.parse('not json', ctx('asvs'))).toEqual([]);
    expect(gitleaksParser.parse('', ctx('asvs'))).toEqual([]);
    expect(semgrepParser.parse('{}', ctx('asvs'))).toEqual([]);
  });
});
