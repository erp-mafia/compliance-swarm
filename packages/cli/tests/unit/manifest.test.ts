import { describe, expect, it } from 'vitest';
import { SkillManifestSchema } from '../../src/skills/manifest.js';

describe('SkillManifestSchema', () => {
  it('accepts a minimal valid manifest', () => {
    const manifest = {
      id: 'oss-license-compliance',
      version: '1.0.0',
      detection: { paths: ['**/package.json'] },
      finding_extraction: { framework: 'oss-license' },
    };
    const result = SkillManifestSchema.safeParse(manifest);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.static_scan).toEqual([]);
      expect(result.data.deep_audit).toEqual([]);
      expect(result.data.suppression).toEqual({ config_file: null, inline_pragma: null });
    }
  });

  it('accepts a manifest with full static_scan + deep_audit', () => {
    const manifest = {
      id: 'gdpr-cicd-compliance',
      version: '1.0.0',
      detection: { paths: ['**/migrations/**', '.compliance/ropa.yaml'] },
      produces: [],
      consumes: ['sbom'],
      static_scan: [
        {
          id: 'semgrep-gdpr',
          tool: 'docker',
          image: 'returntocorp/semgrep:latest',
          args: ['semgrep', '--config', '.semgrep/gdpr/', '--json', '${REPO}'],
          parser: 'semgrep',
          timeout_seconds: 120,
        },
      ],
      deep_audit: [
        {
          id: 'ropa-drift',
          prompt_file: 'references/agentic-prompts.md',
          section: 'RoPA drift detection',
          inputs: ['changed_files', 'sbom', '.compliance/ropa.yaml'],
        },
      ],
      finding_extraction: {
        framework: 'gdpr',
        cross_framework: [
          { tag: 'NIST 800-53', control: 'PT-2' },
          { tag: 'ISO 27001:2022', control: 'A.5.34' },
        ],
      },
    };
    const result = SkillManifestSchema.safeParse(manifest);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.static_scan).toHaveLength(1);
      expect(result.data.static_scan[0]?.pr_mode_enabled).toBe(true);
      expect(result.data.deep_audit[0]?.max_input_chars).toBe(120_000);
    }
  });

  it('rejects unknown framework', () => {
    const manifest = {
      id: 'mystery',
      version: '1.0.0',
      detection: { paths: [] },
      finding_extraction: { framework: 'pci-dss' },
    };
    expect(SkillManifestSchema.safeParse(manifest).success).toBe(false);
  });

  it('rejects unknown parser', () => {
    const manifest = {
      id: 'x',
      version: '1.0.0',
      detection: { paths: [] },
      static_scan: [
        {
          id: 's',
          tool: 'docker',
          args: [],
          parser: 'snyk-special-edition',
          timeout_seconds: 60,
        },
      ],
      finding_extraction: { framework: 'asvs' },
    };
    expect(SkillManifestSchema.safeParse(manifest).success).toBe(false);
  });

  it('rejects manifest with negative timeout', () => {
    const manifest = {
      id: 'x',
      version: '1.0.0',
      detection: { paths: [] },
      static_scan: [
        {
          id: 's',
          tool: 'docker',
          args: [],
          parser: 'trivy',
          timeout_seconds: -10,
        },
      ],
      finding_extraction: { framework: 'iso-27001' },
    };
    expect(SkillManifestSchema.safeParse(manifest).success).toBe(false);
  });
});
