import { z } from 'zod';

const FrameworkEnum = z.enum(['oss-license', 'asvs', 'iso-27001', 'soc-2', 'gdpr']);

const SeverityEnum = z.enum(['critical', 'high', 'medium', 'low', 'info']);

const ParserName = z.enum([
  'scancode',
  'ort',
  'reuse',
  'trivy',
  'checkov',
  'semgrep',
  'gitleaks',
  'privado',
  'bearer',
  'helsinki',
  'opa',
  'steampipe',
  'sarif',
  'json',
]);

const ToolKind = z.enum(['docker', 'npx', 'binary', 'script']);

const StaticScanStep = z.object({
  id: z.string().min(1),
  tool: ToolKind,
  image: z.string().optional(),
  binary: z.string().optional(),
  args: z.array(z.string()),
  parser: ParserName,
  pr_mode_enabled: z.boolean().default(true),
  swarm_mode_enabled: z.boolean().default(true),
  timeout_seconds: z.number().int().positive().max(3600).default(180),
  changed_files_flag: z.string().optional(),
  output_format: z.enum(['json', 'sarif', 'text', 'cyclonedx', 'spdx']).default('json'),
  produces_artifact: z.string().optional(),
  consumes_artifact: z.array(z.string()).default([]),
  failure_action: z.enum(['fail', 'warn', 'ignore']).default('warn'),
});

const DeepAuditStep = z.object({
  id: z.string().min(1),
  prompt_file: z.string(),
  section: z.string().optional(),
  inputs: z.array(z.string()).default([]),
  output_schema: z.string().optional(),
  max_input_chars: z.number().int().positive().max(500_000).default(120_000),
  expected_findings: z.enum(['zero-or-many', 'one-or-many', 'exactly-one']).default('zero-or-many'),
});

const CrossFrameworkRef = z.object({
  tag: z.string(),
  control: z.string(),
});

const FindingExtraction = z.object({
  framework: FrameworkEnum,
  default_severity_mapping: z.record(z.string(), SeverityEnum).default({}),
  cross_framework: z.array(CrossFrameworkRef).default([]),
});

const ProducedArtifact = z.object({
  name: z.string().min(1),
  format: z.enum(['cyclonedx-json', 'spdx-json', 'json', 'text']),
  path: z.string(),
});

const Suppression = z.object({
  config_file: z.string().nullable().default(null),
  inline_pragma: z.string().nullable().default(null),
});

export const SkillManifestSchema = z.object({
  id: z.string().min(1),
  version: z.string().min(1),
  description: z.string().default(''),
  detection: z.object({
    paths: z.array(z.string()).default([]),
    always_applicable: z.boolean().default(false),
  }),
  produces: z.array(ProducedArtifact).default([]),
  consumes: z.array(z.string()).default([]),
  static_scan: z.array(StaticScanStep).default([]),
  deep_audit: z.array(DeepAuditStep).default([]),
  finding_extraction: FindingExtraction,
  suppression: Suppression.default({ config_file: null, inline_pragma: null }),
  out_of_repo: z.array(z.string()).default([]),
});

export type SkillManifest = z.infer<typeof SkillManifestSchema>;
export type StaticScanStepT = z.infer<typeof StaticScanStep>;
export type DeepAuditStepT = z.infer<typeof DeepAuditStep>;
export type Framework = z.infer<typeof FrameworkEnum>;
export type Severity = z.infer<typeof SeverityEnum>;
