import { z } from 'zod';
import { SeverityValues } from '../findings/schema.js';

const SuppressionSchema = z.object({
  id: z.string().optional(),
  control_ref: z.string(),
  path: z.string(),
  justification: z.string().min(1),
  expires: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  risk_id: z.string().optional(),
});

export const ConfigSchema = z.object({
  enabled_skills: z.array(z.string()).default([
    'oss-license-compliance',
    'owasp-asvs-v5-compliance',
    'iso-27001-2022-compliance',
    'soc2-cicd-compliance',
    'gdpr-cicd-compliance',
  ]),
  asvs_level: z.enum(['L1', 'L2', 'L3']).default('L2'),
  soc2_categories: z
    .array(z.enum(['security', 'availability', 'confidentiality', 'processing_integrity', 'privacy']))
    .default(['security']),
  gdpr_jurisdiction_supplements: z.array(z.string()).default([]),
  severity_threshold_to_block: z.enum(SeverityValues).default('high'),
  llm_provider: z.enum(['bedrock', 'anthropic']).default('bedrock'),
  llm_model: z.string().default('claude-sonnet-4-6'),
  suppressions: z.array(SuppressionSchema).default([]),
  artifact_dir: z.string().default('.compliance-artifacts'),
  pr_comment_path: z.string().default('compliance-comment.md'),
  sarif_path: z.string().default('compliance.sarif'),
  dossier_path: z.string().default('compliance-dossier.json'),
});

export type SwarmConfig = z.infer<typeof ConfigSchema>;
export type SuppressionRuleConfig = z.infer<typeof SuppressionSchema>;
