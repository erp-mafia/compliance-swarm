import { createHash } from 'node:crypto';
import { z } from 'zod';

export const FrameworkValues = ['oss-license', 'asvs', 'iso-27001', 'soc-2', 'gdpr'] as const;
export const SeverityValues = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const StatusValues = ['fail', 'pass', 'manual_attestation_required', 'not_applicable'] as const;
export const ModalityValues = ['deterministic', 'agentic', 'extrinsic'] as const;

export const SEVERITY_RANK: Record<(typeof SeverityValues)[number], number> = {
  critical: 50,
  high: 40,
  medium: 30,
  low: 20,
  info: 10,
};

const LocationSchema = z.object({
  file: z.string(),
  line: z.number().int().nonnegative().optional(),
  endLine: z.number().int().nonnegative().optional(),
  column: z.number().int().nonnegative().optional(),
});

const CrossFrameworkSchema = z.object({
  tag: z.string(),
  control: z.string(),
});

export const FindingSchema = z.object({
  id: z.string(),
  framework: z.enum(FrameworkValues),
  control_ref: z.string(),
  rule_id: z.string(),
  severity: z.enum(SeverityValues),
  status: z.enum(StatusValues),
  modality: z.enum(ModalityValues),
  source_tool: z.string(),
  location: LocationSchema,
  message: z.string(),
  evidence: z.string().default(''),
  remediation: z.string().default(''),
  policy_clause: z.string().optional(),
  cross_framework: z.array(CrossFrameworkSchema).default([]),
  suppressed_by: z.string().optional(),
  blocking: z.boolean(),
});

export type Finding = z.infer<typeof FindingSchema>;
export type Severity = (typeof SeverityValues)[number];
export type Framework = (typeof FrameworkValues)[number];
export type Status = (typeof StatusValues)[number];
export type Modality = (typeof ModalityValues)[number];

export type FindingDraft = Omit<Finding, 'id' | 'evidence' | 'remediation' | 'cross_framework'> & {
  id?: string;
  evidence?: string;
  remediation?: string;
  cross_framework?: ReadonlyArray<{ tag: string; control: string }>;
};

export function makeFindingId(d: Pick<Finding, 'framework' | 'control_ref' | 'rule_id' | 'location' | 'source_tool'>): string {
  const key = [
    d.framework,
    d.control_ref,
    d.rule_id,
    d.source_tool,
    d.location.file,
    String(d.location.line ?? ''),
  ].join('|');
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

export function finalize(draft: FindingDraft): Finding {
  const id = draft.id ?? makeFindingId(draft);
  return FindingSchema.parse({ ...draft, id });
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}
