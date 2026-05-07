import type { Finding, Severity } from '../../findings/schema.js';
import type { SkillManifest } from '../../skills/manifest.js';

export interface ParseContext {
  manifest: SkillManifest;
  /** Step id from the manifest's static_scan entry. Used as default rule_id prefix. */
  stepId: string;
  /** Whether findings should be marked blocking by default (PR mode + threshold met). */
  defaultBlocking: boolean;
}

export interface Parser {
  /** Tool's stdout (or contents of an output file the manifest passes via ${OUT}). */
  parse(raw: string, ctx: ParseContext): Finding[];
}

export type ParserName =
  | 'scancode'
  | 'ort'
  | 'reuse'
  | 'trivy'
  | 'checkov'
  | 'semgrep'
  | 'gitleaks'
  | 'privado'
  | 'bearer'
  | 'helsinki'
  | 'opa'
  | 'steampipe'
  | 'sarif'
  | 'json';

export function applyDefaultSeverity(
  manifest: SkillManifest,
  raw: string | undefined,
  fallback: Severity = 'medium',
): Severity {
  if (!raw) return fallback;
  const mapped = manifest.finding_extraction.default_severity_mapping[raw];
  if (mapped) return mapped;
  const lower = raw.toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(lower)) return lower as Severity;
  return fallback;
}

import { trivyParser } from './trivy.js';
import { gitleaksParser } from './gitleaks.js';
import { semgrepParser } from './semgrep.js';
import { checkovParser } from './checkov.js';
import { scancodeParser } from './scancode.js';
import { ortParser } from './ort.js';
import { privadoParser } from './privado.js';
import { bearerParser } from './bearer.js';
import { helsinkiParser } from './helsinki.js';
import { sarifParser } from './sarif.js';

export const PARSERS: Record<ParserName, Parser> = {
  trivy: trivyParser,
  gitleaks: gitleaksParser,
  semgrep: semgrepParser,
  checkov: checkovParser,
  scancode: scancodeParser,
  ort: ortParser,
  privado: privadoParser,
  bearer: bearerParser,
  helsinki: helsinkiParser,
  reuse: sarifParser,        // REUSE emits standard JSON; treat as sarif-ish for now
  opa: sarifParser,          // OPA/Conftest emits JSON; can be SARIF too
  steampipe: sarifParser,    // Steampipe SQL → JSON, custom adapter when needed
  sarif: sarifParser,
  json: sarifParser,
};
