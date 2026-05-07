import type { Finding, Severity } from '../findings/schema.js';
import type { MergedFinding } from '../findings/dedup.js';
import { compareSeverity } from '../findings/schema.js';

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

const FRAMEWORK_LABEL: Record<string, string> = {
  'oss-license': 'OSS Licensing',
  asvs: 'OWASP ASVS v5',
  'iso-27001': 'ISO 27001:2022',
  'soc-2': 'SOC 2',
  gdpr: 'GDPR',
};

const MAX_BYTES = 60_000; // GitHub PR comment limit is 65536; leave headroom.
const MAX_FINDINGS_PER_FRAMEWORK = 20;

export interface MarkdownOptions {
  mode: 'pr' | 'swarm';
  dossierUrl?: string;
  expiredSuppressionCount?: number;
}

export function toMarkdown(
  findings: Array<Finding | MergedFinding>,
  opts: MarkdownOptions,
): string {
  const lines: string[] = [];
  lines.push('## Compliance Swarm Report');
  lines.push('');

  const active = findings.filter((f) => f.status === 'fail');
  const blocking = active.filter((f) => f.blocking);
  const passes = findings.length - active.length;

  if (active.length === 0) {
    lines.push(`✅ **No active findings.** ${findings.length} check(s) ran; ${passes} passed.`);
  } else {
    lines.push(
      `**${active.length}** active finding(s) — **${blocking.length}** blocking. Mode: \`${opts.mode}\`.`,
    );
  }

  if ((opts.expiredSuppressionCount ?? 0) > 0) {
    lines.push('');
    lines.push(
      `⚠️ **${opts.expiredSuppressionCount}** expired suppression(s). Build will fail until renewed or removed.`,
    );
  }

  lines.push('');
  lines.push('### Severity summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|---|---|');
  const counts = countBySeverity(active);
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
    if (counts[sev] > 0) lines.push(`| ${SEVERITY_EMOJI[sev]} ${sev} | ${counts[sev]} |`);
  }

  lines.push('');
  lines.push('### Findings by framework');

  const byFramework = groupByFramework(active);
  for (const [framework, items] of byFramework) {
    items.sort((a, b) => compareSeverity(a.severity, b.severity));
    lines.push('');
    lines.push(`#### ${FRAMEWORK_LABEL[framework] ?? framework}`);
    lines.push('');
    const shown = items.slice(0, MAX_FINDINGS_PER_FRAMEWORK);
    for (const f of shown) {
      const loc = f.location.line ? `${f.location.file}:${f.location.line}` : f.location.file;
      const cross = f.cross_framework.length > 0
        ? ` _(also: ${f.cross_framework.map((c) => `${c.tag} ${c.control}`).join(', ')})_`
        : '';
      lines.push(`- ${SEVERITY_EMOJI[f.severity]} **${f.control_ref}** — \`${loc}\`${cross}`);
      if (f.message) lines.push(`  - ${f.message}`);
      if (f.remediation) lines.push(`  - _Remediation:_ ${f.remediation}`);
    }
    if (items.length > shown.length) {
      lines.push(`  - …and ${items.length - shown.length} more (see dossier).`);
    }
  }

  if (opts.dossierUrl) {
    lines.push('');
    lines.push(`Full dossier: ${opts.dossierUrl}`);
  }

  lines.push('');
  lines.push('---');
  lines.push('_compliance-swarm — fail = `severity ≥ threshold` && `blocking`._');

  let out = lines.join('\n');
  if (Buffer.byteLength(out, 'utf8') > MAX_BYTES) {
    out = out.slice(0, MAX_BYTES - 200) + '\n\n…_truncated; see dossier artifact_.';
  }
  return out;
}

function countBySeverity(findings: Array<Finding | MergedFinding>): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function groupByFramework(findings: Array<Finding | MergedFinding>): Map<string, Array<Finding | MergedFinding>> {
  const map = new Map<string, Array<Finding | MergedFinding>>();
  for (const f of findings) {
    const arr = map.get(f.framework) ?? [];
    arr.push(f);
    map.set(f.framework, arr);
  }
  return map;
}
