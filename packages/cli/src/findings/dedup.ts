import type { Finding } from './schema.js';
import { compareSeverity } from './schema.js';

/**
 * Merge findings that describe the same issue across multiple skills via
 * cross-framework mappings.
 *
 * Two findings collapse when they share `(file, line, source_tool, rule_id)`
 * — a single tool emitting one detection — OR when one finding's
 * `(framework, control_ref)` appears as a cross-framework reference on the
 * other AT the same location. The merged finding keeps the highest severity,
 * unions cross-framework tags, and records both control_refs as siblings.
 */
export interface MergedFinding extends Finding {
  related_controls: Array<{ framework: string; control_ref: string }>;
}

function locationKey(f: Finding): string {
  return `${f.location.file}|${f.location.line ?? ''}|${f.source_tool}|${f.rule_id}`;
}

function crossKey(framework: string, control: string): string {
  return `${framework}::${control}`;
}

function locationMatches(a: Finding, b: Finding): boolean {
  return (
    a.location.file === b.location.file &&
    (a.location.line ?? null) === (b.location.line ?? null)
  );
}

function isCrossMapped(a: Finding, b: Finding): boolean {
  if (!locationMatches(a, b)) return false;
  const aKeys = new Set(a.cross_framework.map((c) => crossKey(c.tag, c.control)));
  const bKeys = new Set(b.cross_framework.map((c) => crossKey(c.tag, c.control)));
  // a's control mapped in b's cross-framework list, or vice versa
  if (aKeys.has(crossKey(b.framework, b.control_ref))) return true;
  if (bKeys.has(crossKey(a.framework, a.control_ref))) return true;
  // overlapping cross-framework tags
  for (const k of aKeys) if (bKeys.has(k)) return true;
  return false;
}

function mergePair(primary: Finding, other: Finding): MergedFinding {
  const tags = new Map<string, { tag: string; control: string }>();
  for (const c of primary.cross_framework) tags.set(crossKey(c.tag, c.control), c);
  for (const c of other.cross_framework) tags.set(crossKey(c.tag, c.control), c);
  // Add the "other" finding's own framework/control_ref as a cross-mapping entry
  // since the merged finding now represents both.
  const otherKey = crossKey(other.framework, other.control_ref);
  if (!tags.has(otherKey)) tags.set(otherKey, { tag: other.framework, control: other.control_ref });

  const related: Array<{ framework: string; control_ref: string }> = [
    { framework: primary.framework, control_ref: primary.control_ref },
    { framework: other.framework, control_ref: other.control_ref },
  ];

  return {
    ...primary,
    severity: compareSeverity(primary.severity, other.severity) <= 0 ? primary.severity : other.severity,
    blocking: primary.blocking || other.blocking,
    cross_framework: Array.from(tags.values()),
    related_controls: related,
  };
}

export function dedup(findings: Finding[]): MergedFinding[] {
  // Step 1: collapse exact duplicates on locationKey.
  const exactBuckets = new Map<string, Finding>();
  for (const f of findings) {
    const k = locationKey(f);
    const existing = exactBuckets.get(k);
    if (!existing) {
      exactBuckets.set(k, f);
      continue;
    }
    // pick the higher-severity / blocking one as primary
    const primary = compareSeverity(existing.severity, f.severity) <= 0 ? existing : f;
    const secondary = primary === existing ? f : existing;
    exactBuckets.set(k, {
      ...primary,
      blocking: primary.blocking || secondary.blocking,
      cross_framework: dedupCross([...primary.cross_framework, ...secondary.cross_framework]),
    });
  }

  const collapsed = Array.from(exactBuckets.values());

  // Step 2: greedy cross-framework merge across remaining findings.
  const used = new Set<number>();
  const merged: MergedFinding[] = [];

  for (let i = 0; i < collapsed.length; i++) {
    if (used.has(i)) continue;
    let primary = toMerged(collapsed[i]!);
    used.add(i);
    for (let j = i + 1; j < collapsed.length; j++) {
      if (used.has(j)) continue;
      const other = collapsed[j]!;
      if (isCrossMapped(primary, other)) {
        primary = mergePair(primary, other);
        used.add(j);
      }
    }
    merged.push(primary);
  }

  return merged;
}

function dedupCross(arr: Array<{ tag: string; control: string }>): Array<{ tag: string; control: string }> {
  const map = new Map<string, { tag: string; control: string }>();
  for (const c of arr) map.set(crossKey(c.tag, c.control), c);
  return Array.from(map.values());
}

function toMerged(f: Finding): MergedFinding {
  return { ...f, related_controls: [{ framework: f.framework, control_ref: f.control_ref }] };
}
