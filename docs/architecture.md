# Architecture

How the orchestrator works under the hood. Read this if you're contributing,
debugging unexpected behavior, or evaluating whether to trust the tool.

## Mental model

```
                ┌──────────────────────────────────────┐
                │           orchestrator                │
                │  • config loader                      │
                │  • skill loader (manifest.yml)        │
                │  • execution graph                    │
                │  • finding schema + dedup             │
                │  • SARIF + markdown + JSON emitters   │
                │  • LLM client (Bedrock | Anthropic)   │
                └──────────────────┬───────────────────┘
                                   │ delegates to
                                   ▼
        ┌────────────────┐  artifact  ┌────────────────────────────────┐
        │  oss-license   │──SBOM────▶ │  asvs │ iso-27001 │ soc2 │ gdpr │
        │ (runs first)   │            │       (run in parallel)        │
        └────────────────┘            └────────────────────────────────┘
```

The orchestrator owns **zero compliance logic**. Every check is declared in a
skill's `manifest.yml`. To extend the tool, you don't fork the orchestrator —
you write a new manifest. See [writing-a-skill.md](./writing-a-skill.md).

## Skills as data

Each skill ships under `packages/skills/<short-name>/`:

```
packages/skills/asvs-v5/
├── SKILL.md                 # human-readable knowledge base (also loadable into Claude)
├── references/              # detailed normative / how-to docs
│   ├── foundational-chapters.md
│   ├── identity-chapters.md
│   ├── platform-chapters.md
│   └── ...
└── manifest.yml             # the executable contract — see manifest.ts schema
```

The `manifest.yml` declares:

- **Detection triggers** — file globs that say "this skill applies to this repo".
- **Static scan steps** — Docker image / binary + args + parser. Each step
  emits findings via a parser (Trivy, Semgrep, Checkov, GitLeaks, ScanCode,
  ORT, Privado, Bearer, Helsinki, OPA, Steampipe, generic SARIF).
- **Deep audit steps** — references to specific sections of the skill's own
  reference docs that the LLM uses as the system prompt for agentic checks.
- **Finding extraction config** — framework label, severity mapping, default
  cross-framework cross-references.
- **Suppression hooks** — skill-native config files (`.ort.yml`, `.checkov.yml`
  pragmas, etc.) the orchestrator honors.
- **Out-of-repo scope** — explicit "this skill cannot adjudicate X" list, so
  findings appropriately flag `manual_attestation_required`.

## Execution graph

1. **Load config** + apply suppression-expiry check.
2. **Resolve mode** (`pr` | `swarm`) + collect changed-files (PR mode only).
3. **Run `oss-license-compliance`** first → produces SBOM artifact.
4. **Cache the SBOM** keyed by hash of all lockfiles. Subsequent skills
   downstream consume from cache.
5. **In parallel**: run `asvs`, `iso-27001`, `soc-2`, `gdpr` static scans.
   Each picks up the SBOM artifact path via `${ARTIFACT_SBOM}` substitution.
6. **If swarm mode**: each skill runs its `deep_audit` steps via the configured
   LLM, with concurrency capped to provider RPM limits.
7. **Merge**: dedup across skills via cross-framework mappings.
8. **Suppress**: apply config rules; auto-fail expired ones.
9. **Threshold**: re-evaluate `blocking` against `severity_threshold_to_block`.
10. **Emit**: SARIF, markdown, JSON dossier.
11. **Exit code**: 0 clean | 1 blocking findings or expired suppressions | 2 internal error.

## Finding shape

```ts
type Finding = {
  id: string;                      // sha256(framework|control|rule|tool|file|line).slice(0,16)
  framework: 'oss-license' | 'asvs' | 'iso-27001' | 'soc-2' | 'gdpr';
  control_ref: string;             // V13.3 | A.8.24 | CC6.1 | Art.5(1)(f) | SPDX-AGPL-3.0
  rule_id: string;                 // semgrep.email-log | trivy.CVE-2024-1234 | gitleaks.aws-key
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'fail' | 'pass' | 'manual_attestation_required' | 'not_applicable';
  modality: 'deterministic' | 'agentic' | 'extrinsic';
  source_tool: string;
  location: { file: string; line?: number; endLine?: number; column?: number };
  message: string;
  evidence: string;
  remediation: string;
  policy_clause?: string;          // for findings that quote .compliance/ markdown verbatim
  cross_framework: Array<{ tag: string; control: string }>;
  suppressed_by?: string;
  blocking: boolean;
};
```

## Cross-framework dedup

The single biggest feature beyond running scanners. Two findings collapse when:

1. They share `(file, line, source_tool, rule_id)` — a tool emitting the same
   detection twice.
2. Their `cross_framework` lists overlap, **and** they share `(file, line)`.

Result: an AWS-key leak picked up by GitLeaks (mapped to ASVS V13.3 with
cross-references to SOC 2 CC6.1 and ISO A.8.24) and confirmed by Trivy
(mapped to ISO A.8.24 with cross-reference back to ASVS V13.3) at the same
line collapses into **one** annotation tagged with all three frameworks.

The merged finding's `related_controls` lists each framework whose check
contributed.

## LLM client

Pluggable, two adapters:

- **`bedrock`** — uses `@anthropic-ai/bedrock-sdk`, AWS region defaults to
  `eu-north-1`. Auth via standard AWS credential chain (OIDC role works).
- **`anthropic`** — uses `@anthropic-ai/sdk` with `ANTHROPIC_API_KEY`.

Both retry on 429/503/529 with exponential backoff (500ms / 2s / 6s).

`deep_audit` steps load a section of the skill's reference markdown as the
system prompt, attach inputs (changed files, SBOM, target source files), and
expect strict JSON output following:

```json
{ "findings": [ { "control_ref": "...", "severity": "high", "status": "fail",
                  "message": "...", "evidence": "...", "remediation": "...",
                  "file": "...", "line": 12 } ] }
```

Malformed responses → zero findings, no crash. Output is logged at debug.

## Output formats

- **SARIF 2.1.0** (`compliance.sarif`) — one run per framework, rules keyed
  on `<framework>/<control_ref>`. Suppressed findings carry the SARIF
  `suppressions` block with `kind: external` and the rule justification.
- **Markdown** (`compliance-comment.md`) — sticky PR comment. Capped at
  60kB to fit GitHub's 65kB comment limit.
- **JSON dossier** (`compliance-dossier.json`) — the structured ground truth.
  Schema versioned (`schema_version: '0.1'`). Used by the action's metadata
  output extraction (`findings-total`, `findings-blocking`).

## Caching

`runner.temp/.compliance-cache/` holds SBOMs hashed by lockfile content. The
GitHub Action wires this to `actions/cache@v4` automatically. First run on a
new lockfile is ~30-60s slower than subsequent.

## Security posture

- **No shell expansion**: `child_process.spawn(..., { shell: false })` for
  every tool invocation. Manifest-supplied args go straight to argv.
- **Output caps**: 32MB stdout, 4MB stderr per tool. Larger output → truncated.
- **Process timeouts**: per-step in manifest (default 180s). SIGTERM then
  SIGKILL if unresponsive.
- **Docker user mapping**: `--user $(id -u):$(id -g)` to avoid root-owned
  outputs in mounted volumes.
- **No secrets in PR mode**: `pr` mode short-circuits LLM calls; no cloud
  credentials needed. Swarm mode uses OIDC where possible.

## What's intentionally not here

- A scanner registry / plugin marketplace. Skills are a tight set of 5; expand
  by writing a manifest, not by depending on third-party plugins.
- Cross-repo state. Each run is stateless; if you want trends, post the
  dossier to your observability stack.
- Auto-remediation. The orchestrator reports; humans (or other agents) fix.
