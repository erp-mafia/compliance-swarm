# compliancemaxx

Multi-framework compliance orchestrator that runs five Claude skills against an
arbitrary repository: **OSS licensing**, **OWASP ASVS v5**, **ISO 27001:2022**,
**SOC 2**, **GDPR**.

Two modes:

| Mode  | Trigger                            | Budget   | Includes                                        |
|-------|------------------------------------|----------|-------------------------------------------------|
| `pr`  | every pull request                 | < 5 min  | deterministic scanners only                     |
| `swarm` | nightly + dispatch + label       | ≤ 60 min | scanners **plus** LLM-based deep audits         |

Output formats: SARIF 2.1.0 (Code Scanning annotations), markdown PR comment,
JSON dossier (artifact, 90-day retention).

## Install

This package lives at `.claude/skills/compliancemaxx/` so it sits alongside
the skill knowledge bases it executes.

```bash
cd .claude/skills/compliancemaxx
npm install
npm test
```

Skill manifests are co-located with their skill:

```
.claude/skills/oss-license-compliance/manifest.yml
.claude/skills/owasp-asvs-v5-compliance/manifest.yml
.claude/skills/iso-27001-2022-compliance/manifest.yml
.claude/skills/soc2-cicd-compliance/manifest.yml
.claude/skills/gdpr-cicd-compliance/manifest.yml
```

The orchestrator owns no compliance logic. It loads each manifest, runs the
declared scanners, parses output to a normalised `Finding` shape, dedups across
frameworks, applies suppressions, and emits artifacts.

## Configure

Create `.compliance/config.yml` at your repo root:

```yaml
# yaml-language-server: $schema=./.compliance/config.schema.yml

enabled_skills:
  - oss-license-compliance
  - owasp-asvs-v5-compliance
  - iso-27001-2022-compliance
  - soc2-cicd-compliance
  - gdpr-cicd-compliance

asvs_level: L2
soc2_categories: [security, confidentiality]
severity_threshold_to_block: high
llm_provider: bedrock          # or "anthropic"
llm_model: eu.anthropic.claude-sonnet-4-6

suppressions:
  - control_ref: A.8.24
    path: extensions/example-logger/**
    justification: Reference impl, never deployed
    expires: '2026-12-31'
    risk_id: RISK-2026-014       # required for ISO/SOC 2 suppressions
```

## CLI

```bash
compliancemaxx run --mode pr --base $BASE_SHA  # PR-mode against changed files
compliancemaxx run --mode swarm                # full hybrid + LLM
compliancemaxx run --mode swarm --no-llm       # offline; agentic stubbed out
compliancemaxx list-skills                     # show loaded manifests
compliancemaxx validate-config                 # JSON-schema + suppression-expiry
compliancemaxx sbom                            # SBOM only (oss-license skill)
```

Exit codes:

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | clean run                                |
| 1    | blocking findings or expired suppressions |
| 2    | internal error                           |

## CI/CD

Drop the example workflows into your repo:

```bash
cp .claude/skills/compliancemaxx/examples/github-actions/*.yml .github/workflows/
```

PR mode (`compliance-pr.yml`) runs on every PR, uploads SARIF to Code Scanning,
posts a sticky comment, archives the dossier for 14 days, blocks merge when
`severity_threshold_to_block` is met.

Swarm mode (`compliancemaxx.yml`) runs nightly, on `workflow_dispatch`, and
on PRs labelled `compliance:full-audit`. Uses GitHub OIDC to assume an AWS role
for Bedrock; falls back to env-resolved auth chain when the role is unset.

GitLab and pre-commit equivalents are in `examples/`.

## Suppression workflow

1. Add a rule to `suppressions:` in `.compliance/config.yml`.
2. Provide a non-empty `justification` and an `expires` date.
3. ISO 27001 and SOC 2 controls require `risk_id` referencing a Risk Register
   entry — without it, the suppression is **not applied**.
4. Once `expires` passes, the orchestrator exits 1 until the rule is renewed
   or removed. `compliancemaxx validate-config` flags expirations early.

## Output interpretation

- A finding's `cross_framework` array tells you what other frameworks the same
  underlying issue maps to — e.g. an AWS-key leak is one finding tagged with
  ASVS V13.3 *and* SOC 2 CC6.1 *and* ISO A.8.24, not three separate noise items.
- `modality` distinguishes deterministic-scanner output (`deterministic`) from
  LLM-driven judgements (`agentic`) and from things the orchestrator cannot
  adjudicate (`extrinsic`, e.g. physical security).
- `status: manual_attestation_required` means the LLM flagged a control that
  cannot be evaluated from repo content alone — you must attach evidence in
  your GRC system.

## Architecture

```
oss-license  ──SBOM──▶  asvs ┐
                              ├─ run in parallel, consume SBOM
                              soc-2/iso-27001/gdpr
                            ──▶ dedup → suppress → emit
```

See `src/skills/manifest.ts` for the manifest contract and
`src/findings/schema.ts` for the unified Finding shape.
