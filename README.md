# compliance-swarm

[![CI](https://github.com/erp-mafia/compliance-swarm/actions/workflows/ci.yml/badge.svg)](https://github.com/erp-mafia/compliance-swarm/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/compliance-swarm.svg)](https://www.npmjs.com/package/compliance-swarm)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Multi-framework compliance orchestrator for repos and CI/CD.** One tool runs five
audit lenses — **OSS licensing**, **OWASP ASVS v5**, **ISO 27001:2022**, **SOC 2**,
**GDPR** — and dedups findings across frameworks so you don't see the same AWS-key
leak reported four times.

## Quickstart — 30 seconds

Drop this into `.github/workflows/compliance-pr.yml`:

```yaml
name: compliance
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: erp-mafia/compliance-swarm@v1
        with:
          mode: pr
          base: ${{ github.event.pull_request.base.sha }}
```

Open a PR. You get:

- **SARIF annotations** on changed lines, native to GitHub Code Scanning.
- A **sticky markdown comment** with the finding summary.
- A **JSON dossier** as a workflow artifact.

That's it. No config file, no secrets, no Bedrock setup needed for PR mode.

## Two modes

| Mode  | Trigger                       | Budget   | Includes                           | Needs            |
|-------|-------------------------------|----------|------------------------------------|------------------|
| `pr`  | every pull request            | < 5 min  | deterministic scanners only        | nothing          |
| `swarm` | nightly + dispatch + label  | ≤ 60 min | scanners **plus** LLM deep audit   | Bedrock or Anthropic API |

## What you'll see

A finding tagged once but mapped to every framework it violates:

```json
{
  "framework": "asvs",
  "control_ref": "V13.3",
  "severity": "critical",
  "location": { "file": "src/secret.ts", "line": 12 },
  "message": "AWS access key in source",
  "cross_framework": [
    { "tag": "soc-2", "control": "CC6.1" },
    { "tag": "iso-27001", "control": "A.8.24" },
    { "tag": "NIST 800-53", "control": "AC-3" }
  ],
  "remediation": "Rotate the key and remove it from history (git filter-repo or BFG)."
}
```

## Configure

Optional `.compliance/config.yml` at your repo root:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/erp-mafia/compliance-swarm/main/packages/cli/.compliance/config.schema.yml

severity_threshold_to_block: high     # critical | high | medium | low | info
asvs_level: L2
soc2_categories: [security, confidentiality]
llm_provider: bedrock                 # or "anthropic"

suppressions:
  - control_ref: A.8.24
    path: extensions/example-logger/**
    justification: Reference impl, never deployed
    expires: '2026-12-31'
    risk_id: RISK-2026-014           # required for ISO/SOC 2 controls
```

Suppressions expire — once `expires` passes, the build fails until renewed.
ISO 27001 and SOC 2 control suppressions require a `risk_id` referencing your
Risk Register.

See [docs/configuration.md](./docs/configuration.md) for the full reference.

## Action inputs

| Input               | Default            | Description                                                       |
|---------------------|--------------------|-------------------------------------------------------------------|
| `mode`              | `pr`               | `pr` or `swarm`.                                                  |
| `base`              | PR base SHA        | Diff base for changed-files.                                      |
| `config-path`       | `.compliance/config.yml` | Override config location.                                   |
| `no-llm`            | `false`            | Skip deep_audit (always true in `pr` mode).                       |
| `llm-provider`      | `bedrock`          | `bedrock` or `anthropic`.                                         |
| `upload-sarif`      | `true`             | Push SARIF to Code Scanning.                                      |
| `upload-dossier`    | `true`             | Archive JSON dossier as artifact.                                 |
| `post-comment`      | `true`             | Sticky PR comment.                                                |
| `fail-on-findings`  | `true`             | Exit non-zero on blocking findings.                               |
| `working-directory` | `.`                | Repo dir to scan.                                                 |

## Beyond GitHub Actions

| Platform     | How                                                                                  |
|--------------|--------------------------------------------------------------------------------------|
| GitLab CI    | [`examples/gitlab/.gitlab-ci.yml`](./examples/gitlab/.gitlab-ci.yml)                 |
| pre-commit   | [`examples/pre-commit/`](./examples/pre-commit/.pre-commit-config.yaml)              |
| Local CLI    | `npm i -g compliance-swarm && compliance-swarm run --mode pr`                        |

## Architecture

```
              orchestrator
                  │
   ┌──────────────┼──────────────┐
   │ oss-license  │  asvs ┐
   │ runs first   │  iso-27001 │ run in parallel,
   │ produces SBOM│  soc-2     │ consume the SBOM
   │              │  gdpr      ┘
   └──────────────┘
                  │
          dedup → suppress → SARIF + markdown + JSON dossier
```

The orchestrator owns no compliance logic. Every check lives in a skill
manifest under [`packages/skills/`](./packages/skills/) — a YAML file declaring
detection triggers, scanner invocations, agentic prompts, and cross-framework
mappings. To add a new framework, write a new manifest. See
[docs/writing-a-skill.md](./docs/writing-a-skill.md).

## What it can and can't do

✅ Catches: hardcoded secrets, dangerous IaC misconfigs, copyleft license
contamination, missing CI gates, PII leaking into logs, RoPA drift, broken
access control patterns, change-management bypasses, supply-chain risk via SBOM.

❌ Cannot: physical security audits, vendor contract review, policy creation
(it audits policies you've already written), regulator filings, manual
attestation. Findings tagged `extrinsic` or `manual_attestation_required`
flag where human judgement is required.

## Documentation

- [Quickstart](./docs/quickstart.md) — run it in 5 minutes
- [Configuration](./docs/configuration.md) — every config option, with examples
- [Suppressions](./docs/suppressions.md) — how to waive findings without losing the audit trail
- [Writing a skill](./docs/writing-a-skill.md) — extend with a new framework
- [Architecture](./docs/architecture.md) — how the pipeline works internally

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Contributing

Issues and PRs welcome. The repo dogfoods itself — every commit triggers a
self-audit run, so changes that break the orchestrator's own scan get caught
early.

```sh
git clone https://github.com/erp-mafia/compliance-swarm
cd compliance-swarm
npm install
npm test
```

Add a [changeset](./.changeset/README.md) to any user-facing change.
