# Quickstart

The fastest path from zero to first scan.

## 1. Add the workflow

Drop this file into your repo at `.github/workflows/compliance-pr.yml`:

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
    timeout-minutes: 8
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: erp-mafia/compliance-swarm@v1
        with:
          mode: pr
          base: ${{ github.event.pull_request.base.sha }}
```

Commit, push, open any PR. The action installs itself and runs.

## 2. Read your first report

After the first run completes, check three places:

- **PR comment** — the sticky comment posted by the action, summary by framework.
- **Files changed → annotations** — SARIF inline comments on the offending lines.
- **Workflow summary → artifacts** → `compliance-dossier-pr-1.zip` — full JSON
  with every finding, cross-framework mapping, and remediation.

## 3. Tighten the threshold

By default the action blocks merge on `severity ≥ high`. To start advisory-only:

```yaml
- uses: erp-mafia/compliance-swarm@v1
  with:
    mode: pr
    base: ${{ github.event.pull_request.base.sha }}
    fail-on-findings: false
```

Or via `.compliance/config.yml`:

```yaml
severity_threshold_to_block: critical    # only block on critical
```

## 4. Add suppressions for known issues

Some findings are real but accepted. Document them with a suppression rule:

```yaml
suppressions:
  - control_ref: A.8.24
    path: extensions/example-logger/**
    justification: Reference impl, never deployed
    expires: '2026-12-31'
    risk_id: RISK-2026-014
```

Read [docs/suppressions.md](./suppressions.md) for the full mechanics —
including why ISO/SOC 2 suppressions need a `risk_id` and what happens when
`expires` passes.

## 5. Turn on swarm mode

PR mode runs deterministic scanners only. Swarm mode adds LLM-driven
agentic checks (RoPA drift, AGPL §13 evaluation, IDOR/access-control
reasoning, ISMS Clause 4-10 review against policy markdown).

Add a second workflow at `.github/workflows/compliance-swarm.yml`:

```yaml
name: compliance — swarm
on:
  schedule: [{ cron: '0 2 * * *' }]
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
  security-events: write
jobs:
  swarm:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.COMPLIANCE_BEDROCK_ROLE_ARN }}
          aws-region: eu-north-1
      - uses: erp-mafia/compliance-swarm@v1
        with:
          mode: swarm
```

Either configure AWS Bedrock via OIDC (set the `COMPLIANCE_BEDROCK_ROLE_ARN`
GitHub repo variable) or use Anthropic API directly:

```yaml
- uses: erp-mafia/compliance-swarm@v1
  with:
    mode: swarm
    llm-provider: anthropic
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## 6. Run locally

```sh
npm install -g compliance-swarm
cd your-repo
compliance-swarm run --mode pr --base main --no-llm
```

Outputs `compliance.sarif`, `compliance-comment.md`, `compliance-dossier.json`
in the current directory.

## What's next?

- [Configuration reference](./configuration.md)
- [Suppression workflow](./suppressions.md)
- [Architecture deep-dive](./architecture.md)
