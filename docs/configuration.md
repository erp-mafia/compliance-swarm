# Configuration

Configuration lives in `.compliance/config.yml` at your repo root. All fields are
optional; defaults are sensible for most repos.

## Full reference

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/erp-mafia/compliancemaxx/main/packages/cli/.compliance/config.schema.yml

# Which skills to run. Default: all 5.
enabled_skills:
  - oss-license-compliance
  - owasp-asvs-v5-compliance
  - iso-27001-2022-compliance
  - soc2-cicd-compliance
  - gdpr-cicd-compliance

# OWASP ASVS verification level.
#   L1 = baseline; L2 = serious apps; L3 = high-assurance
asvs_level: L2

# SOC 2 categories to evaluate. Security is always implied; others opt-in.
soc2_categories: [security, confidentiality]
# Possible values: security, availability, confidentiality, processing_integrity, privacy

# GDPR jurisdiction supplements (UK GDPR, Swiss FADP, etc.).
gdpr_jurisdiction_supplements: []

# Block merge when any finding ≥ this severity.
severity_threshold_to_block: high
# Possible values: critical | high | medium | low | info

# LLM provider for swarm-mode deep_audit.
llm_provider: bedrock          # or "anthropic"
llm_model: eu.anthropic.claude-sonnet-4-6

# Where to write outputs (relative to repo root).
artifact_dir: .compliance-artifacts
sarif_path: compliance.sarif
pr_comment_path: compliance-comment.md
dossier_path: compliance-dossier.json

# Suppressions — see docs/suppressions.md
suppressions: []
```

## Common patterns

### Start advisory, tighten over time

```yaml
severity_threshold_to_block: critical    # only block on critical at first
```

Combined with `fail-on-findings: false` in your workflow, this gives you a
read-only first run. Tighten to `high` once you've triaged the initial output.

### Disable a skill

```yaml
enabled_skills:
  - oss-license-compliance
  - owasp-asvs-v5-compliance
  - soc2-cicd-compliance
  # gdpr-cicd-compliance disabled — no EU data subjects
  # iso-27001-2022-compliance disabled — not in scope this year
```

### Override per-CI-run

The action accepts overrides as inputs:

```yaml
- uses: erp-mafia/compliancemaxx@v1
  with:
    mode: pr
    base: ${{ github.event.pull_request.base.sha }}
    config-path: .compliance/strict.yml      # alternate config
```

## Schema validation

Editors with YAML LSP support will validate your config against the published
schema if you reference it:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/erp-mafia/compliancemaxx/main/packages/cli/.compliance/config.schema.yml
```

You can also validate from the CLI:

```sh
compliancemaxx validate-config
```

This also flags **expired suppressions** — see [docs/suppressions.md](./suppressions.md).

## Environment variables

| Variable                         | Effect                                                                |
|----------------------------------|-----------------------------------------------------------------------|
| `COMPLIANCE_LOG_LEVEL`           | `debug` \| `info` \| `warn` \| `error` (default `info`)               |
| `COMPLIANCE_SWARM_ROOT`          | Override orchestrator package root (rare; for tests / vendored copies)|
| `COMPLIANCE_SKILLS_ROOT`         | Override skills lookup directory                                      |
| `COMPLIANCE_CACHE_DIR`           | SBOM cache location                                                   |
| `COMPLIANCE_BEDROCK_MODEL`       | Default Bedrock model id                                              |
| `COMPLIANCE_ANTHROPIC_MODEL`     | Default Anthropic model id                                            |
| `ANTHROPIC_API_KEY`              | Required for `llm_provider: anthropic`                                |
| `AWS_REGION` / standard AWS env  | Used by `llm_provider: bedrock`                                       |
