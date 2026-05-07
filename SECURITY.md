# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Instead:

- Email: security@erp-mafia.dev (or whichever address is canonical at time of report)
- Or use GitHub's [private vulnerability reporting](https://github.com/erp-mafia/compliancemaxx/security/advisories/new)

Expect an acknowledgement within 3 business days.

## Scope

In-scope:

- The orchestrator code (`packages/cli/`) — supply-chain, code execution,
  output sanitization.
- The bundled skill manifests (`packages/skills/*/manifest.yml`) — anything
  that influences subprocess invocation or LLM prompts.
- The GitHub Action (`action.yml`) — workflow injection, output sanitization,
  permissions handling.

Out-of-scope:

- Vulnerabilities in third-party scanners (Trivy, Semgrep, Checkov, etc.) —
  report to those projects directly.
- Vulnerabilities in `@anthropic-ai/sdk` or `@anthropic-ai/bedrock-sdk` —
  report to Anthropic.

## Disclosure timeline

We aim for coordinated disclosure within 90 days of a confirmed report,
shorter if a fix is straightforward, longer if architectural changes are
required. We'll keep you informed.
