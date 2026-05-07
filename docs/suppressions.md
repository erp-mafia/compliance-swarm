# Suppressions

How to silence a finding without losing the audit trail.

## When to suppress vs. fix

**Fix** when the finding is real and the remediation is reasonable.

**Suppress** when:

- The finding is real but accepted (residual risk in your Risk Register).
- The finding is in code that doesn't ship (test fixtures, internal tools).
- The finding is a tool false-positive your config can't otherwise tune out.

If you're tempted to suppress to "make it green", don't. Untriaged green is
worse than visible red — you'll lose the signal.

## Anatomy of a rule

```yaml
suppressions:
  - id: hardcoded-test-key                  # optional, for cross-reference
    control_ref: A.8.24                     # framework-specific control id
    path: 'extensions/example-logger/**'    # glob, relative to repo root
    justification: |
      Reference implementation; never deployed. The hardcoded key is a
      placeholder for documentation purposes only.
    expires: '2026-12-31'                   # ISO YYYY-MM-DD; required for hygiene
    risk_id: RISK-2026-014                  # required for ISO/SOC 2 controls
```

## Required fields

| Field           | Required when                               | Notes                                                   |
|-----------------|---------------------------------------------|---------------------------------------------------------|
| `control_ref`   | always                                      | Match the `control_ref` field of the finding.           |
| `path`          | always                                      | Glob; matches finding's `location.file`.                |
| `justification` | always                                      | Non-empty. Auditors read these.                         |
| `expires`       | strongly recommended                        | Without it, the rule never re-triggers re-review.       |
| `risk_id`       | controls under `iso-27001` or `soc-2`       | Without it, the rule is **not applied**.                |
| `id`            | optional                                    | Stable handle for cross-reference / dashboards.         |

## Why ISO/SOC 2 require `risk_id`

Auditors expect every accepted finding to map to a documented Risk Register
entry: an owner, a residual-risk score, a Risk Treatment Plan reference. A
suppression without `risk_id` is "compliance laundering" — it makes the
build green without recording why. The orchestrator refuses to apply such
rules so you can't accidentally hide an unaccounted-for risk.

For other frameworks (`asvs`, `oss-license`, `gdpr`), `risk_id` is optional
but encouraged.

## Expiry

Suppressions decay. After `expires`, the orchestrator:

1. Does **not** apply the rule. The original finding becomes blocking again.
2. Adds the rule to the markdown report's "expired suppressions" section.
3. Exits with code `1` until the rule is renewed (new `expires` date) or
   removed.

This forces periodic re-review of waived findings — the antidote to ever-
growing suppression lists.

## Catching expirations early

Run `compliancemaxx validate-config` in CI on a daily schedule:

```yaml
- uses: actions/checkout@v4
- run: npx compliancemaxx validate-config
```

Exits non-zero if any suppression has expired or will expire within 30 days.

## Path globs

Standard minimatch:

| Glob                    | Matches                                              |
|-------------------------|------------------------------------------------------|
| `src/api/secret.ts`     | exactly that file                                    |
| `src/api/**`            | everything under `src/api/`                          |
| `src/**/*.test.ts`      | all `.test.ts` files anywhere under `src/`           |
| `**/__fixtures__/**`    | every `__fixtures__/` directory                      |
| `*.tf`                  | Terraform files at repo root only (no recursion)     |

## Inline / pragma suppressions

Some scanners support inline pragmas (e.g. Checkov's `# checkov:skip=CKV_AWS_19`).
The orchestrator honors those on a tool-by-tool basis but **does not record
them in your dossier**. Prefer config-file suppressions when audit trail matters.
