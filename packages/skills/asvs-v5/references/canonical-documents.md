# Canonical Document Set for ASVS v5.0.0 Verification

The Documented Security Decisions paradigm is the foundational shift in v5.0.0. The agentic auditor cannot verify L2 compliance without reading these artifacts first. This file defines the file patterns, ingestion order, and prompt patterns the pre-flight phase uses.

## Pre-flight contract

Before any chapter-specific check runs, the orchestrator executes a pre-flight pass:

1. Walk the repository for the canonical files below.
2. For each found file, parse and structure its content into a constraint registry.
3. If the minimum set is missing, halt the audit and emit a `PREREQUISITE_FAIL` finding. Downstream chapter checks have no baseline to verify against; running them produces noise, not evidence.
4. If the minimum set is present but a chapter-specific document is missing, halt the audit for that chapter only.

## Search paths (in priority order)

1. `docs/security/` (preferred)
2. `.compliance/`
3. `SECURITY_ARCHITECTURE.md` at repository root
4. `docs/architecture/security/`
5. Wiki references (out of scope for repository-only scanners; emit MANUAL_ATTESTATION_REQUIRED if the team uses an external wiki and the linked content is not in the repo)

## Required documents per chapter

| Document | ASVS section | Required level | What the agent extracts |
|---|---|---|---|
| `encoding-architecture.md` | V1.1 | L2 | per-context output encoding rules (HTML body, attribute, JS, CSS, URL, JSON, XML); deserialization trust boundaries |
| `validation-strategy.md` | V2.1 | L2 | validation boundary location; centralized validator inventory; reject-vs-sanitize policy |
| `frontend-security.md` | V3.1 | L2 | CSP directives; cookie strategy; framing/COOP/COEP/CORP posture; third-party script inventory with SRI |
| `file-handling-policy.md` | V5.1 | L2 | allowed types, size limits, storage isolation strategy, AV scanning policy, serving model |
| `authentication-policy.md` | V6.1 | L2 (mandatory) | factor catalog, MFA enforcement matrix, password policy, recovery flow, IdP relationships |
| `session-policy.md` | V7.1 | L2 | idle timeout, absolute timeout, re-auth thresholds for sensitive operations, federated semantics |
| `authorization-policy.md` + `authorization-matrix.csv` | V8.1 | L2 (mandatory) | role hierarchy, permission matrix, ownership model, ABAC rules, multi-tenant isolation rules |
| `cryptographic-inventory.md` | V11.1 | L2 | algorithm choices per use case, key lifecycle, KMS integration, post-quantum readiness |

The two **mandatory** documents (V6.1, V8.1) are non-negotiable for L2. Their absence is a structural failure equivalent to skipping the audit.

## Supporting artifacts

| Artifact | Purpose |
|---|---|
| `docs/architecture.md` or threat model output (Threat Dragon, IriusRisk export) | Establishes data classification tiers and external trust boundaries; informs V14 |
| `openapi.yaml` / `swagger.json` / `schema.graphql` | Enumerates the attack surface for V4 and V8.2.1 coverage analysis |
| `*.tf`, `k8s/*.yaml`, `Dockerfile`, `docker-compose.yml` | V12, V13, V14.2 IaC verification |
| `package.json`, `pom.xml`, `go.mod`, `Cargo.toml`, `requirements.txt`, SBOM | V13.1 SCA |
| `.github/workflows/*.yml` / `.gitlab-ci.yml` | V13.2 pipeline hardening; also the scanner's own integration point |
| `data-classification.md` or schema annotations | V14.1 |

## Constraint extraction prompt pattern

When the agent ingests a Documented Security Decision, it produces a structured constraint registry. Example for `authentication-policy.md`:

```yaml
extracted_from: docs/security/authentication-policy.md
constraints:
  - id: AUTH-1
    asvs: V6.2.1
    text: "Passwords stored using Argon2id with memory >= 64 MiB"
    type: deterministic_check
    target: hash_function_invocation
  - id: AUTH-2
    asvs: V6.3
    text: "Admin role requires WebAuthn; TOTP not acceptable for admin"
    type: agentic_check
    target: route_protection_for_admin_paths
  - id: AUTH-3
    asvs: V6.4
    text: "Password recovery tokens TTL = 30 minutes, single-use"
    type: deterministic_check
    target: recovery_token_config
```

## Verification prompt pattern

For each constraint, the agent runs a verification prompt with three slots: the constraint, the relevant code, and a strict JSON output schema. The prompt below is the V8 broken access control template; adapt for other chapters:

```text
You are an Application Security Architect verifying OWASP ASVS v5.0.0 Level 2.

Constraint to verify (extracted from docs/security/authorization-policy.md):
{constraint_text}

Source code to evaluate:
{file_path}:
{file_contents}

Task:
1. Determine whether the implementation satisfies the constraint.
2. Cite the exact line numbers in the source code that support your conclusion.
3. Quote the policy clause verbatim.
4. If non-compliant, propose a minimal remediation diff.

Output ONLY valid JSON matching this schema:
{
  "asvs_id": "<V-prefixed ID>",
  "compliant": <boolean>,
  "evidence_lines": [<int>, ...],
  "policy_clause": "<verbatim quote>",
  "justification": "<one paragraph>",
  "remediation": "<diff or null>"
}

Constraints on your reasoning:
- Limit analysis to the provided code and constraint. Do not assume external compensating controls.
- If you cannot determine compliance from the provided files, output compliant=null with a justification listing what additional file you need.
- Do not paraphrase the policy clause; quote it.
```

The `compliant=null` escape hatch is important. It prevents the agent from hallucinating a pass when it lacks context, and it gives the orchestrator a signal to load additional context (e.g., a middleware definition file) and re-prompt.

## Failure mode: undocumented intent

If a security control is implemented in code but not documented, the agent treats it as **undocumented intent**. The verdict is not PASS; it is `STRUCTURAL_DEBT`. The recommendation is to document the decision and re-run. This is by design: ASVS v5.0.0 treats documentation as part of the security architecture, not as an afterthought. A correctly-implemented but undocumented control fails because the next maintainer cannot verify, audit, or extend it.

## Failure mode: contradictory documentation

If two documents specify conflicting constraints (e.g., `session-policy.md` says 8h idle, `authentication-policy.md` says 30min idle), the agent emits a `POLICY_CONFLICT` finding. The orchestrator does not arbitrate; the team must reconcile.
