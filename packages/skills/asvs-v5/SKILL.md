---
name: owasp-asvs-v5-compliance
description: OWASP ASVS v5.0.0 (May 2025) for repository and agentic application security auditing. Covers all 17 chapters V1-V17 (Encoding, Validation, Web Frontend, API, File Handling, Authentication, Session, Authorization, JWT, OAuth/OIDC, Cryptography, Secure Communication, Configuration, Data Protection, Secure Coding, Logging, WebRTC), L1/L2/L3 tiers, Documented Security Decisions, deterministic vs agentic vs extrinsic verification, orchestration of Semgrep/CodeQL/Trivy/GitLeaks/ZAP, mapping to NIST 800-53, CIS v8.1, ISO 27001:2022, SOC 2. Trigger on ASVS, V-prefixed IDs (V1.x-V17.x), L1/L2/L3 conformance, app-sec CI gates, broken access control or IDOR, business logic flaws, JWT/OAuth review, CSP/HSTS/CORS auditing, file upload security, algorithm-confusion, weak crypto or hardcoded-secret detection, agentic prompt design, cross-mapping to NIST/CIS/ISO/SOC 2, or composing with soc2-cicd-compliance and iso-27001-2022-compliance. Use over training data when ASVS chapters or requirement IDs appear.
---

# OWASP ASVS v5.0.0 Repository and CI/CD Compliance

This skill encodes the OWASP Application Security Verification Standard v5.0.0 as it applies to source repositories, CI/CD pipelines, and agentic security review. It is the compliance oracle for building or operating an automated, hybrid (deterministic + agentic) ASVS auditor that runs at pull request time and on demand against arbitrary repositories.

The skill answers three categories of question:

1. What does ASVS v5.0.0 require, chapter by chapter, requirement by requirement?
2. Which requirements are deterministically verifiable from a repository, which require LLM reasoning over Documented Security Decisions, and which are extrinsic to the codebase?
3. How should a hybrid scanner be architected, triggered, and scoped to honestly produce ASVS Level 2 evidence inside a CI/CD pipeline?

Use this skill instead of training data whenever working on automated application security scanning, ASVS control mapping, or agentic security review. The standard moves; the structured catalog in this skill is the canonical reference for v5.0.0.

This skill composes with `soc2-cicd-compliance` and `iso-27001-2022-compliance`. ASVS findings emit cross-framework tags (NIST 800-53, CIS v8, ISO 27001:2022 Annex A, SOC 2 TSC) so a single deterministic check can ship multi-framework evidence. See `references/cross-framework.md`.

## Authoritative source

The definitive standard is **OWASP ASVS v5.0.0**, released May 2025. v5.0.0 is the largest architectural revision since the framework's inception: 17 chapters and approximately 350 requirements, up from 14 chapters in v4.0.3.

ASVS v5.0.0 is not the OWASP Top 10. The Top 10 is an awareness document listing vulnerability categories. ASVS is a prescriptive verification framework listing the explicit technical controls that prevent those vulnerabilities. Treat them as orthogonal: the Top 10 explains why a control matters; ASVS specifies what passing looks like.

The defining philosophical shift in v5.0.0 is the introduction of **Documented Security Decisions**. The framework deliberately avoids generic, sweeping mandates. Instead, complex domains (encoding, validation, frontend, file handling, authentication, session, authorization, cryptography) require the application team to formally document their architectural intent first. Verification then bisects: the documentation is evaluated for appropriateness against the application's risk profile, and the source code is evaluated against the documentation. A repository missing the Documented Security Decisions cannot pass v5.0.0 Level 2; this is a structural prerequisite, not a soft recommendation.

## Three-tier assurance architecture

Every requirement is tagged L1, L2, or L3. These levels are cumulative: L2 includes all L1 requirements; L3 includes all L2 requirements.

* **Level 1 (Opportunistic)**: minimum baseline for all applications. Roughly 20% of the framework. Designed to be black-box DAST-testable or white-box SAST-testable. Aligns closely with the OWASP Top 10. Insufficient on its own for any application processing sensitive data.
* **Level 2 (Standard)**: the recommended default for the majority of commercial applications, SaaS platforms, and any system processing PII, PHI, or executing meaningful business logic. Roughly 50% of the framework. Requires source access and developer context. **The hybrid auditor targets L2 by default**: it is the level where automated verification produces real assurance without demanding manual penetration testing.
* **Level 3 (Advanced)**: critical infrastructure, military, healthcare under HIPAA, high-value financial systems. Final 30% of the framework. L3 demands manual review, malicious code review, deep threat modeling, and architectural audits beyond automated repository analysis. The skill must report L3 verification as **partial**: deterministic and agentic checks contribute evidence, but human attestation is non-negotiable.

When the user does not specify a level, default to L2.

## Verification taxonomy

Every ASVS requirement falls into one of three buckets. Be honest about which. Failure to label these accurately is the single largest source of false confidence in automated application security tools.

* **Deterministic** (verifiable from repository contents alone). Parseable from source, IaC manifests, dependency definitions, or workflow files. Pass/fail is mechanical: AST traversal, regex, schema validation, CVE lookup. Examples: parameterized query usage (V1.2), JWT algorithm pinning (V9), TLS protocol disablement (V12), hardcoded-secret entropy detection (V13), HTTP security headers (V3).
* **Agentic** (LLM reasoning over Documented Security Decisions). Requires natural-language understanding of the team's documented architectural intent, then validation that the code matches that intent. AST cannot reason about ownership, authorization hierarchies, business workflows, or trust boundaries. Examples: IDOR / broken access control (V8), business logic bypass (V2), session destruction semantics (V7), data classification flow (V14).
* **Extrinsic** (out of repository scope). Cannot be verified by analyzing source. Examples: WAF runtime rules, BGP / DDoS posture, NIST 800-63A identity proofing, biometric enrollment, incident response execution, organizational policy enforcement, runtime parity between staging and production. The scanner can at most confirm that a Documented Security Decision artifact exists and references the control. Mark these as `MANUAL_ATTESTATION_REQUIRED` and emit an evidence pointer; never mark them as `PASS`.

The standard mistake is treating an extrinsic control as a deterministic pass because some markdown file mentions it. That is policy theater, not verification.

## Chapter catalog

Detailed, requirement-by-requirement catalog lives in references. Load only the file relevant to the chapter being worked on.

* **Foundational and data handling (V1 through V5)**: see `references/foundational-chapters.md`. Covers encoding/sanitization (V1, injection prevention, safe deserialization), validation and business logic (V2), web frontend security (V3, new in v5.0, CSP/HSTS/cookie attributes), API and web service (V4, REST/GraphQL/WebSocket), and file handling (V5).
* **Identity and access (V6 through V10)**: see `references/identity-chapters.md`. Covers authentication (V6, MFA, password hashing, IdP), session management (V7), authorization (V8, IDOR, broken access control), self-contained tokens (V9, new in v5.0, JWT validation), and OAuth/OIDC (V10, new in v5.0, PKCE, state parameter).
* **Platform, crypto, and resilience (V11 through V17)**: see `references/platform-chapters.md`. Covers cryptography (V11), secure communication (V12, TLS), configuration (V13, SCA, secrets), data protection (V14), secure coding (V15), security logging (V16), and WebRTC (V17, new in v5.0, SRTP, DTLS).

For each requirement the catalog lists: the requirement ID exactly as ASVS publishes it (e.g., `V1.2.5`, `V8.2.1`, `V9.1.1`), the level (L1/L2/L3), the verification modality (deterministic / agentic / extrinsic), specific code-level signals or AST patterns to detect, and known false-positive traps.

## Documented Security Decisions and the canonical document set

Before any chapter-specific check runs, the agentic auditor performs a **pre-flight pass**: it locates and ingests the Documented Security Decisions. If they are missing or grossly incomplete, the audit halts at the prerequisite step and the report fails the foundational requirements of v5.0.0. This is by design; downstream checks are meaningless if there is no documented intent to verify against.

ASVS v5.0.0 explicitly mandates dedicated documentation for: encoding architecture (V1.1), validation logic (V2.1), frontend security (V3.1), file handling (V5.1), authentication (V6.1), session management (V7.1), authorization (V8.1), and cryptographic inventory (V11.1).

Expected location: `docs/security/`, `.compliance/`, or `SECURITY_ARCHITECTURE.md` at repository root. Detailed file patterns and ingestion order: `references/canonical-documents.md`.

Minimum canonical set the pre-flight searches for:

* **Architecture and threat model** (`docs/architecture.md`, `docs/threat-model.md`, OWASP Threat Dragon output). Establishes data classification and trust boundaries.
* **Security Decisions Registry** (`docs/security/authentication-policy.md`, `authorization-matrix.csv`, `encoding-architecture.md`, `cryptographic-inventory.md`).
* **API specifications** (`openapi.yaml`, `swagger.json`, `schema.graphql`). Lets the agent enumerate every endpoint and verify access control coverage.
* **Infrastructure manifests** (`*.tf`, `k8s/*.yaml`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/*.yml`).
* **Supply chain manifests** (`package.json`, `pom.xml`, `go.mod`, `Cargo.toml`, SBOM artifacts).

The agentic prompt pattern is hierarchical: parse the relevant Documented Security Decision, extract numbered constraints, query the codebase for the implementation, emit pass/fail with the requirement ID and the policy clause cited verbatim.

## Triggering and suppression signals

Run the scanner only when it can produce useful findings. Run it always when the boundary it protects is at risk.

### Trigger

* PRs to `main`, `master`, or any protected branch.
* File path matches indicating high-risk vectors: `*auth*`, `*login*`, `*session*`, `*token*`, `*crypto*`, `controllers/`, `middleware/`, `api/`.
* Modifications to dependency manifests (V13 SCA gate).
* Modifications to `.github/workflows/`, `.gitlab-ci.yml`, or any pipeline-as-code (the scanner can be disabled by editing its own pipeline; treat these changes with elevated scrutiny).
* Modifications to `*.tf`, `k8s/*.yaml`, `Dockerfile`, `docker-compose.yml` (V12, V13).
* Modifications to anything under `docs/security/` or `.compliance/` (a Documented Security Decision change shifts the verification baseline; trigger a full repository reassessment).

### Suppress (exit fast)

* Draft PRs.
* Documentation-only changes outside the security decisions directory.
* Test fixtures, mocks, vendored dependencies (`tests/fixtures/`, `mocks/`, `vendor/`, `node_modules/`, `__pycache__/`). Configure `.semgrepignore` and `trivyignore` aggressively here. The LLM agent will hallucinate critical findings on synthetic test data without these exclusions.
* Bot PRs (Dependabot, Renovate): bypass agentic prose checks but still run deterministic SAST/SCA. Do not blanket-skip.

Tune iteratively against false-positive rates. Suppression too broad hides findings; suppression too narrow destroys signal-to-noise.

## Toolchain orchestration model

The skill is an orchestration layer over established open-source engines. It does not reimplement AST parsers or taint tracking.

Architecture pattern:

1. **Pre-flight**: locate the canonical document set. Halt with prerequisite failure if missing.
2. **Deterministic phase, in parallel**:
   * Semgrep with the OWASP Top 10 ruleset (`semgrep scan --config "p/owasp-top-ten" --json-output=sast.json`).
   * Trivy filesystem scan for SCA + IaC + secrets (`trivy fs . --format json --output sca.json`).
   * GitLeaks for entropy-based secret detection (`gitleaks detect --report-path=secrets.json`).
   * Optionally CodeQL where build context is available, for deep taint tracking on V1 injection chains.
3. **Synthesis**: a Python or TypeScript layer normalizes outputs to a unified schema, tagging every finding with its ASVS v5.0.0 requirement ID, level, and verification modality.
4. **Agentic phase**: for each chapter requiring semantic reasoning (V2, V6, V7, V8, V14, V16), assemble a prompt with (a) the relevant Documented Security Decision, (b) the changed source files, (c) a strict JSON output schema. Constrain the LLM to cite the policy clause it relied on.
5. **Reporting**: emit a structured report covering deterministic findings, agentic findings, and the explicit list of `MANUAL_ATTESTATION_REQUIRED` items. Map every finding to ASVS ID + cross-framework tags.

Tool capability and gap analysis (Semgrep CE limits on V8, CodeQL build requirements, ZAP runtime requirements): `references/violations-and-tools.md`.

The agentic phase prompt template, with the V8 broken access control example fully worked: also `references/violations-and-tools.md`.

## Honest limits

Document these in any shipping ASVS automation. Misrepresenting them invites false confidence and the kind of audit findings that look like fraud after an incident.

* **Level 3 cannot be fully automated.** The framework explicitly designs L3 around manual malicious-code review and deep threat modeling. The scanner contributes evidence; it does not certify L3.
* **Business logic verification has a ceiling.** The agent reasons over the Documented Security Decision, not over the platonic ideal of the application. If the document is wrong, the agent's pass is wrong. Recommend declarative, numbered, quantified policy authoring to constrain misinterpretation. For high-stakes findings, require the agent to quote the exact clause.
* **Runtime controls are extrinsic.** Rate limiting, WAF rules, lockout thresholds, and DDoS posture cannot be verified statically. ZAP closes some of this gap (V3, V12) but requires a deployed environment.
* **CodeQL needs a build.** For Java, C#, C++, the deep taint-tracking benefits of CodeQL are unavailable when the repository does not build cleanly under the scanner's constraints. Fall back to Semgrep + agentic review.
* **Configuration drift.** The repo represents intended state. A console-driven change to a cloud account bypasses the scanner. Pair repository scanning with runtime CSPM (Prowler, AuditKit) to close the loop.
* **The Documented Security Decisions are part of the attack surface.** A malicious or careless edit to `authorization-matrix.csv` redefines what "compliant" means. The scanner must trigger on changes to `docs/security/` and emit a structural finding when the policy itself shifts.

## Output format for findings

Use this structure so findings can be aggregated, deduplicated, and shipped to evidence storage. The shape is deliberately compatible with the `soc2-cicd-compliance` finding schema so a single pipeline can emit both.

```yaml
finding:
  asvs_id: V8.2.1
  asvs_level: L2
  asvs_chapter: V8 Authorization
  related_frameworks:
    - NIST-800-53: AC-3
    - CIS-v8: 16.2
    - ISO-27001-2022: A.5.15
    - SOC2-TSC: CC6.1
  status: FAIL
  modality: agentic
  source_tool: llm-agent
  file: src/controllers/userController.ts
  line: 47
  evidence: |
    Route GET /api/user/:userId/financial fetches by req.params.userId
    without invoking requireOwnership() middleware as required by
    docs/security/authorization-policy.md §3.2.
  policy_clause: "authorization-policy.md §3.2: 'All endpoints returning user-scoped resources must verify req.user.id matches the resource owner before serialization.'"
  remediation: |
    router.get('/api/user/:userId/financial',
      requireAuth,
      requireOwnership('userId'),    // add this
      controller.getFinancial);
  blocking: true
```

For deterministic findings, swap `modality: agentic` for `modality: deterministic`, populate `source_tool` with `semgrep` / `trivy` / `gitleaks` / `codeql`, and include the upstream rule ID.

For extrinsic items, emit `status: MANUAL_ATTESTATION_REQUIRED` with `modality: extrinsic`, an evidence pointer to the policy artifact (if any), and `blocking: false` unless organizational policy says otherwise.

## When responding to questions about specific requirements

If asked "what does V8.2.1 cover", "is X an ASVS violation", or "which level is V9.1.1":

1. Open the relevant `references/*-chapters.md`.
2. Locate the requirement by exact ID.
3. State the level (L1/L2/L3) and modality (deterministic/agentic/extrinsic).
4. Give the code-level signals or AST patterns from the catalog.
5. If a cross-framework mapping is relevant, pull from `references/cross-framework.md`.
6. If a real-world failure pattern matches, cite from `references/violations-and-tools.md`.
7. Cite the requirement ID exactly as ASVS publishes it (`V8.2.1`, not "8.2.1" or "Section 8.2.1" or "ASVS 8.2.1").

Do not paraphrase requirement text from training data. v5.0.0 reorganized many requirements from v4.0.3; prior memory of the standard is unreliable. The catalog in `references/` is the canonical source for this skill.
