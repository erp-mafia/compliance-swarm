# Verification Tiers

The honest scope of automated GDPR detection. Every requirement maps to one of three tiers; misclassification is the primary cause of false confidence in privacy tooling. The ordering below is by tier, not by article number, because the operational decision (which engine handles this check?) is tier-driven.

## Tier 1: deterministically verifiable from the repository

Static analysis with high confidence. AST parsing, regex, schema validation, IaC parsing. The GDPR-Bench-Android study found that formal-AST baselines achieve high specificity but limited recall; LLMs improve line-level recall (Qwen2.5-72B at 61.6% Accuracy@1 line-level) at the cost of some specificity. For Tier 1 checks that are mechanical, prefer the deterministic engine.

### Hardcoded secrets and credentials (Art. 32)

API keys, OAuth tokens, database passwords, private keys committed to source. Direct, indisputable Article 32 violation. Run secret scanners across the full Git history, not just HEAD; secrets remain compromised after they are removed from the working tree.

Tools: GitLeaks, Semgrep secret rules, Trufflehog. Wrap as a pre-commit hook *and* a CI gate; the hook fails fast for the developer, the CI gate is the audit-grade signal.

### Insecure data transmission (Art. 32, Art. 5(1)(f))

Plain-HTTP API calls, deprecated TLS configurations (SSLv3, TLS 1.0, TLS 1.1), weak cipher suites, missing certificate validation (`verify=False` in requests, `rejectUnauthorized: false` in Node). AST-detectable.

### Missing cryptographic primitives on PII (Art. 32)

ORM column definitions storing entities matching known sensitive patterns (`SocialSecurityNumber`, `personnummer`, `HealthRecord`, anything Fideslang-labeled `user.payment.*`, `user.health.*`, `user.biometric.*`, `user.genetic.*`) without encryption decorators or hashing functions. AST-detectable when the ORM is annotation-driven (TypeORM, SQLAlchemy with declarative base, Hibernate JPA).

### Unconstrained data collection (Art. 5(1)(c) data minimization)

OpenAPI request payload schemas accepting fields not functionally required for the documented endpoint operation. The deterministic check is `additionalProperties: false`; without it, the schema admits unbounded extraneous PII.

### Invasive third-party dependencies (Art. 6, Art. 25)

Tracking SDKs, analytics libraries, advertising networks present in dependency manifests (`package.json`, `build.gradle`, `pom.xml`, `requirements.txt`, HTML script tags) without consent management orchestration. The skill maintains a denylist of known-invasive SDKs; presence triggers a Tier 2 follow-up to validate consent gating.

### Soft-delete masquerading as Article 17 erasure

AST pattern matching on controller methods registered as the erasure endpoint. If the body is `UPDATE ... SET is_deleted = ...` or equivalent ORM `update()` rather than `DELETE` (or a documented cryptographic shredding call), it is non-compliant.

### IaC default-secure violations (Art. 25)

Terraform / CloudFormation / Pulumi / Kubernetes manifest parsing for:
* Storage resources without encryption configuration
* Storage resources with public ACLs
* Network rules with `0.0.0.0/0` ingress on ports serving PII workloads
* IAM policies with wildcard actions on resources holding PII
* Missing mandatory security headers on API gateway / ingress configurations

Tools: Checkov, Trivy IaC, OPA/Rego, tfsec, Kics. The agent should run multiple in parallel and deduplicate findings by `(file, line, semantic_rule)`.

## Tier 2: agentic reasoning over policy artifacts

Requires natural-language understanding cross-referenced with code reality. An LLM (or a ReAct-style agent; the GDPR-Bench-Android study reported the highest file-level Accuracy@1 of 17.4% from a ReAct configuration) extracts prescriptive statements from policy markdown, then validates implementation against them. The prompt templates for these checks are in `agentic-prompts.md`.

### RoPA drift (Art. 30)

The agent receives the parsed `.compliance/ropa.yaml` and the Privado data flow JSON. It enumerates flows present in the code but not in the RoPA (under-documentation, the Article 30 violation) and flows present in the RoPA but not in the code (stale documentation, a less severe but still flagged drift).

### Purpose limitation (Art. 5(1)(b), Art. 6)

The agent reads the OpenAPI spec for an endpoint, extracts the documented business purpose, then reads the controller method to enumerate which data objects are queried and returned. If the data objects exceed what the documented purpose justifies, the agent flags purpose creep.

### Consent logic vs. cookie policy (Art. 6, Art. 7)

The agent reads `.compliance/consent_mappings.yaml` and the frontend consent management code. It validates that scripts categorized as analytics or marketing only initialize after the corresponding consent state is recorded. The check requires understanding both the policy intent and the runtime control flow.

### DPIA-vs-implementation drift (Art. 35)

The agent reads each DPIA in `.compliance/dpia_inventory/`, extracts the "measures envisaged" section, and verifies each named control exists in code. A DPIA promising "all access logged to immutable storage" must have a corresponding logging configuration in IaC.

### Privacy policy semantic alignment (Art. 12, Art. 13)

The agent compares `.compliance/privacy_policy.md` claims about data categories collected, processing purposes, recipients, and retention against the union of all detected processing in code. Mismatches are misrepresentations to data subjects, an Article 12/13 violation.

### Incident response runbook completeness (Art. 33, Art. 34)

The agent reads `.compliance/incident_response.md` and validates it against the EDPB Guidelines 9/2022 phase structure (detection, assessment, containment, escalation, notification, communication). Missing phases or deprecated communication channels block the build.

## Tier 3: fundamentally out of repo

The repository cannot prove these. The scanner can at most check for an *evidence pointer*: a URI, signed credential, or external API reference that points to where the proof lives.

### Physical security (related to Art. 32 organizational measures)

A data center server room being locked is unprovable from code. The scanner expects `.compliance/evidence_pointers.yaml` to contain a URI to the latest physical facility audit (SOC 2 report covering the colocation provider, ISO 27001 certificate scope, etc.).

### Employee privacy training (Art. 39 DPO support, organizational measures)

The scanner expects an evidence pointer to an HR / LMS API endpoint confirming all currently active contributors (matched by email against the Git committer set) have completed annual privacy training within a documented validity window.

### Executed DPA / SCC contracts (Art. 28, Art. 46)

The repository may contain Markdown templates of Data Processing Agreements and SCCs. The scanner cannot verify that a specific vendor *signed* a specific instance. The evidence pointer is an URI to the contract management system (DocuSign API, Ironclad, etc.) returning the signed instance keyed by vendor + module + execution date.

### Regulator notification logs (Art. 33)

Whether a notification was actually sent to the supervisory authority within 72 hours of awareness is a runtime, organizational fact. The scanner expects an evidence pointer to a notification log API.

### Board independence and governance (organizational measures)

Governance structure, role separation between DPO and CISO, board oversight of the privacy program. Out of repo entirely. The scanner verifies that the *policy* documents these structures exist, not that they actually do.

## The Honest Output Pattern

When the scanner emits a finding, it should annotate the tier explicitly:

```
[GDPR Art. 32 / SC-28 / A.8.24]
Tier 1 (deterministic): server_side_encryption_configuration missing on aws_s3_bucket.user_uploads.

[GDPR Art. 30]
Tier 2 (agentic): ropa.yaml does not document the data flow from /api/v1/orders to Stripe (detected by Privado at services/checkout.ts:142).

[GDPR Art. 39 / Organizational]
Tier 3 (out of repo): no evidence pointer found for employee privacy training. Add an entry to .compliance/evidence_pointers.yaml referencing the LMS API.
```

The user knows immediately which findings can be fixed by editing code, which require updating policy markdown, and which require organizational action outside engineering's scope. This honesty is what makes the scanner trustworthy.