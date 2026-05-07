# Violation Patterns and Toolchain Orchestration

Organizations rarely fail SOC 2 audits because they lack policies. They fail because operational reality diverges from documentation. This file catalogs the empirical violation patterns the scanner must hunt and the open-source engines used to detect them.

## Real-world violation patterns

### 1. IaC misconfiguration (CC6.1, CC6.6, C1.1)

IaC dictates the actual security posture of deployed infrastructure. Insecure code yields an insecure environment.

**Common failures:**

* `aws_db_instance` or `aws_rds_cluster` with `storage_encrypted = false` or missing `kms_key_id`.
* `aws_s3_bucket` with `block_public_acls = false`, missing server-side encryption, or no bucket policy denying unencrypted PUTs.
* `aws_security_group` with ingress rule `cidr_blocks = ["0.0.0.0/0"]` on ports 22, 3389, 5432, 3306, 6379, 27017, or any database port.
* `aws_ebs_volume` without `encrypted = true`.
* Kubernetes manifests with `hostNetwork: true`, `privileged: true`, or `runAsUser: 0` outside justified system pods.

**Detection:** AST parse of HCL/YAML/JSON. Use Checkov, tfsec, or Terrascan with rule packs aligned to SOC 2 + CIS. Block PR on critical findings.

### 2. IAM over-privilege (CC6.3)

Developers grant wildcard permissions to bypass deployment friction. This is the single most common SOC 2 finding in cloud-native shops.

**Common failures:**

* AWS IAM policy: `Action: "*"`, `Resource: "*"`, `Effect: Allow`.
* Kubernetes `ClusterRole` with `verbs: ["*"]` on `resources: ["secrets"]`.
* GCP IAM bindings with `roles/owner` on a service account.
* Azure: Owner role assigned to non-human principals.

**Detection:** static analysis of IAM JSON, Helm charts, Kubernetes manifests. Flag wildcards. Require scoping to exact ARNs or resource names before merge. Allow exceptions only via documented justification in the PR description that the agentic layer reviews.

### 3. Cryptographic secret sprawl (CC6.1, C1.1)

The leading vector for systemic breaches.

**Common failures:**

* Hardcoded `AKIA...` (AWS access key), `ghp_...` (GitHub PAT), `sk_live_...` (Stripe), `xoxb-...` (Slack bot token).
* Committed `.env` files containing DB URIs, API tokens.
* Private keys (`-----BEGIN RSA PRIVATE KEY-----`) in source.
* `password = "..."` literals in IaC.

**Detection:** GitLeaks, GitHub Advanced Security secret scanning, TruffleHog. High-precision regex plus entropy detection across the *entire commit history* (not just the current diff; old commits remain in the public history of forks).

**Remediation requirement:** finding a leaked secret means rotation, not just removal. The scanner should generate a remediation playbook citing the rotation procedure for the specific provider.

### 4. Change management bypass (CC8.1)

Auditors search ruthlessly for breaks in the chain of custody.

**Common failures:**

* Repository owner temporarily disables branch protection to force-push a hotfix, then re-enables it.
* Direct push to `main` by an admin bypassing PR requirement.
* Self-approved PR (developer is the only reviewer in `CODEOWNERS` for the touched path).
* PR merged before required status checks completed (status check defined as required but not enforcing).
* Force push to `main` rewriting history.

**Detection:**

* Type I miss: a point-in-time check sees branch protection enabled and passes.
* Type II catch: GraphQL query of all commits on `main` over the window. For each commit, fetch the PR. Verify pre-merge `APPROVED` review by a non-author authorized reviewer and passing required status checks. Orphaned commits, force-pushes, and self-merges are exceptions.

GitHub provides this audit trail via the audit log API (org-level) or the commit and PR REST/GraphQL APIs. Stream the audit log to immutable storage; native retention is 90 days.

### 5. Dependency vulnerability accumulation (CC3.2, CC9.2)

Supply chain risk is heavily scrutinized.

**Common failures:**

* `package-lock.json` containing transitive dependencies with known critical CVEs (Log4Shell-class) unpatched for >30 days.
* `go.sum` with vulnerable indirect dependencies.
* Container base images on EOL distros (Alpine 3.10, Debian 9).
* Pinned versions of libraries with public exploits available, no upgrade PR open.

**Detection:** Trivy, Snyk, Dependabot, OSV-Scanner. Track *time-to-remediation* against the SLA in the Risk Management Policy. Aging reports drive Type II evidence.

### 6. Pipeline self-tampering (CC4.1, CC4.2)

A subtle but high-impact failure: a developer modifies the CI workflow to skip security jobs.

**Common failures:**

* Adding `if: github.event.pull_request.user.login != 'bot-account'` to a security job (skipping it for some PRs).
* Changing `continue-on-error: false` to `true` on a SAST step, downgrading it from blocking to advisory.
* Deleting or commenting out a Trivy or Checkov step.

**Detection:** scan diffs to `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`. Any change reducing security-job strictness must be flagged as a high-severity CC4 finding requiring security-team approval. Treat this category as the most important because it can hide every other finding.

### 7. Logging and audit gap (CC7.2)

**Common failures:**

* `aws_cloudtrail` resource missing or with `is_multi_region_trail = false`, `enable_log_file_validation = false`.
* No `aws_guardduty_detector` resource.
* VPC Flow Logs not configured.
* Application logs lack PII redaction, leaking confidential data into long-term storage.

**Detection:** IaC parse for required logging resources. Application-level: scan logging configurations for redaction filters on fields tagged Confidential or Restricted in `Data_Classification_Handling.md`.

## Open-source toolchain orchestration

The scanner is an orchestration layer over best-in-class engines. It does not reimplement parsers.

### Engine inventory

| Tool | Domain | Notes |
|---|---|---|
| **Checkov** | IaC scanning (Terraform, CloudFormation, Kubernetes, Helm, ARM, Serverless) | 1000+ built-in policies aligned to SOC 2, CIS, NIST, HIPAA. Output: SARIF, JSON, CSV. Custom Python policies supported. |
| **tfsec / Trivy IaC** | IaC scanning | Faster than Checkov on large monorepos; narrower built-in policy set. |
| **Trivy** | Container image scanning, SCA, IaC, secret scanning | Single binary covers four domains. Strong CVE database. |
| **Snyk** | SCA, container scan, IaC, code scanning | Commercial; free tier for OSS. Better remediation suggestions than OSS alternatives. |
| **GitLeaks** | Secret scanning across Git history | Fast Go binary. Custom rule support via TOML. |
| **TruffleHog** | Secret scanning with verification | Validates leaked credentials by attempting to authenticate. Higher precision than entropy-only tools. |
| **OPA / Gatekeeper** | Policy as code (Rego) | Use for organization-specific constraints (e.g., "only US-East regions allowed"). Reads naturally as the executable form of `Information_Security_Policy.md`. |
| **Conftest** | Apply OPA policies to config files | Wrapper for testing Kubernetes/Terraform/Dockerfile/Helm against Rego policies. |
| **Semgrep** | SAST (custom rule patterns) | Multi-language; rule packs for common vulnerabilities. |
| **CodeQL** | SAST (deep semantic analysis) | GitHub-native; broader detection than Semgrep but slower and heavier. |
| **Prowler / AuditKit** | Cloud API state checks | Runtime CSPM; not pure repo-scoped but useful for org-level GitHub API checks (MFA enforcement, audit log streaming). |
| **OSV-Scanner** | SCA against OSV database | Lightweight; covers many ecosystems. Good supplement to Trivy. |

### Orchestration architecture

```
PR webhook
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Trigger evaluation                              │
│ - Files changed?                                │
│ - Draft PR?                                     │
│ - Bot author?                                   │
│ - Modifies .github/workflows/?                  │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Parallel deterministic scans                    │
│  ├── Checkov (IaC)         → SARIF              │
│  ├── Trivy (containers)    → JSON               │
│  ├── Trivy (SCA)           → JSON               │
│  ├── GitLeaks (secrets)    → JSON               │
│  ├── Conftest (custom OPA) → JSON               │
│  ├── Semgrep (SAST)        → SARIF              │
│  └── GitHub API queries    → JSON               │
│      (branch protection, audit log config)      │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Normalize to unified schema                     │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ RAG over .compliance/ + agentic mapping         │
│  - Pull relevant policy clause                  │
│  - Map technical finding to TSC + framework tags│
│  - Generate remediation block                   │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│ PR comment (grouped by criterion)               │
│ + Status check (blocking on critical)           │
│ + Evidence persisted to .compliance/evidence/   │
└─────────────────────────────────────────────────┘
```

### Prompt template for the agentic mapping layer

```
System:
  You are a SOC 2 compliance auditor. Given a parsed security finding from a
  deterministic engine and the relevant policy clause, produce an audit
  finding mapped to the appropriate Trust Services Criteria.

  Output schema (YAML):
    primary_criterion: <CC or optional-category identifier>
    related_criteria: [list]
    framework_tags: {soc2: [...], nist_800_53_r5: [...], iso_27001_2013: [...], cis_v8: [...]}
    status: PASS | FAIL
    severity: critical | high | medium | low
    type: deterministic | agentic
    source_tool: <tool name>
    file: <path>
    line: <number or null>
    evidence: <one-sentence factual description>
    policy_clause: <quoted text from .compliance/ with file path and section>
    remediation: |
      <exact code block to fix>
    blocking: <bool>

User:
  Finding from Checkov:
    rule_id: CKV_AWS_17
    file: terraform/rds.tf
    line: 42
    description: Ensure RDS instances have storage encrypted

  Policy clause from Information_Security_Policy.md §4.2:
    "All databases storing customer data must use AES-256 encryption at rest
    with customer-managed KMS keys."

  Produce the audit finding.
```

### Cost and latency considerations

* Run deterministic engines in parallel; total wall-clock is bounded by the slowest (typically Checkov on a large IaC tree, 30-90 seconds).
* Cache scan results by content hash. Re-running the scanner on a no-op rebase should be near-free.
* Agentic mapping is the expensive step in dollar terms. Batch findings: send 10-20 findings per LLM call, not one at a time.
* For Type II evidence collection (history-walk), schedule as nightly batch, not per-PR. The PR-time scanner produces Type I evidence; the nightly walker accumulates Type II.

### Failure mode: tool drift

Open-source engines update rule packs frequently. A passing scan today may fail tomorrow because Checkov shipped a new rule. Pin the engine version in CI. Promote upgrades through a PR like any other dependency. Treat rule-pack diffs as risk-assessment input (CC3.4: changes affecting internal control).
