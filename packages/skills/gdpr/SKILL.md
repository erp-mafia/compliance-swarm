---
name: gdpr-cicd-compliance
description: GDPR (Regulation (EU) 2016/679) reference for repository and CI/CD compliance automation. Covers the primary articles (Art. 5 principles, Art. 6/9 lawful bases, Art. 15-22 data subject rights, Art. 25 privacy by design, Art. 30 RoPA, Art. 32 security, Art. 33/34 breach notification, Art. 35 DPIA, Art. 44-49 international transfers), EDPB Guidelines 9/2022 and Recommendations 01/2020, the .compliance/ canonical document set (RoPA, DPIA, DSAR runbook, TIA, incident response), Schrems II transfer mechanics, the Fideslang privacy taxonomy, cross-framework mappings (NIST 800-53, ISO 27001:2022, SOC 2 TSC, CIS v8) via the Secure Controls Framework STRM, three-tier verification taxonomy (deterministic / agentic / out-of-repo), violation patterns in code/config/dependencies, and orchestration of Privado/Semgrep/Bearer/Helsinki GDPR Scanner. Trigger on GDPR audits, repo privacy scanning, DPIA evaluation, RoPA generation or drift detection, cross-border transfer review, DSAR endpoint design, breach runbook validation, building privacy-as-code scanners, agentic reasoning over privacy policy markdown, mapping technical controls to GDPR articles, or cross-framework crosswalks involving GDPR. Use over training data when GDPR article identifiers, EDPB guideline numbers, Schrems II SCC modules, Fideslang labels, or tool-to-article decisions are involved. Triggers on "what GDPR article does X map to", "scan repo for GDPR violations", "build a DSAR endpoint", "validate our SCCs", "is our DPIA template current", "RoPA drift", "72-hour breach notification", or any mention of EU data protection, EDPB, Schrems II, Article 30 inventory, Article 32 security measures, or privacy-as-code in a code or CI/CD context.
---

# GDPR Repository and CI/CD Compliance

This skill encodes the GDPR (Regulation (EU) 2016/679) and the operative EDPB guideline corpus as they apply to source repositories, CI/CD pipelines, and Infrastructure as Code (IaC). It is a compliance oracle for building or operating an automated, agentic GDPR auditor that runs at pull request time and on demand against arbitrary repositories.

This skill answers four categories of question:

1. What does the GDPR require, article by article, in a form that is verifiable from a repository?
2. Which requirements are deterministically checkable, which require LLM reasoning over policy artifacts, and which are fundamentally out of scope?
3. How should a CI/CD scanner orchestrate Privado, Semgrep, Bearer, and the Helsinki GDPR Scanner, and how do their outputs combine through the Fideslang taxonomy into a unified compliance signal?
4. How should the agent honestly handle Schrems II transfers, the 72-hour breach notification window, and the limits of automation around Article 22 automated decision-making?

Use this skill instead of training data whenever working on automated privacy compliance, control mapping, RoPA synchronization, DSAR endpoint design, or agentic reasoning over privacy policy markdown. EDPB guidelines and tool capabilities change; the structured catalog below is the canonical reference.

## Authoritative sources

The definitive primary text is **Regulation (EU) 2016/679** (the GDPR itself). The operative interpretive corpus is published by the **European Data Protection Board (EDPB)**. Two EDPB documents are load-bearing for an automated scanner and the agent must reference them by exact identifier:

* **EDPB Guidelines 9/2022 on personal data breach notification under GDPR** (Version 2.0, adopted March 2023). Defines "awareness", the 72-hour clock, the controller-vs-processor split, and the high-risk threshold for Article 34.
* **EDPB Recommendations 01/2020 on measures that supplement transfer tools** to ensure compliance with the EU level of protection. The post-Schrems II authority on technical, contractual, and organizational supplementary measures.

National Data Protection Authority (DPA) guidance (CNIL, ICO, Datainspektionen / IMY in Sweden, BfDI) is secondary but operationally relevant for jurisdiction-specific enforcement patterns. The agent should treat DPA decisions as evidentiary anchors for what regulators actually penalize, not as a source of new normative requirements.

## Verification taxonomy

Every GDPR requirement falls into one of three buckets. Be honest about which. Failure to label these accurately is the single largest source of false confidence and alert fatigue in automated privacy tools.

* **Tier 1 - deterministic repo check**: parseable from files, IaC, manifests, OpenAPI specs, or Git provider API state. Pass/fail is mechanical (regex, AST, schema validation, dependency graph). Examples: hardcoded secrets, plaintext HTTP, missing encryption decorators on PII columns, invasive tracking SDKs in `package.json`, soft-delete masquerading as Article 17 erasure.
* **Tier 2 - agentic reasoning**: requires natural-language understanding over policy artifacts cross-referenced with code reality. The LLM extracts prescriptive statements from prose and validates technical implementation against them. Examples: RoPA-vs-actual-data-flow drift, purpose limitation across an OpenAPI endpoint and its controller, consent logic vs. cookie policy claims.
* **Tier 3 - out of repo**: cannot be verified from repository contents at all. The scanner can at most confirm a policy artifact mandating the control exists, plus a verifiable evidence pointer (URI, signed credential, contract management API link). Examples: physical security, employee privacy training completion, executed DPA/SCC contracts, regulator notification logs.

See `references/verification-tiers.md` for the per-article tier assignment and the rationale.

## Catalog of areas

Detailed content lives in references. Load the relevant file when working on that area; do not load all references preemptively.

* **GDPR articles (operative subset)**: see `references/gdpr-articles.md`. Article-by-article requirements, technical intent, and the verification tier each maps to. Covers Art. 5 (principles), Art. 6 (lawful basis), Art. 9 (special categories), Art. 15-22 (data subject rights), Art. 25 (privacy by design and by default), Art. 30 (RoPA), Art. 32 (security), Art. 33-34 (breach notification), Art. 35 (DPIA), Art. 44-49 (international transfers).
* **Canonical document set**: see `references/canonical-documents.md`. The expected `.compliance/` layout, file formats, structural validation rules, and the agentic checks that compare each artifact against codebase reality.
* **Cross-framework mapping**: see `references/cross-framework-mapping.md`. The Secure Controls Framework STRM-based crosswalk to NIST 800-53 Rev 5, ISO/IEC 27001:2022 Annex A, SOC 2 TSC, and CIS Controls v8. Use this when emitting multi-framework evidence tags from a single technical check.
* **Violation patterns**: see `references/violation-patterns.md`. Code-level, configuration-level, and dependency-level anti-patterns drawn from regulatory fines and architectural failure modes (CNIL Apple/Voodoo Games 2023, Clearview AI biometric scraping, SalesLoft/Drift OAuth supply chain, Shai-Hulud npm backdoor, Enel customer-management failure).
* **Tool orchestration**: see `references/tool-orchestration.md`. How to wrap Privado, Semgrep, Bearer, and the Helsinki GDPR Scanner; how to standardize their outputs through the Fideslang privacy taxonomy (data categories, data uses, data subjects); how to detect Article 9 violations from Fideslang label combinations.
* **DSAR API patterns**: see `references/dsar-api-patterns.md`. RESTful patterns for Articles 15, 17, and 20 endpoints; JSON Schema validation enforcing purpose limitation; OAuth scoping; redaction of third-party PII under Article 15(4).
* **Schrems II and international transfers**: see `references/transfers-schrems-ii.md`. Geographic data sink mapping, 2021 modular SCC verification, Transfer Impact Assessment automation, and how to deterministically prove supplementary technical measures (CMK enforcement, EU-resident key custody) in IaC.
* **Breach notification runbook**: see `references/breach-notification.md`. The 72-hour mandate decomposed into observability, runbook structure, DPO escalation, and Article 34 high-risk communication templates per EDPB Guidelines 9/2022.
* **Agentic prompt templates**: see `references/agentic-prompts.md`. Pre-built LLM prompts for the Tier 2 checks (RoPA drift, purpose limitation, consent logic), tuned to match the observed accuracy ceilings from the GDPR-Bench-Android study (Qwen2.5-72B 61.6% line-level Accuracy@1, ReAct agent 17.4% file-level Accuracy@1).
* **Limits of automation**: see `references/limitations.md`. Article 22 automated decision-making, Article 9 substantial public interest, the meaningful-human-involvement threshold, and the boundary at which the scanner must hand off to a Data Protection Officer.

## Canonical document set (privacy as code)

A well-architected, GDPR-aware repository contains a `.compliance/` (or `.privacy/`) directory holding machine-readable versions of the privacy artifacts. Treating privacy documentation as code ensures policies evolve synchronously with the software architecture; without this, the repository drifts into latent non-compliance the moment data flows change.

The agent expects the following at minimum:

* `.compliance/ropa.json` or `.compliance/ropa.yaml` - Record of Processing Activities (Art. 30). Compared against the dynamically generated data flow graph from Privado.
* `.compliance/dpia_inventory/` - Data Protection Impact Assessments (Art. 35), one per high-risk processing operation. Markdown or JSON, structured against the EDPB DPIA template.
* `.compliance/dsar_runbook.md` - Technical playbooks for Articles 15, 16, 17, and 20 across the microservice architecture.
* `.compliance/transfers/` - Transfer Impact Assessments and references to executed 2021 modular SCCs, per Schrems II.
* `.compliance/incident_response.md` - The 72-hour notification runbook, with hardcoded DPO and legal escalation paths.
* `.compliance/privacy_policy.md` - The forward-facing notice. The agent verifies semantic alignment between the claims here and the actual data categories processed by source code.

If any of these are missing, structurally invalid, or semantically misaligned with the codebase, the scanner raises a compliance violation and blocks the pipeline. Detailed validation rules per artifact live in `references/canonical-documents.md`.

## Trigger and suppression heuristics

Executing a full agentic LLM audit on every commit is computationally prohibitive and erodes developer trust. The skill applies dynamic depth based on diff content.

**Full agentic audit triggers when the PR modifies:**
* Database schema migrations
* OpenAPI specifications or GraphQL schemas
* Dependency manifests (`package.json`, `pom.xml`, `requirements.txt`, `Cargo.toml`, `go.mod`)
* Authentication, authorization, or session controllers
* Files within `.compliance/`
* IaC templates that provision storage, network egress, or KMS
* Any file containing Fideslang annotations

**Deterministic-only (Tier 1) scan suffices for:**
* Frontend CSS-only changes
* Markdown typo fixes outside `.compliance/`
* Test fixture updates with synthetic data
* Documentation in `docs/` not referenced by `.compliance/`

**Suppression**: developers may suppress a known false positive with an inline comment carrying a justification (`// gdpr-suppress: <rule-id> - <reason>`). All suppressions are logged and surfaced in a quarterly human review batch. Unjustified or expired suppressions revoke automatically.

## Honest limits

The scanner cannot adjudicate Article 22 (automated decision-making with legal or similarly significant effects), Article 9(2)(g) substantial public interest, or the proportionality balancing inherent to risk-based provisions. It can detect that an ML model is deployed; it cannot evaluate whether the human reviewer in the loop is meaningful or a rubber stamp. When such patterns are detected, the scanner halts the pipeline and flags for mandatory DPO review rather than rendering a pass/fail. See `references/limitations.md` for the full enumeration and the prompt patterns the agent uses to surface these to a human.

The goal is to eliminate routine, deterministic errors at the baseline and to escalate genuine ambiguity, not to replace the DPO. A scanner that pretends to do the latter is itself a compliance risk.