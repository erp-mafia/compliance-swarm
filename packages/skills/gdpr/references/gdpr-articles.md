# GDPR Articles - Operative Subset

The articles below form the verifiable core of an automated GDPR scanner. Each entry gives the legal scope, the technical intent for an automated auditor, the verification tier, and the concrete artifacts the scanner inspects.

The agent must reference articles by exact identifier in its output. Multi-framework crosswalks for each article live in `cross-framework-mapping.md`.

## Article 5 - Principles relating to processing of personal data

**Scope**: Lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity and confidentiality (the "security principle"), and accountability.

**Technical intent**: Verify that data collection mechanisms are scoped strictly to stated purposes (no over-collection), that retention policies exist and are mechanically enforced, and that integrity/confidentiality is upheld through cryptographic primitives.

**Tier**: Mixed. Tier 1 for retention scripts, schema minimality, and encryption. Tier 2 for purpose limitation against stated business purpose in OpenAPI documentation.

**Artifacts inspected**:
* OpenAPI request and response schemas (over-collection detection)
* Cron jobs and lifecycle policies for storage (retention enforcement)
* ORM column definitions and IaC encryption flags (integrity/confidentiality)
* `.compliance/privacy_policy.md` claims vs. actual fields collected (transparency)

## Article 6 - Lawfulness of processing

**Scope**: Establishes the six lawful bases (consent, contract, legal obligation, vital interests, public task, legitimate interests).

**Technical intent**: For each processing operation, verify that the declared lawful basis is structurally compatible with the operation. Consent-based operations require evidence of opt-in capture; legitimate-interest operations require a documented LIA (Legitimate Interests Assessment).

**Tier**: Tier 2. The legal basis is declared in `.compliance/ropa.yaml` per processing activity; the agent reads the declaration and validates it against the code path.

**Common violation**: invoking a sensitive API (camera, geolocation, contacts) without a preceding consent check. From the document, an Android example: `manager.openCamera(cameraId, stateCallback, null)` with no preceding conditional gating consent state.

## Article 9 - Special categories of personal data

**Scope**: Prohibits processing of racial/ethnic origin, political opinions, religious beliefs, trade union membership, genetic data, biometric data, health data, and data concerning sex life or sexual orientation. Lifted only by one of the Article 9(2) exceptions (explicit consent, vital interests, substantial public interest, etc.).

**Technical intent**: Detect any code path or schema field annotated as a special category and require an explicit Article 9(2) basis declaration in the RoPA, plus matching consent capture infrastructure if the basis is 9(2)(a).

**Tier**: Tier 1 detection of the field via Fideslang labels (`user.health.*`, `user.biometric.*`, `user.genetic.*`); Tier 2 validation of the declared 9(2) basis.

**Hard rule**: an endpoint with Fideslang `data_use: marketing.advertising.third_party` and any data category under `user.health.*`, `user.biometric.*`, or `user.genetic.*` is an immediate, non-suppressible Article 9 violation. Marketing is never a valid 9(2) basis.

## Articles 15-22 - Data subject rights

**Scope**: Access (15), rectification (16), erasure / right to be forgotten (17), restriction (18), portability (20), objection (21), automated decision-making (22).

**Technical intent**: Verify the existence of dedicated, RBAC-protected API endpoints satisfying each right within 30 days. Detailed REST patterns and JSON Schema rules are in `dsar-api-patterns.md`.

**Tier**: Tier 1 for endpoint existence and method shape; Tier 2 for tracing the execution path of `DELETE /api/v1/privacy/user/data` to verify hard deletion (or cryptographic shredding) rather than a soft-delete boolean toggle.

**Article 17 anti-pattern (highest-frequency violation)**: implementing erasure as `UPDATE users SET is_deleted = 1`. This is non-compliant. The right to erasure requires hard deletion or mathematically irreversible anonymization. The agent must trace the controller method statically and flag any soft-delete pattern.

**Article 22**: see `limitations.md`. The scanner can detect ML model deployment; it cannot adjudicate whether human review is "meaningful".

## Article 25 - Data protection by design and by default

**Scope**: Embedding privacy-enhancing technologies (PETs) into system architecture from the earliest design stages. Default settings must be the most privacy-preserving available.

**Technical intent**: Audit configuration files for secure defaults (minimum necessary permissions, tracking disabled by default, opt-in rather than opt-out flows). Verify IaC implements least-privilege architectures.

**Tier**: Tier 1 across IaC (Terraform, CloudFormation, Pulumi) for IAM policy granularity, default-deny network rules, default-encrypted storage, and disabled telemetry.

**Common violations**:
* `Access-Control-Allow-Origin: *` on endpoints serving authenticated PII
* AWS S3 buckets with `public-read` default ACL
* Mobile app `AndroidManifest.xml` requesting `ACCESS_FINE_LOCATION` or `READ_CONTACTS` without functional necessity tied to declared purpose
* Missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options` headers

## Article 30 - Records of processing activities (RoPA)

**Scope**: Comprehensive documentation of personal data flows, categories of data subjects, processing purposes, recipients (including third parties), retention periods, and (for international transfers) the safeguards in place.

**Technical intent**: Validate the existence and structural integrity of `.compliance/ropa.yaml`, then reconcile its declared flows against the data flow graph generated by Privado. Any flow appearing in code but not in the RoPA, or vice versa, is a synchronization violation.

**Tier**: Tier 1 for schema validation; Tier 2 for the RoPA-vs-actual-flow reconciliation.

**Drift detection prompt** (excerpt; full version in `agentic-prompts.md`): the agent receives the parsed RoPA and the Privado JSON, and is asked to enumerate flows present in one but not the other. Drift directly violates Art. 30(1) and is a precondition for almost every downstream GDPR violation.

## Article 32 - Security of processing

**Scope**: Appropriate technical and organizational measures, with explicit examples: pseudonymization, encryption, ability to ensure ongoing confidentiality / integrity / availability / resilience, ability to restore access in a timely manner after an incident, and a process for regularly testing those measures.

**Technical intent**: The most deterministically scannable article. Hardcoded secrets, weak cryptography, plaintext transmission, unencrypted storage, missing backup configurations, and absent restore procedures are all Tier 1.

**Tier**: Tier 1 for nearly everything.

**Detection rules**:
* Secret scanning via GitLeaks or Semgrep against the full Git history (not just HEAD)
* TLS configuration parsing rejecting SSLv3, TLS 1.0, TLS 1.1, and weak cipher suites
* IaC parsing for `encrypted: true` on storage resources, with KMS key ARN validation
* ORM annotation scanning for sensitive entities (`SocialSecurityNumber`, `HealthRecord`, anything Fideslang-labeled `user.payment.*` or `user.health.*`) without encryption decorators
* Backup job verification (cron presence + retention period + restore drill schedule)

## Articles 33 and 34 - Personal data breach notification

**Scope**: Article 33 imposes a 72-hour notification window to the supervisory authority from the moment of "awareness". Article 34 requires direct communication to data subjects when the breach is likely to result in a "high risk" to their rights and freedoms. EDPB Guidelines 9/2022 (Version 2.0, March 2023) define the operative thresholds.

**Technical intent**: Verify that the repository's monitoring, alerting, and runbook infrastructure can technically support the 72-hour window. The runbook itself is a Tier 2 artifact; the alerting infrastructure is Tier 1.

**Tier**: Tier 1 for monitoring configurations (Prometheus alert rules, Datadog monitors, CloudWatch alarms, OpenSearch detectors); Tier 2 for `.compliance/incident_response.md` evaluation against EDPB Guidelines 9/2022 phases.

Full decomposition in `breach-notification.md`.

## Article 35 - Data protection impact assessment (DPIA)

**Scope**: Required for any processing "likely to result in a high risk to the rights and freedoms of natural persons", with explicit triggers including systematic and extensive automated profiling, large-scale processing of special categories, and systematic monitoring of publicly accessible areas.

**Technical intent**: Identify code patterns matching high-risk criteria (ML profiling, biometric processing, large-scale special-category handling, public-area monitoring) and require a corresponding DPIA in `.compliance/dpia_inventory/` structured against the EDPB DPIA template (April 2026 update).

**Tier**: Tier 1 for the trigger detection (ML library imports, biometric API calls); Tier 2 for the DPIA artifact structural and content validation.

**Trigger heuristics**:
* Imports of `tensorflow`, `pytorch`, `sklearn`, `xgboost`, `lightgbm` in production paths
* Calls to facial recognition, voice analysis, or fingerprinting APIs
* Cross-database joins producing comprehensive individual profiles

When triggered without a corresponding DPIA, the scanner blocks the pipeline.

## Articles 44-49 - Transfers to third countries

**Scope**: Prohibits transfers of personal data outside the EEA absent an adequacy decision (Art. 45), appropriate safeguards (Art. 46, including the 2021 modular SCCs and Binding Corporate Rules), or a derogation (Art. 49). Schrems II (CJEU C-311/18) requires that even with SCCs, the controller must perform a Transfer Impact Assessment and apply supplementary measures where the destination's law undermines EU protection.

**Technical intent**: Trace data flows to external sinks, resolve their geographic location, classify as restricted transfer if non-EEA, and validate corresponding SCC + TIA + supplementary measures in `.compliance/transfers/`.

**Tier**: Tier 1 for IP/hostname geolocation and TIA-mandated technical measure verification (CMK enforcement, EU-resident key custody); Tier 2 for SCC module selection correctness (Module 1 controller-to-controller, Module 2 controller-to-processor, Module 3 processor-to-processor, Module 4 processor-to-controller).

Full decomposition in `transfers-schrems-ii.md`.