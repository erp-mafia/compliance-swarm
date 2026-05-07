# Breach Notification (Articles 33 and 34)

Article 33 imposes a 72-hour notification window from the moment the controller becomes "aware" of a personal data breach. Article 34 requires direct communication to data subjects when the breach is likely to result in a "high risk" to their rights and freedoms. EDPB Guidelines 9/2022 (Version 2.0, March 2023) define awareness, the high-risk threshold, and the controller-vs-processor split.

Compliance with the 72-hour mandate is impossible without specific technical and organizational preparedness in advance. The scanner verifies that the preparedness exists in the repository.

## "Awareness" - the operative trigger

Per EDPB Guidelines 9/2022, awareness occurs when the controller has a reasonable degree of certainty that a security incident has occurred leading to the compromise of personal data. Awareness is not when the security team first sees an alert; it is when the technical and forensic facts establish, at a reasonable level of confidence, that personal data was affected.

The 72-hour clock starts at awareness. A scanner that focuses only on the runbook misses the upstream technical question: does the observability stack actually let the team reach awareness in a timely manner?

## Tier 1 checks: observability infrastructure

The scanner parses monitoring and alerting configurations to verify that the necessary detection capacity exists.

### Required signals

The agent expects detection rules for at minimum:

* **Mass exfiltration patterns**: outbound network volume anomalies, especially to unfamiliar destinations
* **Mass deletion**: bulk DELETE operations on PII tables outside of documented retention jobs
* **Unauthorized administrative access**: privilege escalation, root/sudo use outside documented break-glass procedures, IAM policy changes outside Terraform-driven workflows
* **Authentication anomalies**: credential stuffing, impossible-travel logins, account lockout spikes
* **Application-level anomalies**: query rate spikes against PII-bearing endpoints, unusual response sizes (a `GET /users/me` returning 50MB is not `users/me`)
* **Integrity violations**: unexpected modifications to audit logs, security configurations, or critical IAM resources

### Configuration substrates

The scanner reads:

* `prometheus/alerts/*.yml` and Alertmanager routing
* Datadog monitor exports (`monitors-*.json`)
* AWS CloudWatch alarm definitions (in IaC)
* GuardDuty / Security Hub / Macie configurations
* SIEM rule definitions (Splunk, Elastic, Sentinel, Wazuh)
* Application-level audit log emitters

For each required signal class above, the agent verifies at least one detection rule exists, and that the detection routes to a paging destination (PagerDuty, Opsgenie, on-call alias) rather than to a low-priority dashboard.

### Logging completeness

The detection only works if the underlying logs exist. The scanner verifies:

* PII-bearing endpoints emit access logs to a centralized destination
* The destination is append-only or has tamper-evidence (S3 with object lock, immutable bucket, write-only IAM policies)
* Log retention covers a window long enough for forensic reconstruction (typically 12-24 months for PII access logs)
* Logs themselves do not contain PII payloads (an audit log that records "user X accessed user Y's medical record" is correct; one that records the medical record's content is itself a confidentiality breach)

## Tier 2 checks: the runbook

`.compliance/incident_response.md` is read by the agent and validated against EDPB Guidelines 9/2022's phase structure.

### Phase 1: Detection and triage

The runbook documents:
* Who is on the initial response rotation
* The classification framework (confidentiality breach, integrity breach, availability breach, or some combination)
* The threshold criteria for declaring an incident vs. a non-incident security event
* The handoff to phase 2

A breach can be one or more of:
* **Confidentiality breach**: unauthorized disclosure of, or access to, personal data
* **Integrity breach**: unauthorized alteration of personal data
* **Availability breach**: accidental or unlawful destruction or loss of access to personal data

Loss of availability counts. A ransomware encryption that the controller cannot reverse is an availability breach even if no data is exfiltrated. The runbook should not treat ransomware as exclusively a security incident; it is also an Article 33 trigger.

### Phase 2: Assessment and containment

The runbook documents:
* The technical playbook for halting active data loss (revoke credentials, isolate hosts, block network egress)
* The forensic preservation requirements (snapshot affected systems before remediation, preserve volatile memory if relevant)
* The query playbook for answering: "Who was affected, and exactly what data?"

The "who and what" question is the hardest one and the one most often unanswerable in practice. The scanner specifically looks for query playbooks against the audit log destinations that can answer it; absence is a major finding.

### Phase 3: DPO and legal escalation

The runbook documents:
* Hardcoded routing to the DPO and external legal counsel within the first hours
* The decision authority for whether the threshold for Article 33 notification is met
* The decision authority for whether Article 34 high-risk communication to data subjects is required

### Phase 4: Supervisory authority notification

The runbook references:
* The competent supervisory authority for the controller (typically the lead authority under the One-Stop-Shop mechanism for cross-border processing)
* The notification template and required content per Article 33(3)
* The submission portal or contact for the authority
* The escalation if the 72-hour window cannot be met (Article 33(1) permits delayed notification "where the notification to the supervisory authority is not made within 72 hours, it shall be accompanied by reasons for the delay")

For Sweden, the competent authority is IMY (Integritetsskyddsmyndigheten). The runbook should reference the current IMY notification portal and the Swedish-language template.

### Phase 5: Data subject communication (Article 34)

When the breach is "likely to result in a high risk to the rights and freedoms of natural persons", communication directly to data subjects is required, in clear and plain language, "without undue delay".

The runbook should contain:
* Pre-drafted templates for common breach scenarios (credential breach, PII exfiltration, ransomware)
* Multilingual versions for jurisdictions in scope
* The threshold logic for high-risk determination, anchored in EDPB Guidelines 9/2022 and any DPA-specific guidance
* The communication channel decision tree (email, in-app, postal, public notice)

Article 34(3) lists exceptions: the data was encrypted to a level rendering it unintelligible, subsequent measures eliminated the high risk, or direct communication would involve disproportionate effort. The runbook should reference these exceptions explicitly so the decision is principled rather than ad hoc.

### Phase 6: Post-incident documentation

Article 33(5) requires the controller to document any personal data breach, regardless of whether it triggered notification, in a manner that enables the supervisory authority to verify compliance. The runbook documents the format and retention of the breach register.

## Common runbook failures the scanner catches

* Missing classification framework (the runbook treats all breaches as confidentiality breaches and ignores integrity / availability)
* DPO escalation path references a person who is no longer the DPO (drift; cross-reference against an HR/IDP source if available)
* Notification portal URL is deprecated or the regulator has updated the submission process
* Article 34 templates are present in only one language for a multi-jurisdiction service
* No defined query playbook for "who was affected and what data" - the runbook waves at "the security team will determine the scope" without specifying how
* No documented threshold logic for high-risk determination, leaving phase 5 to ad hoc judgment

## Processor notification

Article 33(2) requires processors to notify their controllers "without undue delay" upon becoming aware. The 72-hour clock for the controller starts when the controller is informed by the processor (subject to interpretation; the EDPB position is that the controller should be informed as quickly as possible to preserve the 72-hour window).

If the repository operates as a processor for one or more controllers, the runbook documents:
* The notification SLA to controllers (typically 24 hours or sooner, set in the DPA)
* The communication channel per controller relationship
* Sample notification content

The scanner verifies the existence of these elements when the codebase has indicators of processor operation (DPA templates in `.compliance/`, multi-tenant architecture, service-level agreements naming controller customers).