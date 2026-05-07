# Optional Trust Services Categories

These four categories are included only when applicable to the organization's services, SLAs, or regulatory obligations. The Common Criteria (CC1-CC9) remain mandatory regardless.

## Availability (A1.1 to A1.3)

Systems are accessible for operation and use to meet the entity's commitments and SLAs.

### A1.1 - Capacity and demand

* **Deterministic**: IaC declares auto-scaling groups, Kubernetes HPA/VPA, RDS read replicas, capacity quotas. Verify scaling policies have non-trivial thresholds (not `min=max`).

### A1.2 - Environmental protections, software, data backup, recovery

* **Deterministic**:
  * Multi-AZ deployment for production databases (`multi_az = true` for RDS, replica configurations for Postgres, geo-redundant storage for cloud blob).
  * Automated snapshot or backup schedules with declared retention.
  * Restore procedures referenced in IaC or runbook artifacts.

### A1.3 - Recovery testing

* **Agentic**: parse the DR runbook for declared restore-test cadence. The repo can verify the cadence is *declared*; actual execution evidence is out-of-repo unless restoration runs are scripted in CI (e.g., a scheduled job that restores a snapshot to a sandbox account).

## Confidentiality (C1.1 to C1.2)

Information designated as confidential is protected throughout its lifecycle.

### C1.1 - Identifies and maintains confidential information

* **Deterministic**:
  * Encryption-at-rest: KMS-backed encryption on all storage (`storage_encrypted = true`, `kms_key_id` set, EBS volumes encrypted, S3 SSE-KMS).
  * Encryption-in-transit: TLS 1.2+ on all listeners, no plaintext HTTP on public endpoints.
  * Secret scanning across commit history (overlaps with CC6.1).
* **Agentic**: parse `Data_Classification_Handling.md`. For each data tier (Public, Internal, Confidential, Restricted), confirm IaC controls match. Restricted-tier resources should use customer-managed KMS keys and dedicated tenancy where the policy mandates it.

### C1.2 - Disposes of confidential information

* **Deterministic**: S3 lifecycle rules, RDS final snapshot policies, log retention bounds. Verify destruction is configured, not just paused.

## Processing Integrity (PI1.1 to PI1.5)

System processing is complete, valid, accurate, timely, and authorized.

### PI1.1 - Quality of processing inputs

* **Deterministic**: presence of input validation libraries or schemas (e.g., Zod, Pydantic, JSON Schema validators) in critical service entry points.

### PI1.2 - System inputs are complete, accurate

* **Agentic**: read processing-flow documentation. Confirm declared validation gates exist as code.

### PI1.3 - System processing produces complete and accurate outputs

* **Deterministic**: query CI/CD coverage reports (JaCoCo, Codecov, Istanbul). Coverage thresholds must meet or exceed the SDLC policy's stated minimum (often 70-80% for new code). Verify the threshold is enforced as a blocking status check, not advisory.

### PI1.4 - Output is delivered to authorized parties

* **Agentic**: parse webhook configurations and outbound integrations. Confirm authentication is required on all outputs.

### PI1.5 - System processing is authorized

* **Deterministic**: API authentication and authorization middleware is present on all routes (no anonymous mutating endpoints unless explicitly justified).

## Privacy (P1.1 to P8.1)

Collection, use, retention, disclosure, and disposal of personal information per the entity's privacy notice.

The privacy category has the most criteria (P1 through P8). Treat each subgroup as a checklist.

### P1 - Notice and communication of objectives

* **Agentic**: parse the public privacy notice (often `PRIVACY.md` or a CMS-managed page mirrored in the repo). Confirm it covers the categories of information collected, uses, third-party sharing, retention, and rights.

### P2 - Choice and consent

* **Deterministic**: consent-tracking logic in code. Cookie banners, opt-in flags, and consent log persistence are present.

### P3 - Collection

* **Agentic**: confirm data collection points in code (forms, API endpoints) match the notice. Flag fields collected in code but not declared in the notice.

### P4 - Use, retention, disposal

* **Deterministic**: data retention lifecycle configured. S3 object expiration rules, database retention jobs, log expiration. Retention durations match the privacy notice.
* **Agentic**: cross-reference declared retention in the privacy notice against IaC lifecycle policies.

### P5 - Access

* **Deterministic**: subject access request (SAR) endpoints or admin tooling exist. For regulated regions (GDPR Art. 15, CCPA), a documented mechanism is mandatory.

### P6 - Disclosure to third parties

* **Agentic**: read vendor list and DPAs. Confirm each external data flow has a documented legal basis.

### P7 - Quality

* **Deterministic**: data correction endpoints (GDPR Art. 16) exist.

### P8 - Monitoring and enforcement

* **Agentic**: parse the privacy policy for declared review cadence and enforcement procedures. Verify a designated privacy owner is named (DPO if required).

## Scope decision

When asked which optional categories apply:

* **Availability** is required if the SLA promises uptime to customers.
* **Confidentiality** is required if customer-classified-confidential data is processed.
* **Processing Integrity** is required for transaction processing, financial calculation, payments, or anything where output correctness is contractually or legally significant.
* **Privacy** is required if PII is collected and the entity has obligations under GDPR, CCPA, HIPAA-adjacent rules, or its own privacy notice.

Most B2B SaaS scopes Security + Availability + Confidentiality. Payment processors add Processing Integrity. Consumer-facing or PII-heavy services add Privacy.
