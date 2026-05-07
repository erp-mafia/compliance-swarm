# Cross-Framework Mappings

A single deterministic technical check can produce evidence for multiple frameworks simultaneously. Tag findings with all relevant identifiers so one scan run yields multi-framework audit packages.

The AICPA publishes official mappings of the 2017 Trust Services Criteria to NIST 800-53, ISO 27001, and others. Some mappings are direct; others are subjective and require interpretation.

## SOC 2 to NIST SP 800-53 Revision 5

NIST 800-53 Rev. 5 is the prescriptive control catalog used in FedRAMP and federal systems. Mappings are typically many-to-many.

| SOC 2 Criterion | NIST 800-53 Rev. 5 | Repository check |
|---|---|---|
| CC4.1 Monitoring | CA-7 Continuous Monitoring | Persistent CI/CD security scan execution on every PR. |
| CC5.2 Control Activities | AC-1 Access Control Policy, CM-1 Configuration Management Policy | Canonical policy markdown present and recently reviewed. |
| CC6.1 Logical Access | AC-2 Account Mgmt, AC-3 Access Enforcement, AC-6 Least Privilege, IA-2 Identification and Authentication | IAM policy parse for wildcards; MFA enforcement; SSO configuration. |
| CC6.6 Boundary Protection | AC-17 Remote Access, SC-7 Boundary Protection | Security group ingress rule audit; WAF attachment to public endpoints. |
| CC6.7 Restricts Transmission | SC-8 Transmission Confidentiality, SC-13 Cryptographic Protection | TLS 1.2+ enforcement on listeners. |
| CC7.1 Vulnerability Detection | RA-5 Vulnerability Scanning, SI-2 Flaw Remediation | Continuous IaC scan; SCA scan on every dependency change. |
| CC7.2 Anomaly Detection | AU-2 Audit Events, AU-6 Audit Review, SI-4 System Monitoring | CloudTrail + GuardDuty + VPC Flow Logs IaC presence; audit log streaming. |
| CC8.1 Change Management | CM-2 Baseline Configuration, CM-3 Configuration Change Control, CM-4 Security Impact Analysis | Branch protection state; PR approval history; mandatory status checks. |
| C1.1 Confidentiality (encryption at rest) | SC-28 Protection of Information at Rest | KMS configuration on storage resources. |
| C1.1 Confidentiality (encryption in transit) | SC-8 | TLS listener configuration. |

## SOC 2 to ISO/IEC 27001 Annex A

ISO 27001 maps to the ISMS-specific technical controls in Annex A. The 2013 and 2022 revisions differ in clause numbering; cite the version in use.

### Annex A 2013 mappings

| SOC 2 Criterion | ISO 27001:2013 Annex A | Repository check |
|---|---|---|
| CC1.1 Tone at the top | A.5.1.1 Information Security Policies | Policy artifact presence and acknowledgment registry. |
| CC5.2, CC5.3 Control Activities | A.9.1.1 Access Control Policy, A.12.1.1 Documented Operating Procedures, A.18.1.1 Independent Review | Policy markdown freshness; CODEOWNERS coverage. |
| CC6.1 Logical Access | A.9.2.1 User Registration, A.9.4.2 Secure Log-on, A.13.2.1 Information Transfer Policies | SSO enforcement; TLS configuration; secret scanning. |
| CC6.3 Least Privilege | A.9.2.3 Privileged Access, A.9.4.1 Information Access Restriction | IAM wildcard scan; CODEOWNERS for sensitive paths. |
| CC6.6 Boundary Protection | A.13.1.1 Network Controls, A.13.1.3 Segregation in Networks | Security group and NACL audit. |
| CC7.1 Vulnerability Detection | A.12.6.1 Management of Technical Vulnerabilities | SCA, IaC scan, container scan on every commit. |
| CC8.1 Change Management | A.12.1.2 Change Management, A.14.2.2 System Change Control | Branch protection; PR approval traceability. |
| C1.1 Confidentiality | A.10.1.1 Cryptographic Controls Policy, A.18.1.4 Privacy and PII | KMS + TLS configuration matched against policy. |

### Annex A 2022 changes

ISO 27001:2022 reorganized Annex A into four themes (Organizational, People, Physical, Technological) with 93 controls. Direct one-to-one ports of 2013 references will fail. Notable additions relevant to repo automation:

* A.5.7 Threat intelligence
* A.5.23 Information security for use of cloud services
* A.8.9 Configuration management
* A.8.16 Monitoring activities
* A.8.28 Secure coding

When asked for ISO 27001 mapping, ask which version the user is certifying against if it is not stated.

## SOC 2 to CIS Controls v8

CIS Controls v8 are prioritized, technical safeguards. They map cleanly to deterministic IaC and CI/CD checks.

| SOC 2 Criterion | CIS Control v8 | Repository check |
|---|---|---|
| CC6.1, C1.1 | Control 3: Data Protection | KMS encryption on storage; secret scanning. |
| CC6.6, CC7.1 | Control 4: Secure Configuration of Enterprise Assets and Software | IaC baseline scanning (Checkov); drift blocked at PR. |
| CC6.2, CC6.3 | Control 5: Account Management; Control 6: Access Control Management | SSO; CODEOWNERS; IAM wildcard ban. |
| CC4.1, CC7.1 | Control 7: Continuous Vulnerability Management | SCA, IaC scan, container scan on every PR. |
| CC2.1, CC7.2 | Control 8: Audit Log Management | CloudTrail + log aggregation IaC. |
| CC3.2, CC9.2 | Control 15: Service Provider Management | SBOM generation; vendor SOC 2 freshness. |
| CC8.1, PI1.3 | Control 16: Application Software Security | SAST + DAST + SCA inextricably integrated; coverage gates. |
| CC7.3-CC7.5 | Control 17: Incident Response Management | IR plan structural check. |

## Other mappings worth knowing

* **PCI DSS v4.0**: relevant for payment processors. PCI Requirement 6 (secure systems and applications) maps to CC8.1 + CC7.1. Requirement 8 (access) maps to CC6.1-CC6.3. Requirement 11 (test security) maps to CC4.1 + CC7.1.
* **HIPAA Security Rule**: 45 CFR §164.308 (administrative safeguards) maps loosely to CC1, CC2, CC3. §164.312 (technical safeguards) maps to CC6.
* **GDPR**: Article 32 (security of processing) maps to CC6.1, CC6.7, C1.1. Articles 15-22 (data subject rights) map to P5, P7.
* **FedRAMP**: built on NIST 800-53; use the SOC 2-to-NIST table above as the bridge.

## Output structure for multi-framework findings

Tag every emitted finding with all applicable framework identifiers:

```yaml
finding:
  primary_criterion: CC6.1
  framework_tags:
    soc2: [CC6.1, C1.1]
    nist_800_53_r5: [AC-3, IA-2, SC-28]
    iso_27001_2013: [A.9.4.2, A.10.1.1]
    iso_27001_2022: [A.8.5, A.8.24]
    cis_v8: [3.11, 6.7]
    pci_dss_v4: [3.5, 8.3]
  status: FAIL
  evidence: ...
```

This is the multidimensional tagging model. A single scan produces audit-ready evidence packages for every framework the organization pursues.
