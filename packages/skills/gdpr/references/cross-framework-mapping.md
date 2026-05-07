# Cross-Framework Mapping

The Secure Controls Framework (SCF) operates as a Living Control Set (LCS) and provides Set Theory Relationship Mapping (STRM) between regulatory regimes. The SCF translates the GDPR into 1,400+ discrete technical controls across 33 domains, and exports its mappings as NIST OSCAL JSON. The scanner ingests this OSCAL artifact to emit multi-framework evidence tags from a single technical check.

When a GDPR violation is detected, the agent should output the GDPR article *and* the equivalent identifier in NIST 800-53 Rev 5, ISO/IEC 27001:2022 Annex A, SOC 2 TSC, and CIS Controls v8. This serves the typical compliance team that operates against multiple regimes simultaneously and reduces remediation duplication.

## The crosswalk table

The mapping below is the operational core. The agent should treat it as authoritative for the GDPR articles enumerated; for less common articles, fall back to the SCF OSCAL export.

| GDPR | Verifiable technical objective | NIST 800-53 R5 | ISO/IEC 27001:2022 Annex A | SOC 2 TSC | CIS v8 |
|------|---------------------------------|----------------|----------------------------|-----------|--------|
| Art. 5(1)(f), Art. 32 | Encryption at rest (AES-256) and in transit (TLS 1.2+); key management | SC-8 (Transmission Confidentiality and Integrity), SC-28 (Protection of Information at Rest), SC-12 (Cryptographic Key Establishment) | A.8.24 (Use of cryptography) | CC6.1 (Logical Access), CC6.6 (Boundary Protection), CC6.7 (Data Transmission) | 3.10, 3.11 (Data protection) |
| Art. 5(1)(c) | Data minimization in API schemas and data collection | PT-2 (Authority to Process), PT-3 (PII Processing Purposes) | A.5.34 (Privacy and protection of PII) | P3.1, P3.2 (Privacy purpose) | 3.1 (Data management process) |
| Art. 5(1)(e), Art. 17 | Storage limitation, retention enforcement, irreversible erasure | SI-12 (Information Management and Retention), MP-6 (Media Sanitization) | A.5.10 (Acceptable use), A.8.10 (Information deletion) | P4.2 (Privacy retention), P4.3 (Privacy erasure) | 3.4 (Data retention), 3.5 (Disposal) |
| Art. 25 | Privacy by design and default; least privilege; secure defaults | AC-2 (Account Management), AC-3 (Access Enforcement), AC-6 (Least Privilege), CM-6 (Configuration Settings), CM-7 (Least Functionality) | A.5.15 (Access control), A.8.2 (Privileged access rights), A.8.9 (Configuration management) | CC6.1, CC6.3 (Logical and Physical Access) | 3.3 (Access control list), 4.1 (Secure configuration) |
| Art. 30 | Records of Processing Activities; data inventory; data flow mapping | PM-5 (System Inventory), PT-2, PT-3, CM-8 (System Component Inventory) | A.5.9 (Inventory of information and other associated assets), A.5.34 | CC6.1 (Information Asset Inventory), P3.1 | 1.1 (Asset inventory), 3.2 (Data inventory) |
| Art. 32, Art. 5(1)(f) | Continuous logging, integrity monitoring, secret scanning | AU-2 (Event Logging), AU-12 (Audit Generation), SI-7 (Software Integrity), IA-5 (Authenticator Management) | A.8.15 (Logging), A.8.16 (Monitoring activities), A.5.17 (Authentication information) | CC7.1, CC7.2 (System Operations) | 8.1, 8.2 (Audit log management) |
| Art. 33, Art. 34 | Incident detection, response, breach notification within 72 hours | IR-4 (Incident Handling), IR-6 (Incident Reporting), IR-8 (Incident Response Plan) | A.5.24 (Information security incident management planning), A.5.25 (Assessment and decision on information security events), A.5.26 (Response to information security incidents) | CC7.3 (Incident detection), CC7.4 (Incident response) | 17.1-17.9 (Incident response) |
| Art. 35 | DPIA for high-risk processing; risk assessment | RA-3 (Risk Assessment), RA-8 (Privacy Impact Assessments), PT-7 (Specific Categories of PII) | A.5.30 (ICT readiness), A.5.34 | P1.1 (Privacy notice), P6.1-P6.6 (Privacy disclosure and notification) | n/a (CIS does not address DPIA) |
| Art. 15-21 | Data subject rights endpoints; access, rectification, erasure, portability | PT-4 (Consent), PT-5 (Privacy Notice), PT-6 (System of Records Notice), PM-21 (Accounting of Disclosures) | A.5.34, A.8.10 (Information deletion), A.8.11 (Data masking) | P4.1 (Privacy access), P4.3 (Privacy erasure), P5.1 (Privacy disclosure) | n/a |
| Art. 44-49 | International transfers, SCCs, TIAs, supplementary measures | SR-3 (Supply Chain Controls and Processes), AC-21 (Information Sharing), CA-3 (Information Exchange) | A.5.20 (Addressing information security within supplier agreements), A.5.21 (Managing information security in the ICT supply chain), A.5.31 (Legal, statutory, regulatory and contractual requirements) | CC9.2 (Vendor Risk), C1.1 (Confidentiality) | 15.1-15.7 (Service provider management) |
| Art. 32 | Backup and recovery; ability to restore | CP-9 (System Backup), CP-10 (System Recovery and Reconstitution) | A.8.13 (Information backup), A.5.30 (ICT readiness for business continuity) | A1.2 (Availability backup), A1.3 (Recovery testing) | 11.1-11.5 (Data recovery) |

## SCF OSCAL ingestion

The full SCF OSCAL export is available from the SCF's GitHub. The scanner should:

1. Pin a specific SCF release version in the build pipeline (the SCF is a Living Control Set; mappings change).
2. Parse the OSCAL JSON to build an in-memory map: `gdpr_article -> [scf_control_id, ...] -> [external_framework_control_id, ...]`.
3. When a check fails, the scanner traverses from the GDPR article through the SCF control to all linked external framework controls, and emits the full set in the output.

## Output format

A single technical violation should produce a finding shaped like:

```json
{
  "rule_id": "gdpr-32-unencrypted-storage",
  "severity": "high",
  "file": "infrastructure/terraform/s3.tf",
  "line": 42,
  "evidence": "aws_s3_bucket.user_uploads has server_side_encryption_configuration absent",
  "framework_mappings": {
    "gdpr": ["Art. 32(1)(a)"],
    "nist_800_53_r5": ["SC-28"],
    "iso_27001_2022": ["A.8.24"],
    "soc2_tsc": ["CC6.1", "CC6.6"],
    "cis_v8": ["3.11"]
  },
  "remediation": "Add server_side_encryption_configuration block with sse_algorithm = \"AES256\" and (for restricted-transfer destinations) a CMK ARN."
}
```

This structure satisfies a vendor risk team running ISO 27001, an enterprise customer demanding SOC 2 evidence, and a European DPA simultaneously, from a single repository scan.

## DPMP reference

The SCF also incorporates the Data Privacy Management Principles (DPMP), which organize 86 individual privacy principles into 11 domains and map them to 31 global privacy frameworks. When the customer organization operates outside the EU but processes EU data subject information, the DPMP layer is what extends GDPR-aligned controls to PIPEDA, LGPD, CCPA/CPRA, and other regimes. The mapping logic is identical: GDPR article -> SCF control -> DPMP principle -> destination-framework control identifier.