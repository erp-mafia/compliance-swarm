# Cross-Framework Mapping for ASVS v5.0.0

A single deterministic check should produce multi-framework evidence. This file is the lookup table for emitting NIST 800-53 Rev 5, CIS v8.1, ISO/IEC 27001:2022 Annex A, and SOC 2 TSC tags alongside ASVS findings.

The mapping is grounded in OpenCRE (OWASP Common Requirement Enumeration), which mathematically interlinks security standards based on shared technical primitives. Where OpenCRE is incomplete, mappings are derived from authoritative published cross-walks.

## Master mapping table

| ASVS Chapter | NIST 800-53 Rev 5 | CIS v8.1 | ISO 27001:2022 Annex A | SOC 2 TSC |
|---|---|---|---|---|
| V1 Encoding/Sanitization | SI-10, SI-15 | 16.10, 16.11 | A.8.26, A.8.28 | CC8.1, PI1.1 |
| V2 Validation/Business Logic | SI-10, SI-3 | 16.10 | A.8.26 | PI1.1, PI1.2, CC8.1 |
| V3 Web Frontend (new) | SC-18, SC-23 | 16.5 | A.8.23 | CC6.7 |
| V4 API/Web Service | SC-8, AC-3, SI-10 | 16.5, 16.10 | A.8.20, A.8.26 | CC6.6, CC8.1 |
| V5 File Handling | SI-3, SI-7, AC-3 | 10.1, 10.5 | A.8.7, A.8.10 | CC6.8 |
| V6 Authentication | IA-2, IA-5, IA-8 | 6.3, 6.5 | A.5.16, A.5.17, A.8.5 | CC6.1, CC6.2 |
| V7 Session | IA-11, AC-12 | 6.4 | A.5.18 | CC6.1 |
| V8 Authorization | AC-2, AC-3, AC-6 | 6.7, 6.8 | A.5.15, A.5.18, A.8.3 | CC6.1, CC6.3 |
| V9 Self-Contained Tokens (new) | IA-5, SC-12, SC-13 | 6.5 | A.8.5, A.8.24 | CC6.1 |
| V10 OAuth/OIDC (new) | IA-2, IA-8, AC-3 | 6.5, 6.7 | A.5.16, A.5.18 | CC6.1, CC6.3 |
| V11 Cryptography | SC-12, SC-13, SC-28 | 3.10, 3.11 | A.8.24 | CC6.1, C1.1 |
| V12 Secure Communication | SC-8, SC-13, SC-23 | 3.10, 12.6 | A.8.20, A.8.21 | CC6.7 |
| V13 Configuration | CM-2, CM-6, CM-7, RA-5, SI-2 | 4.1, 4.6, 7.3, 16.2 | A.8.9, A.8.25, A.8.8 | CC7.1, CC8.1 |
| V14 Data Protection | SC-28, MP-6, AC-21 | 3.1, 3.3, 3.11 | A.8.10, A.8.11, A.8.12 | C1.1, C1.2, P-series |
| V15 Secure Coding | SA-15, SI-7 | 16.1, 16.11 | A.8.25, A.8.28 | CC8.1 |
| V16 Security Logging | AU-2, AU-3, AU-9, AU-12 | 8.2, 8.5, 8.11 | A.8.15, A.8.16 | CC4.1, CC7.2 |
| V17 WebRTC (new) | SC-8, SC-13 | 3.10 | A.8.20, A.8.24 | CC6.7 |

## Requirement-level mappings (high-leverage)

### V8.2.1 Operation-level authorization / IDOR

* **NIST 800-53**: AC-3 (Access Enforcement), AC-6 (Least Privilege).
* **CIS v8.1**: 6.7 (Centralize Access Control), 6.8 (Define and Maintain Role-Based Access Control).
* **ISO 27001:2022**: A.5.15 (Access Control), A.8.3 (Information Access Restriction), A.8.18 (Use of Privileged Utility Programs).
* **SOC 2 TSC**: CC6.1 (Logical Access Security), CC6.3 (Authorization).

A single agentic finding for missing IDOR protection emits all four tags, which is what makes the scanner economically viable for organizations pursuing multiple attestations.

### V6.2.1 Password hashing

* **NIST 800-53**: IA-5 (Authenticator Management).
* **NIST 800-63B**: §5.1.1.2 verifier requirements for memorized secrets.
* **CIS v8.1**: 6.5 (Require MFA for Administrative Access) (related), 5.2 (Use Unique Passwords).
* **ISO 27001:2022**: A.5.17 (Authentication Information).
* **SOC 2 TSC**: CC6.1.

### V9.1 JWT algorithm pinning

* **NIST 800-53**: SC-12 (Cryptographic Key Establishment and Management), SC-13 (Cryptographic Protection), IA-5.
* **CIS v8.1**: 3.11 (Encrypt Sensitive Data at Rest).
* **ISO 27001:2022**: A.8.24 (Use of Cryptography).
* **SOC 2 TSC**: CC6.1.

### V13.1 SCA / vulnerable dependencies

* **NIST 800-53**: RA-5 (Vulnerability Monitoring and Scanning), SI-2 (Flaw Remediation), SR-3 (Supply Chain Controls and Processes).
* **CIS v8.1**: 16.2 (Establish and Maintain a Process to Accept and Address Software Vulnerabilities), 7.3 (Perform Automated Operating System Patch Management).
* **ISO 27001:2022**: A.8.8 (Management of Technical Vulnerabilities), A.8.25 (Secure Development Life Cycle).
* **SOC 2 TSC**: CC7.1 (Vulnerability Management).

### V12.1 TLS enforcement

* **NIST 800-53**: SC-8 (Transmission Confidentiality and Integrity), SC-13.
* **CIS v8.1**: 3.10 (Encrypt Sensitive Data in Transit).
* **ISO 27001:2022**: A.8.20 (Networks Security), A.8.21 (Security of Network Services).
* **SOC 2 TSC**: CC6.7 (Restriction of Data Transmission).

### V14.2 Encryption at rest

* **NIST 800-53**: SC-28 (Protection of Information at Rest).
* **CIS v8.1**: 3.11.
* **ISO 27001:2022**: A.8.24.
* **SOC 2 TSC**: C1.1 (Confidentiality of Information), CC6.1.

### V16 Security logging

* **NIST 800-53**: AU-2 (Event Logging), AU-3 (Content of Audit Records), AU-9 (Protection of Audit Information), AU-12 (Audit Record Generation).
* **CIS v8.1**: 8.2 (Collect Audit Logs), 8.5 (Collect Detailed Audit Logs), 8.11 (Conduct Audit Log Reviews).
* **ISO 27001:2022**: A.8.15 (Logging), A.8.16 (Monitoring Activities).
* **SOC 2 TSC**: CC4.1 (Monitoring of Controls), CC7.2 (System Monitoring).

## Composition with sibling skills

This skill is intended to compose with `soc2-cicd-compliance` and `iso-27001-2022-compliance`. The finding schema is intentionally aligned. When a single CI run produces evidence for multiple attestations:

1. The scanner runs once and emits findings tagged with all applicable framework IDs.
2. The reporting layer filters by audience: a SOC 2 auditor sees CC6.1 grouped findings; an ISO auditor sees A.5.15 grouped findings; the engineering team sees ASVS V8.2.1 grouped findings. Same underlying evidence, different views.
3. Cross-framework conflicts are rare but real (e.g., GDPR data retention vs. SOC 2 audit log retention can have opposing minimums for the same data class). When conflicts surface, the scanner emits both findings and lets governance resolve.

## What this mapping is not

* It is not a substitute for an organization's Statement of Applicability (ISO) or system description (SOC 2). Those documents define which controls are in scope for the organization's specific risk profile.
* It is not a claim that an ASVS pass implies a SOC 2 pass. ASVS verifies application security; SOC 2 includes organizational, physical, and operational controls largely outside the codebase. ASVS findings are *evidence inputs* to SOC 2 attestation, not the attestation itself.
* It is not exhaustive. New requirements introduced in v5.0.0 (V3, V9, V10, V17) have less mature cross-framework coverage in OpenCRE; the mappings above are the most defensible derivations as of the standard's publication.

## Updating the mapping

When ASVS, NIST, CIS, ISO, or AICPA publish revisions:

* NIST 800-53 revisions (last major: Rev 5 in 2020, with subsequent control overlays) usually preserve identifiers and revise points of focus. Re-validate the mapping rather than rewrite it.
* ISO 27001:2022 reorganized Annex A from 114 controls in the 2013 edition to 93 controls in 4 themes. The mappings above use 2022 identifiers exclusively; do not mix with 2013 identifiers.
* CIS v8.1 (2024) refined v8 (2021) safeguards. v9 is anticipated; check for updates.
* SOC 2 TSC last revised in 2017 with points of focus revised in 2022. Identifiers are stable.
