# Schrems II and International Transfers

CJEU C-311/18 (Schrems II, 2020) invalidated the EU-US Privacy Shield and held that transfers under Standard Contractual Clauses (SCCs) require a case-by-case assessment of the destination country's legal framework. EDPB Recommendations 01/2020 establish the operational methodology: identify the transfer, identify the transfer tool (SCC, BCR, derogation), assess the destination law, identify supplementary measures, and re-evaluate periodically.

The 2021 modular SCCs (Commission Implementing Decision 2021/914) replaced the 2010 SCCs and structure the clauses by transfer scenario:
* Module 1: controller to controller
* Module 2: controller to processor
* Module 3: processor to processor
* Module 4: processor to controller

The scanner's job is to verify that for every detected restricted transfer, a SCC of the correct module exists, a Transfer Impact Assessment (TIA) is on file, and the technical supplementary measures the TIA promises are actually enforced in code.

## Detection: mapping data sinks to geography

Privado identifies external sinks in the data flow graph, including their hostnames and IP addresses. The agent enriches each sink with geographic metadata via:

* Reverse DNS to identify the hosting provider
* IP geolocation databases (MaxMind, IP2Location, RIPE)
* Provider-specific region tagging (AWS region, GCP region, Azure region encoded in the hostname or in the IaC resource)
* For SaaS endpoints, a maintained mapping of vendor data residency commitments (Stripe, Twilio, OpenAI, Anthropic, etc.)

A sink resolving outside the EEA, and not in a country covered by a current adequacy decision (Andorra, Argentina, Canada commercial, Faroe Islands, Guernsey, Israel, Isle of Man, Japan, Jersey, New Zealand, South Korea, Switzerland, United Kingdom, Uruguay, and the EU-US Data Privacy Framework for participating organizations as of the framework's status), is classified as a restricted transfer subject to Chapter V.

**Caveat**: adequacy decisions evolve. The scanner pins a dated reference table and emits a soft warning when the table is older than 90 days, prompting an update.

## Verification: SCC presence and module correctness

For each restricted transfer, the agent expects:

* A reference in `.compliance/transfers/transfers_inventory.yaml` to an SCC artifact under `.compliance/transfers/scc_*`.
* The SCC module corresponds to the actual data flow direction:
  * The controller's own service exporting to a vendor's processor → Module 2
  * Two of the controller's services in different jurisdictions both classifying as controllers (joint controllership scenarios) → Module 1
  * The controller's processor sub-engaging another processor → Module 3
* The SCC artifact metadata names the parties, the categories of data subjects, the categories of personal data, the purposes of processing, and the retention period - and these match the corresponding RoPA entry.

Module mismatch is a common drift mode: a vendor relationship begins as a vanilla SaaS (Module 2) and evolves into a joint controllership (Module 1) without the SCC being updated.

## Verification: TIA presence and supplementary measures

The TIA evaluates whether the destination country's legal framework offers protections "essentially equivalent" to GDPR. EDPB Recommendations 01/2020 note that for several major destinations (notably the United States in respect of Section 702 FISA and Executive Order 12333), the answer is no without supplementary measures.

The TIA enumerates the supplementary measures the controller relies on. These are typically:

* Encryption in transit (TLS 1.3 with verified ciphersuites)
* Encryption at rest with a Customer Managed Key held inside the EEA, where the foreign processor cannot access the plaintext key material
* Pseudonymization of direct identifiers prior to transfer
* Contractual measures (notification of access requests by foreign authorities, transparency reports)
* Organizational measures (legal challenge of access requests, data minimization at the export boundary)

The scanner verifies that the technical measures are deterministically implemented:

### CMK enforcement (Tier 1)

For any storage resource (S3, RDS, GCS, Azure Blob, etc.) provisioned in a non-EEA region where the TIA promises CMK with EU-resident key material:

* The IaC must reference a KMS key whose key store is in an EEA region
* For AWS, this typically means a multi-region key with the primary in eu-* regions, or an external key store
* For cross-account access, the key policy must explicitly grant the destination service `kms:Decrypt` only via a documented temporary mechanism, not blanket access

### Pseudonymization at the boundary (Tier 1)

If the TIA promises that direct identifiers are pseudonymized prior to transfer, the agent looks for a transformation function on the egress path. Common patterns:

* A reverse-proxy or API gateway that hashes / tokenizes specific fields before forwarding
* A schema mapping in a streaming pipeline that drops or transforms identifier columns
* A dedicated tokenization service whose key material does not leave the EEA

If none of these exists in the codebase but the TIA claims pseudonymization, the scanner flags TIA-vs-implementation drift.

### Encryption in transit (Tier 1)

TLS 1.2+ with strong ciphersuites for the transfer leg. AST scan of HTTP client configuration for the destination service.

## Article 49 derogations

Article 49 permits certain transfers without an Article 46 safeguard, but only in narrow circumstances: explicit consent, contract with the data subject, important reasons of public interest, legal claims, vital interests, public register data. Derogations are not a fallback for ordinary commercial transfers.

The agent flags any RoPA entry where the international transfer safeguard is `derogation_art_49_X` and the processing is recurring, large-scale, or commercial. The EDPB has been explicit that derogations cannot be used systematically.

## The agent's check sequence per detected transfer

1. Locate the transfer in `.compliance/transfers/transfers_inventory.yaml`. If absent, emit a finding (Article 30 + Article 44 violation: undocumented restricted transfer).
2. Verify the SCC artifact exists at the referenced path. If absent, emit a finding.
3. Verify the SCC module matches the actual data flow direction. If mismatched, emit a finding.
4. Verify the TIA artifact exists. If absent, emit a finding.
5. Read the TIA's "supplementary measures" section. For each named technical measure, run the corresponding deterministic check against IaC and code. For each missing implementation, emit a finding.
6. For SaaS vendors: check the vendor's most recent Transparency Report against the TIA's vendor risk assumptions. (Tier 3 evidence pointer.)

## A worked example

A Swedish controller routes user contact data (`user.contact.email`) to AWS US-East-1 for processing by an analytics vendor.

* Restricted transfer detected (US, no current Privacy Shield, vendor not on EU-US DPF).
* `transfers_inventory.yaml` shows safeguard `scc_module_2`, references `transfers/scc_aws_us_east_1.pdf`, references `transfers/tia_aws_us_east_1.md`.
* SCC artifact present, Module 2 correct (controller-to-processor).
* TIA promises: TLS 1.3, AES-256 at rest with CMK held in eu-north-1, no pseudonymization (direct identifiers are necessary for the analytics use case).
* IaC check: S3 bucket references KMS key whose primary is in eu-north-1 and replicated to us-east-1 with restrictive access policy. Pass.
* TLS check: HTTPS endpoint uses TLS 1.3. Pass.
* No findings. Transfer is documented and technically supported.

A subsequent pull request adds a new field `user.health.conditions` to the analytics export. The agent now flags:

* Article 9 violation (special category data being processed under SCC Module 2 with no explicit Article 9(2) basis declared)
* TIA-vs-implementation drift: the TIA's risk assessment did not contemplate health data; the supplementary measures are inadequate for special category data crossing into a jurisdiction with broad surveillance authorities
* Mandatory DPO escalation before merge.

This is exactly the kind of case where the scanner adds asymmetric value: the change looks innocuous to the engineer (one extra column) but materially alters the legal posture.