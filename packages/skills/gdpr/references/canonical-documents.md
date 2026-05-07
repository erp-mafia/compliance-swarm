# Canonical Document Set

A GDPR-aware repository contains a `.compliance/` directory holding machine-readable versions of the privacy artifacts. Treating privacy documentation as code is the precondition for every Tier 2 agentic check; without it, the auditor has no policy substrate against which to validate codebase reality.

## Layout

```
.compliance/
├── ropa.yaml                    # or ropa.json - Record of Processing Activities
├── dpia_inventory/
│   ├── ml_credit_scoring.md     # one DPIA per high-risk operation
│   ├── biometric_login.md
│   └── customer_segmentation.md
├── dsar_runbook.md              # technical playbook for Articles 15/16/17/20
├── transfers/
│   ├── tia_aws_us_east_1.md     # one TIA per restricted transfer
│   ├── scc_module_2_aws.pdf     # executed SCCs, by module
│   └── transfers_inventory.yaml # machine-readable index
├── incident_response.md         # 72-hour breach runbook
├── privacy_policy.md            # forward-facing notice
└── consent_mappings.yaml        # cookie/consent state to processing operation map
```

The structure is a convention, not a regulation. The agent should be tolerant of variants (`/.privacy/`, `/docs/compliance/`, etc.) but must locate and validate equivalents of all the artifacts above.

## Per-artifact validation rules

### `ropa.yaml` - Article 30

**Required schema**:
```yaml
processing_activities:
  - id: "string"
    name: "string"
    purpose: "string"
    lawful_basis: "consent | contract | legal_obligation | vital_interests | public_task | legitimate_interests"
    data_categories: ["fideslang-label", ...]
    data_subjects: ["fideslang-label", ...]
    recipients: ["string", ...]      # internal services + external processors
    retention_period: "ISO-8601 duration"
    international_transfers:
      - destination: "country-code"
        safeguard: "adequacy | scc_module_X | bcr | derogation_art_49"
        tia_ref: "path/to/transfers/tia_*.md"
    security_measures: ["string", ...]
```

**Tier 1 checks**: schema validity; every `data_categories` and `data_subjects` entry resolves to a Fideslang label; every `tia_ref` points to an existing file under `.compliance/transfers/`.

**Tier 2 checks**: every flow in the Privado-generated data flow graph appears as a `processing_activities` entry, and vice versa. The agentic prompt for this is in `agentic-prompts.md`.

**Common failure mode**: the RoPA is hand-maintained and drifts the moment a developer adds a new third-party SDK or a new database column. Drift is the rule, not the exception. The scanner exists primarily to catch this.

### `dpia_inventory/` - Article 35

Each file is a DPIA for a single high-risk processing operation. Structure follows the EDPB DPIA template (April 2026 update):

1. Systematic description of envisaged processing operations and purposes
2. Assessment of necessity and proportionality
3. Assessment of risks to data subjects' rights and freedoms
4. Measures envisaged to address the risks (including safeguards, security measures, mechanisms to ensure protection)
5. Date and signature of the DPO consultation
6. Where applicable, prior consultation with the supervisory authority (Art. 36)

**Tier 1 checks**: file presence per high-risk trigger detected in code; section headers match the EDPB template.

**Tier 2 checks**: the "measures envisaged" section names specific technical controls that the agent can then verify exist in code (encryption keys managed by service X, access logged to service Y, etc.). If the DPIA promises a control that the codebase does not implement, the scanner flags a DPIA-vs-implementation drift.

### `dsar_runbook.md` - Articles 15-22

Documents the technical mechanism by which each data subject right is satisfied. For each right, expected content:

* Endpoint(s) involved
* Authentication mechanism
* Identity verification procedure (proof-of-identity above the API auth layer)
* Microservices queried (with explicit join logic for distributed PII)
* SLA against the 30-day Article 12(3) window
* Escalation path for ambiguous requests (e.g., requests touching ongoing legal proceedings, conflicting data subjects)

**Tier 2 check**: the agent reads the runbook, extracts the named endpoints, and verifies each exists in the API layer with the documented authentication and behavior.

### `transfers/` - Articles 44-49

`transfers_inventory.yaml` is the machine-readable index:

```yaml
transfers:
  - destination_country: "US"
    destination_service: "aws-us-east-1"
    fideslang_data_categories: ["user.contact.email", "user.preferences"]
    safeguard: "scc_module_2"
    scc_executed_date: "2024-03-15"
    scc_artifact: "transfers/scc_module_2_aws.pdf"
    tia_artifact: "transfers/tia_aws_us_east_1.md"
    supplementary_measures:
      - "encryption in transit (TLS 1.3)"
      - "encryption at rest with CMK held in EU"
      - "pseudonymization of direct identifiers prior to transfer"
```

Detailed Schrems II evaluation logic is in `transfers-schrems-ii.md`.

### `incident_response.md` - Articles 33 and 34

Detailed phase structure and EDPB Guidelines 9/2022 alignment in `breach-notification.md`. The high-level required phases:

1. Detection and triage (confidentiality / integrity / availability classification)
2. Assessment and containment
3. DPO and legal escalation paths
4. Supervisory authority notification (within 72 hours of awareness)
5. Data subject communication (Article 34, when high risk)
6. Post-incident review and Article 33(5) documentation

### `privacy_policy.md` - Articles 12, 13, 14

The user-facing notice. The agent verifies:

* Every Fideslang `data_category` actually processed by the codebase appears in the policy
* Every `data_use` actually invoked appears in the policy as a stated purpose
* Every recipient (third-party SDK, processor) appears in the policy
* Retention periods named in the policy match the retention enforcement in code
* Lawful basis named in the policy matches the basis declared in `ropa.yaml`

**Common failure mode**: the legal team updates the privacy policy on a quarterly cadence; the engineering team adds a new analytics SDK on a Tuesday afternoon. The policy is now lying to data subjects. The scanner catches this within the same PR.

### `consent_mappings.yaml`

Maps cookie / consent state to the processing operations they unlock. Used by the agent to validate frontend consent logic against backend behavior:

```yaml
consent_categories:
  strictly_necessary:
    fideslang_data_uses: ["provide.service.operations"]
    consent_required: false
  analytics:
    fideslang_data_uses: ["improve.system", "improve.system.analytics"]
    consent_required: true
    cookie_names: ["_ga", "_gid"]
  marketing:
    fideslang_data_uses: ["marketing.advertising.first_party.contextual"]
    consent_required: true
```

The agent uses this to check, for example, that no script tagged as `marketing` initializes before the user has accepted the marketing consent category.

## Drift as the primary failure mode

In every category above, the dominant failure mode is not the absence of the artifact but its silent divergence from code reality. A scanner that only checks for file existence is performing security theater. Every Tier 2 check in this file is, fundamentally, a drift check.

The agent's mental model: each artifact is a *contract* between legal and engineering, expressed in code-adjacent form. Drift is contract breach.