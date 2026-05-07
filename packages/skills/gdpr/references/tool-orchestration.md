# Tool Orchestration

Build the scanner as an orchestrator over specialized open-source tools, not a bespoke static analysis engine. Each tool below has been refined to outperform a general scanner within its niche; the skill's contribution is the unified data model (Fideslang), the agentic reasoning over standardized outputs, and the multi-framework finding format.

## The Fideslang taxonomy

The Fideslang privacy taxonomy (developed by Ethyca, maintained with the IAB Tech Lab) is the standardization layer. Without it, each tool emits findings in its own ontology, and cross-tool reasoning is impossible.

Three orthogonal label axes:

* **Data categories**: what the data is. Hierarchical. `user.contact.email`, `user.health.genetic`, `user.financial.account_number`, `user.behavior.browsing_history`, `system.operations.logs`.
* **Data uses**: why it is processed. `provide.service.operations`, `improve.system.analytics`, `marketing.advertising.first_party.contextual`, `marketing.advertising.third_party.targeted`.
* **Data subjects**: who it concerns. `customer`, `employee`, `prospect`, `patient`, `child`.

Developers annotate code, OpenAPI specs, and YAML configurations with Fideslang labels. The agent's reasoning then operates against these labels, which are tool-agnostic.

### Hard rules over Fideslang label combinations

Some label combinations are categorical violations regardless of consent state, because they violate Article 9 prohibition (no Article 9(2) basis is configurable for them).

| Data category | Data use | Verdict |
|---------------|----------|---------|
| `user.health.*` | `marketing.advertising.*` | Article 9 violation, immediate |
| `user.biometric.*` | `marketing.advertising.*` | Article 9 violation, immediate |
| `user.genetic.*` | any except documented Art. 9(2) basis | Article 9 violation |
| `user.behavior.children.*` | `marketing.advertising.third_party.targeted` | Art. 8 (children's consent) + UK ICO Children's Code violation |
| `user.financial.account_number` (full PAN) | any logged or persisted state outside PCI scope | Art. 32 violation, plus PCI DSS scope violation |

The agent should encode these as deterministic rules running against the union of Fideslang annotations across the codebase.

## Privado - data flow mapping and RoPA automation

**Function**: identifies 110+ specific personal data elements in source code and traces their trajectory to sinks (databases, third-party APIs, log destinations).

**Why**: the only credible open-source tool for generating an actual data flow graph from source. The graph is the substrate against which RoPA drift is detected.

**Integration**:
```bash
privado scan <repo> --skip-dependency-check
```

Output: `.privado/privado.json` containing a knowledge graph of sources, processors, and sinks, each annotated with Fideslang-compatible labels.

**Privacy property**: Privado generates the graph natively, without sending source code to a cloud service. This is critical when the scanner itself is processing customer source code.

**Skill consumption**: the agent loads `privado.json`, extracts the flow set, and reconciles against `.compliance/ropa.yaml`. The reconciliation is the Tier 2 RoPA drift check.

## Semgrep - deterministic AST rule enforcement

**Function**: AST pattern matching at the speed required for synchronous PR-time checks.

**Why**: rules are expressed in a near-source-code DSL that engineers can read and write. Custom rules for organization-specific patterns (e.g., "no logging of `personnummer`") are cheap to author.

**Integration**: maintain a `.semgrep/gdpr/` rule directory. Run via:
```bash
semgrep --config .semgrep/gdpr --json .
```

**Skill consumption**: parse the JSON output, map each rule ID through the cross-framework table, emit unified findings.

**Privacy note**: Semgrep offers zero data retention for AI subprocessors and isolates customer data. This is relevant when the scanner is operated as a SaaS over customer code.

## Bearer - privacy-as-code auditing and reporting

**Function**: compiles privacy information required by legal teams; produces RoPA-shaped artifacts and risk reports.

**Why**: where Privado focuses on flow graph generation, Bearer focuses on continuous evidence artifact generation aligned to Article 30. Useful for the legal-engineering interface.

**Integration**:
```bash
bearer scan . --report privacy --format json
```

**Skill consumption**: Bearer's report becomes a secondary substrate for cross-validation against the Privado flow graph. Discrepancies between the two tools' findings are themselves signal (each tool has different blind spots).

## Helsinki GDPR Scanner - frontend consent and cookie validation

**Function**: scans rendered frontend pages against documented cookie banner site settings; detects scripts that fire before consent.

**Why**: Tier 1 deterministic checks on backend code do not catch the most common consent violation, which is frontend tracking SDKs that initialize on page load regardless of consent state.

**Integration** (Docker via Stonehenge):
```bash
docker run --rm -v $(pwd):/work helsinki-gdpr-scanner /work --output /work/json
```

**Skill consumption**: parses the JSON reports under `/json`, identifies tracking scripts that loaded prior to consent, and cross-references against `.compliance/consent_mappings.yaml` to determine whether each script's category required consent.

## Combining outputs: the unified finding format

Each tool emits in its own format. The agent normalizes to:

```json
{
  "rule_id": "string",
  "tool": "privado|semgrep|bearer|helsinki|builtin",
  "severity": "critical|high|medium|low",
  "tier": 1 | 2 | 3,
  "file": "path",
  "line": int,
  "evidence": "string",
  "fideslang": {
    "data_categories": ["..."],
    "data_uses": ["..."],
    "data_subjects": ["..."]
  },
  "framework_mappings": {
    "gdpr": ["Art. ..."],
    "nist_800_53_r5": ["..."],
    "iso_27001_2022": ["..."],
    "soc2_tsc": ["..."],
    "cis_v8": ["..."]
  },
  "remediation": "string",
  "suppression_eligible": bool
}
```

A single semantic violation may surface in multiple tools' outputs. Deduplication key: `(file, line, fideslang.data_categories, framework_mappings.gdpr)`. When duplicates merge, retain the union of evidence statements and the highest severity.

## Execution ordering

For pull request gating, run in this order; later stages depend on earlier outputs:

1. **Secret scanners** (GitLeaks, Trufflehog) - fast, fail fast.
2. **Semgrep** - AST rules, parallelizable, completes in seconds.
3. **SCA / dependency scan** (Trivy, Snyk, Dependabot data) - parallelizable with Semgrep.
4. **Privado** - slower, requires graph construction. Begin in parallel with stages 2-3.
5. **Bearer** - parallel with Privado.
6. **Helsinki GDPR Scanner** - requires built frontend assets; runs after build stage.
7. **Agentic Tier 2 reasoning** - runs only after all Tier 1 outputs are normalized. Has the longest latency budget; should be skipped on PRs that don't trigger it (see SKILL.md trigger heuristics).

For nightly or scheduled deep scans, run all stages without parallelism budget concerns and run additional out-of-band checks (DAST, penetration smoke tests, transfer geolocation refresh).