# Agentic Prompt Templates

The Tier 2 checks require an LLM to reason over policy markdown and code together. The prompt templates below are the operational core of the agentic auditor. Each is structured around three components: the policy artifact, the code-derived ground truth, and the specific question the agent is asked to answer.

The GDPR-Bench-Android study established realistic accuracy ceilings for this class of work. Qwen2.5-72B reached 61.6% Accuracy@1 at the line level; a ReAct-style agent reached 17.4% Accuracy@1 at the file level. The takeaway: prompt narrowly, give the agent both halves of the comparison explicitly, and prefer many small, focused checks over one omnibus prompt.

## Prompt: RoPA drift detection

The most important Tier 2 check. The agent reconciles `ropa.yaml` against the Privado-derived data flow graph.

```
You are a GDPR Article 30 compliance auditor. You are given two artifacts:

1. The repository's declared Record of Processing Activities (ropa.yaml).
2. The actual data flows detected in the source code by Privado (privado.json).

Your task: enumerate flows that are present in one artifact but not the other.

For each discrepancy, output:
- Direction: "in_code_not_in_ropa" or "in_ropa_not_in_code"
- Source: file:line if from code, or RoPA entry id if from RoPA
- Sink: the destination service or processing operation
- Fideslang data category
- Severity: "critical" if the flow involves user.health.*, user.biometric.*, user.genetic.*, user.financial.*, or user.behavior.children.*; "high" otherwise

Output format: JSON array. No prose.

A flow is "the same" if it has the same Fideslang data_category and the same sink. Different field names with the same data_category are the same flow.

ROPA:
<paste ropa.yaml>

PRIVADO OUTPUT:
<paste privado.json subset relevant to flows>
```

The output of this prompt feeds directly into the finding emitter; no further LLM judgment is required.

## Prompt: purpose limitation check

For a single API endpoint, validate that the actual data returned is commensurate with the documented business purpose.

```
You are a GDPR Article 5(1)(b) auditor. You are given:

1. The OpenAPI specification for a single endpoint, including its summary, description, and tags.
2. The controller method body for the endpoint.
3. The Fideslang annotations on the response schema fields.

Your task: assess whether the data returned exceeds what the documented purpose requires.

For each field returned that you assess as exceeding the purpose, output:
- Field name
- Fideslang data_category
- Why this field is not necessary for the documented purpose (one sentence)
- Suggested remediation (drop the field, gate it behind a different scope, or expand the documented purpose)

If all fields are commensurate with the purpose, output an empty array.

OPENAPI:
<paste relevant endpoint spec>

CONTROLLER:
<paste controller method>

Output format: JSON array. No prose.
```

This check is sensitive to false positives. The agent's threshold for flagging should be high - a finding should be defensible to the implementing engineer, not pedantic. Pair the prompt with a developer suppression mechanism that requires a justification.

## Prompt: consent logic vs. cookie policy

```
You are a GDPR Article 6(1)(a) and Article 7 auditor. You are given:

1. The repository's consent_mappings.yaml documenting which Fideslang data_uses require consent and which cookies map to which categories.
2. The frontend consent management code (the part that decides which scripts and cookies are activated).
3. The list of scripts and cookies that fire on the marketing landing page.

Your task: identify any script or cookie tagged as a consent-required category that fires before the user has given consent.

For each violation, output:
- Script or cookie name
- Required consent category (per consent_mappings.yaml)
- Why the current code activates it without consent (one sentence)
- File:line reference if available

Output format: JSON array. No prose.

If you cannot determine the answer with high confidence from the inputs, output a single object with field "uncertainty" describing what you would need to determine the answer.

CONSENT MAPPINGS:
<paste consent_mappings.yaml>

FRONTEND CONSENT CODE:
<paste relevant code>

PAGE LOAD MANIFEST:
<paste from helsinki-gdpr-scanner output>
```

The "uncertainty" output channel matters. This check has high false-positive potential because consent management code is genuinely complex. The agent should be trained to escape rather than guess.

## Prompt: DPIA-vs-implementation drift

```
You are a GDPR Article 35 auditor. You are given:

1. A DPIA document for a high-risk processing operation.
2. The relevant section(s) of the codebase that implement the operation.

Your task: extract every technical or organizational measure named in the DPIA's "measures envisaged to address the risks" section, and for each, judge whether the codebase implements it.

For each measure, output:
- Measure (verbatim from the DPIA)
- Implementation status: "implemented" | "partially_implemented" | "not_implemented" | "cannot_assess_from_repository"
- Evidence: file:line references for "implemented" and "partially_implemented"; brief explanation of what is missing for "not_implemented"; brief explanation of what is needed to assess for "cannot_assess_from_repository"

Output format: JSON array. No prose.

DPIA:
<paste DPIA markdown>

RELEVANT CODE:
<paste code; if too large, paste an index of files and let the user iterate>
```

The "cannot_assess_from_repository" output is critical. Some DPIA measures are organizational (training, governance, board oversight) and are out of repo by nature. The agent must label these honestly rather than judging them as not-implemented.

## Prompt: privacy policy alignment

```
You are a GDPR Article 13 auditor. You are given:

1. The repository's privacy_policy.md.
2. The union of Fideslang data_categories actually processed in the codebase.
3. The list of recipients (third-party services, processors) actually invoked from the codebase.
4. The retention periods enforced by retention scripts in the codebase.

Your task: identify discrepancies where the privacy policy makes claims that are not borne out by the codebase, or where the codebase processes data that the privacy policy does not disclose.

For each discrepancy, output:
- Type: "policy_claims_what_code_does_not_do" | "code_does_what_policy_does_not_disclose"
- Subject: the specific data category, recipient, or retention claim
- Evidence in policy: a short excerpt
- Evidence in code: file:line if available

Output format: JSON array. No prose.

PRIVACY POLICY:
<paste privacy_policy.md>

CODE-DERIVED FACTS:
<paste structured summary>
```

This check often surfaces the most embarrassing findings. Privacy policies are written by legal teams on a quarterly cadence; code changes daily. The drift between them is, in the median repository, substantial.

## Prompt: incident response runbook completeness

```
You are a GDPR Article 33 and Article 34 auditor. You are given:

1. The repository's incident_response.md runbook.
2. EDPB Guidelines 9/2022 (Version 2.0, March 2023) phase structure as a reference.

Your task: verify the runbook addresses each of the six phases (detection and triage, assessment and containment, DPO and legal escalation, supervisory authority notification, data subject communication, post-incident documentation) and that the content for each phase is operationally specific (not aspirational).

For each phase, output:
- Phase name
- Status: "addressed" | "addressed_but_vague" | "missing"
- Evidence: a short excerpt for "addressed" and "addressed_but_vague"; for "missing", confirm absence
- For "addressed_but_vague": what specific element is needed to make it operational

Output format: JSON object keyed by phase name. No prose.

RUNBOOK:
<paste incident_response.md>
```

The "addressed_but_vague" verdict is what the agent earns its keep on. A runbook that says "the team will notify the authority within 72 hours" is technically present but operationally useless. The agent should distinguish.

## Prompt: dependency consent gating

```
You are a GDPR auditor specializing in third-party SDK consent compliance. You are given:

1. The list of dependencies in the project (package.json or equivalent).
2. The denylist of SDKs known to require explicit consent.
3. The consent management code (if any).

Your task: for each dependency on the denylist that appears in the project, determine whether its initialization is gated behind explicit consent for the appropriate Fideslang data_use.

For each dependency, output:
- Package name and version
- Reason it is on the denylist (e.g., "advertising identifier collection", "device fingerprinting")
- Consent gating status: "gated" | "not_gated" | "unable_to_determine"
- File:line of initialization
- Required consent category

Output format: JSON array. No prose.

DEPENDENCIES:
<paste manifest>

DENYLIST:
<paste denylist>

CONSENT CODE:
<paste relevant code, or note "no consent management detected">
```

A dependency on the denylist with `not_gated` status is a likely Article 6 violation in any consumer context. `unable_to_determine` is escalated to a human review; the cost of false positives in this category is reputational, so the agent should err toward escalation.

## Prompt construction principles

A few patterns repeat across these prompts and should be replicated when adding new ones:

* **Show both halves**: the agent gets the policy artifact and the code-derived facts in the same prompt. Without one, the agent guesses.
* **Constrain output to JSON**: the findings flow into a downstream emitter. Prose responses cannot be parsed reliably.
* **Provide an "uncertainty" or "cannot_assess" escape**: the agent must be able to say "I don't know" rather than guess. The downstream system treats these as escalation triggers.
* **Anchor severity in objective criteria**: "critical" if special category data, "high" otherwise. The agent's tone-driven severity guesses are not useful; explicit rules are.
* **Reference the EDPB document by exact identifier when relevant**: this anchors the LLM in the correct interpretive corpus and reduces drift toward generic privacy advice.

When iterating on these prompts based on observed false positive / negative rates, change one variable at a time and re-evaluate against a held-out set. The GDPR-Bench-Android study's accuracy numbers are a useful sanity check ceiling: if a custom prompt reports 95% accuracy on a real-world repository, it is overfitting or measuring something narrower than it claims.