# Limits of Automation

The honest scope of what an automated GDPR scanner cannot do. A scanner that pretends otherwise is itself a compliance risk, because it produces a false sense of completeness while the actual high-stakes legal questions go unaddressed.

This document enumerates the categories of GDPR question that fall outside automation's reach, and prescribes how the scanner should behave when it encounters them: surface, halt, escalate, never silently pass.

## Article 22: automated decision-making with legal or similarly significant effects

Article 22 protects individuals from decisions based "solely" on automated processing that produce "legal effects" or "similarly significantly affect" them. Hiring decisions, credit scoring, insurance underwriting, parole risk assessment, eligibility for state benefits - these are paradigm cases. Recommender systems and ad targeting are usually not, but can become so depending on context (e.g., serving high-stakes ads only to certain demographic clusters).

What the scanner can do:
* Detect the presence of an ML model in a production code path
* Identify the model's role in a decision pipeline (advisory, gating, automated)
* Verify a DPIA exists for the operation if it is high-risk
* Extract from the DPIA the declared mitigation measures and check them against code

What the scanner cannot do:
* Adjudicate whether the decision produces "legal effects" or "similarly significantly affects" the data subject. This is fact-specific legal interpretation.
* Adjudicate whether a human in the loop constitutes "meaningful human involvement" or is a rubber stamp. The CPPA's recent rules and the EDPB's guidance both emphasize this distinction, but it cannot be measured statically. A reviewer who clicks "approve" on 1,000 cases per day is rubber-stamping; a reviewer who reads each case takes 10 minutes per case. The scanner cannot tell from code which is happening.
* Adjudicate whether the operation falls within the Article 22(2) exceptions (necessary for contract, authorized by law, based on explicit consent).

What the scanner does:
* When it detects a model in a pipeline that touches Fideslang categories `user.financial.*`, `user.employment.*`, `user.legal.*`, `user.health.*`, `user.behavior.children.*`, or `user.demographic.protected_class`, it halts the pipeline.
* It emits a structured escalation: "Article 22 review required. Detected model at <file:line>. Decision pipeline shape: <inferred>. DPIA present: yes/no. Human review step present in code: yes/no. The following questions cannot be answered automatically: [whether the decision produces legal effects, whether human involvement is meaningful, whether an Article 22(2) exception applies]. Resolution requires DPO sign-off."
* It does not emit a pass.

## Article 9: special category processing under "substantial public interest"

Article 9(2)(g) permits processing of special category data when "necessary for reasons of substantial public interest, on the basis of Union or Member State law". This is the basis under which research databases, public health systems, and certain national security operations process health, biometric, or other special category data.

What the scanner cannot do:
* Adjudicate whether a stated public interest is "substantial".
* Verify the existence and current status of the Union or Member State legal basis claimed.
* Weigh the public interest against the data subjects' rights (the proportionality test).

What the scanner does:
* When it detects special category processing with declared basis `art_9_2_g_substantial_public_interest`, it requires:
  - A reference in the DPIA to the specific Union or Member State law providing the basis
  - A reference to the proportionality assessment
  - A reference to safeguards specific to special category processing
* It does not adjudicate the substance, but it does verify the artifacts that an audit would need to evaluate the substance exist.

## Risk-based provisions: "appropriate measures", "high risk", "undue delay"

The GDPR is replete with standards rather than rules. "Appropriate technical and organizational measures" (Art. 32). "High risk to the rights and freedoms of natural persons" (Art. 35, Art. 34). "Without undue delay" (Art. 12, Art. 33). "Likely to result in" (Art. 35, Art. 34).

The scanner cannot adjudicate these standards directly. It can:
* Encode common heuristics as defaults (TLS 1.2+ is appropriate; TLS 1.0 is not; AES-256 is appropriate; DES is not)
* Verify that a DPIA explicitly addresses the risk question
* Verify that the runbook defines operational thresholds rather than leaving them to ad hoc judgment

It cannot:
* Decide whether a specific implementation is "appropriate" in a contested case
* Decide whether a specific breach is "high risk" without DPO judgment
* Decide whether a specific delay was "undue"

When the scanner cannot decide, it should not pretend to. A "needs DPO review" finding is a complete answer.

## Cross-border legal landscape changes

Adequacy decisions are issued, suspended, and revoked. The CJEU rules on standing concepts (Schrems II invalidated the Privacy Shield in a single decision). National DPA enforcement priorities shift.

The scanner pins reference data (the adequacy decision list, the SCC module text, the EDPB guideline versions) at a specific date. It cannot self-update with currency. The scanner emits a soft warning when its reference data is older than 90 days and a hard requirement when it is older than 365 days, prompting the operator to update.

The scanner does not pretend to know about cases or guidelines published after its reference date.

## Out-of-repository organizational facts

Several Tier 3 facts cannot be verified from code at all. The scanner expects evidence pointers but cannot validate the substance:

* DPO competence and independence (Art. 38, 39)
* Effective implementation of training programs
* Real-world execution of contractual safeguards (a signed DPA does not guarantee the processor honors it)
* Physical security measures
* Governance independence between data controller and security functions

For each of these, the scanner verifies that an evidence pointer exists pointing somewhere in principle accountable. It does not verify that the underlying claim is true.

## The boundary the scanner enforces

The scanner's contract with its operator is precise:

| Category | Scanner verdict |
|----------|-----------------|
| Tier 1 violation present | Block the build, specific finding |
| Tier 2 violation present | Block the build, agentic explanation |
| Tier 3 evidence pointer missing | Block the build, request evidence URI |
| Article 22 / Article 9(2)(g) / risk-based provision implicated | Block the build, escalate to DPO |
| Reference data is stale | Soft warning to operator, hard block above threshold |
| Suppression with valid justification | Pass with logged exception |
| Everything checks out | Pass |

There is no "pass with concerns" verdict. The scanner either passes or escalates; concerns become concrete blocks or concrete escalations. This is what makes the scanner useful. A scanner that emits ambient anxiety without actionable next steps becomes background noise that engineers route around.

## Why the limits matter

Two failure modes haunt automated compliance:

**False confidence**: the scanner passes, the engineer ships, the regulator later finds a violation in territory the scanner never covered. The organization then claims good-faith reliance on tooling, which the regulator does not credit because the violation was in a category any competent privacy program would have addressed manually.

**Alert fatigue**: the scanner emits dozens of low-confidence warnings on every PR. Engineers learn to ignore them or to suppress them en masse. The signal-to-noise ratio collapses, and a real violation passes unnoticed.

The remedy for both is the same: be honest about what the scanner does and does not check. Tier 1 findings are mechanical and high-confidence; emit them with conviction. Tier 2 findings are agentic and require human review; mark them as such. Tier 3 facts are out of repo; collect pointers, do not pretend to verify substance. And for the genuinely subjective questions (Art. 22, substantial public interest, undue delay), do not emit a verdict at all - escalate.

The scanner's value is in the boundary it draws between "this is mechanically wrong" and "this requires legal judgment". Both halves are necessary; both halves must be honestly named.

## Reference: the human-in-the-loop pattern

The deployment pattern this skill is built for is not "automated GDPR compliance". It is "automated elimination of routine compliance errors, with structured escalation of substantive questions to a Data Protection Officer".

The DPO uses the scanner's outputs to:
* Spend zero time on Tier 1 findings (they are auto-blocked, the engineer fixes them, no DPO involvement)
* Spend modest time auditing Tier 2 findings (the agentic reasoning is a draft; the DPO reviews and accepts or rejects)
* Spend the bulk of their time on the substantive questions the scanner correctly refuses to answer (Article 22, Article 9 substantial public interest, proportionality)

This division of labor is what justifies the engineering investment. The scanner makes the DPO more effective by removing routine work from their plate; it does not replace the DPO.

A scanner sold as a DPO replacement is being mis-sold. A scanner sold as a DPO force multiplier is being sold honestly.