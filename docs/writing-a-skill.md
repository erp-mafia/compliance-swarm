# Writing a skill

Add a new compliance frame in three files.

## When to add a new skill vs. extend an existing one

**New skill** when you're adding a new compliance frame entirely — PCI DSS, HIPAA,
NIS2, etc. Each skill maps 1:1 to a `framework` value in the Finding schema,
which means it gets its own SARIF run, its own dedup namespace, and its own
section in the markdown report.

**Extend existing** when you're adding a check inside an established frame —
a new ASVS chapter requirement, a new ISO control, a new GDPR data category. Just
add a `static_scan` step or `deep_audit` step to the existing manifest.

## Anatomy

A skill is three things:

```
packages/skills/<short-name>/
├── SKILL.md                 # what a human (or Claude) reads to understand the frame
├── references/              # detailed normative content + agentic prompt sections
│   └── *.md
└── manifest.yml             # the executable contract
```

## 1. Pick a short-name

The directory name is also the skill's filesystem identifier. Keep it short.
Examples in the existing set: `oss-license`, `asvs-v5`, `iso-27001`, `soc2`, `gdpr`.

The `id` field inside `manifest.yml` is what shows up in finding metadata and
SARIF run names — by convention longer-form: `oss-license-compliance`,
`owasp-asvs-v5-compliance`, etc.

## 2. Write the manifest

```yaml
id: my-framework-compliance
version: 1.0.0
description: One-line summary of what this skill audits.

detection:
  always_applicable: false        # set true for frames that apply to every repo
  paths:
    - "**/*.tf"                   # globs that signal applicability
    - ".compliance/my-framework.yaml"

# What this skill produces for downstream skills (e.g. SBOM).
produces: []
# What this skill consumes from upstream skills.
consumes: ["sbom"]

static_scan:
  - id: my-tool
    tool: docker                  # or: binary | script
    image: org/my-tool:latest     # docker only
    args:
      - "scan"
      - "--format=json"
      - "--output=${OUT}"
      - "${REPO}"                 # ${REPO}, ${OUT}, ${ARTIFACT_DIR}, ${ARTIFACT_<NAME>} substituted
    parser: trivy                 # or: semgrep | gitleaks | checkov | scancode | ort | privado | bearer | helsinki | sarif | json
    timeout_seconds: 240
    pr_mode_enabled: true         # run in PR mode? (false for slow tools)
    swarm_mode_enabled: true
    output_format: json
    failure_action: warn          # fail | warn | ignore — what to do if the tool errors

deep_audit:
  - id: my-llm-check
    prompt_file: references/my-prompts.md
    section: "Section heading the LLM should use"
    inputs:
      - changed_files             # special tokens
      - sbom                      # produced-artifact names
      - "src/**/*.ts"             # globs matched against the repo
    max_input_chars: 100000

finding_extraction:
  framework: my-framework         # MUST be one of the known frameworks (see schema)
  default_severity_mapping:
    CRITICAL: critical
    HIGH: high
    MEDIUM: medium
    LOW: low
  cross_framework:
    - { tag: "NIST 800-53", control: "AC-2" }
    - { tag: "ISO 27001:2022", control: "A.8.24" }

suppression:
  config_file: null               # or path to a skill-native suppression config
  inline_pragma: null

out_of_repo:
  - "Things this skill explicitly cannot adjudicate from repo content."
```

## 3. Adding a new framework constant

The `framework` enum is currently fixed to the original 5. Adding a sixth
requires a small core change:

1. Add the value to `FrameworkValues` in `packages/cli/src/findings/schema.ts`.
2. Add a case to `FRAMEWORK_LABEL` in `packages/cli/src/emit/markdown.ts`.
3. Add the value to `SkillManifestSchema`'s framework enum in
   `packages/cli/src/skills/manifest.ts`.

These are 3-line changes; they're separated to keep the framework list
explicit (vs. accepting any string, which would let typos flow through).

## 4. Parser choice

If your tool emits SARIF 2.1.0, use `parser: sarif` and you're done. Otherwise
pick the parser whose output shape matches yours. If none fit, add a parser:

1. Create `packages/cli/src/tools/parsers/<your-tool>.ts` exporting a `Parser`.
2. Register it in `packages/cli/src/tools/parsers/index.ts`.
3. Add it to the `ParserName` union in `manifest.ts`.

A parser is a 30-50 line function: take raw output (string), return `Finding[]`.
See `trivy.ts` or `checkov.ts` as references.

## 5. Test it

Write a unit test mirroring `tests/unit/parsers.test.ts` — feed canned tool
output through the parser and assert the resulting findings.

For end-to-end, extend `tests/integration/dirty-fixture.test.ts` to add your
skill to the `FAKE_SKILLS` array with canned scanner output.

## 6. Cross-framework discipline

Filling out `cross_framework` is the single biggest leverage point. A finding
your skill emits will dedup with findings from other skills only when the
mappings line up. Get this right by referencing each skill's existing
`cross_framework` entries — re-use the same `tag` strings (`NIST 800-53`,
`ISO 27001:2022`, `SOC 2`, `CIS v8`, etc.) so dedup keys match.

## Submitting upstream

Open a PR with:

- Manifest + parser + tests
- A changeset (`npx changeset` → `minor` for new skill, `patch` for new check)
- README mention if it changes the headline list

The CI workflow runs your skill against the test fixtures; the self-audit
workflow runs the orchestrator on this repo to make sure your changes don't
crash the existing 5 skills.
