---
'compliancemaxx': patch
---

Include the human-readable `compliance-comment.md` in the action's
uploaded artifact, alongside the SARIF and JSON dossier.

Previously the markdown summary was only used for posting a sticky PR
comment — which never fires for cron-triggered runs (no PR exists).
That left swarm/audit-mode runs with no easy way to read findings
without parsing the raw JSON.

Also exposes the new `comment-path` action output for programmatic
consumers, and fixes a leftover `swarm`-vs-`audit` mode name
inconsistency in the retention-days expression.
