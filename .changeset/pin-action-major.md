---
'compliancemaxx': patch
---

Pin `action.yml` to `compliancemaxx@^2.0.0` instead of `@latest`.

Previously the action invoked `npx -y compliancemaxx@latest` because
`$GITHUB_ACTION_REF` is not consistently populated in composite actions.
This meant `uses: erp-mafia/compliancemaxx@v1` would silently pull the v2
npm package — a breaking change leak. The action now uses
`${{ github.action_ref }}` (more reliable) and falls back to a hardcoded
major-version pin baked into action.yml itself.

Each future major release will bump this pin; the corresponding git tag
will capture the new action.yml, so consumers stay on the major they
opted into.
