# Changesets

This directory contains changesets for `compliance-swarm`. Each user-facing
change should ship with a changeset describing the change and its semver
impact.

## Adding a changeset

```
npx changeset
```

Pick the affected package(s) (`compliance-swarm`), choose the version bump
(major / minor / patch), and write a one-line summary. Commit the generated
markdown file with your PR.

## What gets released

When the release workflow runs on `main`:

1. If pending changesets exist → opens / updates a "Version Packages" PR.
2. When that PR is merged → publishes to npm, tags `vX.Y.Z`, and force-moves
   the major-version Action tag (`v1`, `v2`, …) so consumers using
   `uses: erp-mafia/compliance-swarm@v1` always get the latest 1.x.

See `.github/workflows/release.yml`.
