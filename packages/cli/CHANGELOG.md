# compliancemaxx

## 0.1.1

### Patch Changes

- [`5686758`](https://github.com/erp-mafia/compliancemaxx/commit/568675885e056dd698d6cd06fe455744bc16df92) Thanks [@jakobwennberg](https://github.com/jakobwennberg)! - First release through the OIDC trusted-publisher pipeline.

  - Bundle `packages/skills/` into the npm tarball via `prepack` so
    `npx compliancemaxx` works without checking out the repo.
  - `release.yml` no longer needs `NPM_TOKEN`; npm trusted publishing
    mints a short-lived OIDC token at publish time and produces
    provenance attestations automatically.
  - Canonicalize `bin` and `repository.url` per `npm pkg fix`.
