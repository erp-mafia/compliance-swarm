# Contributing

Thanks for considering a contribution.

## Ground rules

- File an issue before a non-trivial PR — saves us both time.
- Add a [changeset](./.changeset/README.md) to any user-facing change.
- Keep PRs focused — one concern per PR.
- Tests for new behavior. Snapshot tests for SARIF / markdown output where
  the shape is part of the contract.

## Getting started

```sh
git clone https://github.com/erp-mafia/compliance-swarm
cd compliance-swarm
npm install
npm test
```

Inside `packages/cli/` you can run individual scripts:

```sh
cd packages/cli
npx tsx bin/compliance-swarm.ts list-skills
npx vitest          # watch mode
npm run typecheck
```

## Adding a new skill

See [docs/writing-a-skill.md](./docs/writing-a-skill.md).

## Adding a new parser

See the parser section of [docs/writing-a-skill.md](./docs/writing-a-skill.md#4-parser-choice)
and existing parsers under `packages/cli/src/tools/parsers/`.

## Style

- TypeScript strict mode with `exactOptionalPropertyTypes` and
  `noUncheckedIndexedAccess`.
- No comments unless the *why* is non-obvious.
- Keep imports flat: prefer `import { X } from '../foo.js'` over star imports.
- Don't introduce a logger — use `createLogger(prefix)`.

## Releasing

`changesets/action` opens a release PR on `main`. Maintainers merge it; the
release workflow then publishes to npm and force-moves the major-version
Action tag (`v1`, `v2`, …).

## Code of conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Be kind. Argue ideas, not
people.
