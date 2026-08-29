# `src/packages/oracle` — name collision notice

**This package is not the Oracle assurance authority.**

For doctrine Oracle — the independent, read-only Completion Validation
authority that returns `PASS`/`BLOCK` before every successful final
delivery — see:

- `src/roster/oracle.md` (roster entry)
- `doctrine/oracle.md` (canonical behavior)
- `agents/oracle.md` (dispatch definition)
- `src/packages/contracts/schemas/oracle-completion-validation-v1.schema.json`
  (the machine-checkable PASS/BLOCK receipt schema)

## What this package actually is

`src/packages/oracle` is a facade over the **Audit** core
(`src/lib/core`: `inspectProduct`, `buildPlan`, `audit`, `verifyRun`,
`explain` — see `src/packages/oracle/lib/facade.mjs`). `src/lib/core` itself
contains zero references to "oracle" anywhere in its source. This package's
output shape is Audit-shaped (`findings`, `denominators`, `claimBoundary`),
not a Completion Validation verdict.

It appears to be an artifact of an earlier migration where an Audit-facing
package was named `oracle`, before "Oracle" was fixed as the canonical name
of the Completion Validation authority elsewhere in the codebase
(`src/config/naming-registry.json`, `docs/agent-rules.md`,
`docs/LEGION-CANONICAL-SSOT.md`). The collision is coincidental, not
architectural — the two "oracle"s share a name and nothing else.

## Consumer status

As of this writing, no code outside this package's own tests
(`src/packages/oracle/tests/*.test.mjs`) imports from
`src/packages/oracle`. It is packaged (referenced in `package.json`,
`biome.json`, `MANIFEST.package.json`) but has no external caller. It is
also the first hit a code search for "oracle" surfaces, which actively
misleads anyone looking for the assurance authority — see
`docs/audits/oracle-audit.md` Finding 5.

## Open question (not decided here)

Whether this package should be renamed (e.g. to something under an
`audit-facade` or `audit-core-bridge` name that doesn't collide with the
Oracle authority) or removed outright, since it currently has no consumer.
That decision — including whatever removal entails for
`legacy-parity.json`, `greptile-absorb.test.mjs`, and any historical-evidence
value the fixtures carry — is reserved for the repository owner and is
deliberately **not** made by this file. Nothing in `src/packages/oracle/**`
has been deleted or renamed as part of writing this notice.
