# Phase 6.7 — Evidence Gauntlet

A diff-scoped, three-layer mechanical check for `commit` and any other
`/commit`-adjacent gate. Bounded to the frozen diff — never repo-wide.

## The three layers

1. **Mutation testing on changed lines.** For each added line in the
   diff, the gauntlet injects a small syntactic fault (`===`→`!==`,
   `&&`→`||`, `return N`→`return !N`, `return "x"`→`return ""`,
   `return N`→`return 0`), reruns the project's test command, then
   restores the source. A mutant that survives proves the test cannot
   fail on that change — the preventive twin of Insights'
   `tests-that-cannot-fail` detector.

2. **Changed-lines-only coverage.** Drives `NODE_V8_COVERAGE` and
   reports the fraction of *added* lines that were executed at least
   once. Whole-repo coverage is discarded — it moves too slowly to
   gate anything and punishes untouched legacy code.

3. **Test-order independence.** Reuses a seeded Fisher-Yates shuffle. The gauntlet re-invokes the
   test command N times with different seeds via `GAUNTLET_TEST_ORDER`;
   any order-dependent failure shows up as a failed run.

## Output

A single JSON object on stdout matching Arcane's `check` shape
(`executor: 'host'`, `authority: 'host'`, `kind: 'gauntlet'`,
`status: 'passed' | 'failed'`, `exit_code: 0 | 1`, `output: <JSON>`,
`receipt: <JSON>`). Existing trust-class and issuer-derived-field
enforcement in Arcane applies unchanged.

## Standing anti-gaming constraints (in the implementation, not just a comment)

- Never weaken a test to make the gauntlet pass.
- Never report an unrun check as passed.
- Mutators that don't match the line's syntactic shape are reported as
  `skipped` with a reason, never silently ignored.
- Layer failure is always `failed`, never `passed` or `unverified`.

## Integration

```bash
# Run the gauntlet on the working tree against HEAD.
node src/lib/gauntlet/gauntlet.mjs

# CI mode: compare against a base branch.
node src/lib/gauntlet/gauntlet.mjs --base origin/main

# Use a frozen diff file (preferred for /commit).
node src/lib/gauntlet/gauntlet.mjs --diff /tmp/frozen.diff

# Pipe the receipt into Arcane as a host-issued check.
node src/lib/gauntlet/gauntlet.mjs | jq -r '.receipt' | legion arcane verify --check
```

The `command` field is the exact rerunnable command, matching the
workspace "one small runnable check" rule and old-coder's EVIDENCE
format.

## Files

- `gauntlet.mjs` — entry point.
- `lib/diff.mjs` — diff extraction (added lines per file).
- `lib/mutation.mjs` — mutation testing on changed lines.
- `lib/coverage.mjs` — changed-lines-only coverage.
- `lib/order.mjs` — test-order independence.
- `lib/arcaneshape.mjs` — receipt + check shape.
- `tests/gauntlet.test.mjs` — self-tests.
- `tests/fixtures/sample-diff/` — weak test plus a known survivable
  mutant; proves the gauntlet refuses to pass when the test is weak.
