# Coverage-on-the-change and audit_diff trajectory

Two `render-report.mjs` additions layered on the standard `report.json` shape
(`references/engine-interface.md` §Report shape). Both are RENDERER-owned: the lenses (or `/commit`'s
diff-scoped gate) supply input data; `render-report.mjs` computes the gate/verdict and persists what
needs to persist across runs. Neither one mutates `facts.json` or `collect-facts.mjs`'s check set.

## Per-change coverage rows (§2A)

**Problem.** A binary "tests pass" hides that the CHANGED code specifically is untested — the suite
can be green while every touched symbol is uncovered. §2A reports coverage **per file**, not as one
boolean.

**Input shape** — supplied on `report.coverage` when the run is diff-scoped (matches the schema locked
with `/commit`, `tools/skills/commit/SKILL.md` "Coverage on the change"):

```json
{
  "coverage": {
    "ratio": 0.5,
    "perFile": [
      {
        "file": "src/auth/mfa.ts",
        "touched": ["MFA.verify", "MFA.challenge"],
        "covered": ["MFA.verify"],
        "uncovered": ["MFA.challenge"],
        "tests": ["test/auth/mfa.test.ts"],
        "verdict": "partial"
      }
    ]
  }
}
```

`ratio` is optional — `coverageGate()` derives it from `sum(covered)/sum(touched)` across `perFile`
when omitted. This is a **read of the diff against the test set** — the lens (or `/commit`) never
re-runs the test suite to produce it.

**Gate thresholds** (`coverageGate()` in `render-report.mjs`):

| condition | state | severity |
|---|---|---|
| `report.coverage` absent, or `perFile` empty | *(section omitted — nothing to render)* | — |
| `ratio` unreadable (no test infrastructure) | `UNPROVEN` | — |
| any touched file with an **empty `tests` array** | `NOT CLEAN` | `critical` |
| `ratio < 0.5` | `NOT CLEAN` | `critical` |
| `ratio < 0.8` | `NOT CLEAN` | `high` |
| `ratio >= 0.8` and every touched file has a covering test | `CLEAN` | — |

A file with zero covering tests is `critical` **regardless of the aggregate ratio** — an untested
touched file is not offset by other files being well-covered. `UNPROVEN` never collapses to `CLEAN`:
if the repo has no test infrastructure to read against, the gate says so honestly rather than passing
by default.

**Rendering.** §2A prints the gate line, an inline `⛔` banner naming every file with no covering
test, and the full per-file table (`file | touched | covered | uncovered | tests | verdict`). The
`--agent` JSON summary carries the same data as `coverage_gate: {state, ratio, severity,
no_test_files}`.

**Scope.** A whole-repo `/audit` pass typically has no diff to read coverage against, so
`report.coverage` is simply absent and §2A prints a one-line "not reported this run" note — this is
expected, not an error. The feature is exercised by `/commit`'s diff-scoped gate and any lens that
chooses to supply diff-scoped coverage on a `/audit --base <ref>` run.

## `audit_diff` trajectory

**Problem.** A single audit run is a snapshot with no sense of direction — is the repo getting
better or worse since last time? `audit_diff` answers that without asking the user to diff two
Markdown reports by eye.

**Ownership.** The RUNNER (`render-report.mjs`), not the lenses, computes this — lenses only ever
describe the *current* state; they have no memory of prior runs. `render-report.mjs` persists a
compact fingerprint digest at:

```
<workspace>/.audit/audit-trajectory.json
```

(override with `--trajectory-history <path>` — useful for the fixture/demo run in this doc, or for a
CI job that wants an isolated history file). The digest is read at the start of every invocation,
diffed against the current finding set, and rewritten at the end — best-effort; a write failure logs
to stderr and never blocks the render.

**Fingerprint.** `file:line + category + title` (title case-folded). When no exact match survives
for a prior entry, one fallback pass retries on `category + title + basename(file)` — this tolerates
a same-run file rename without double-counting it as both `resolved` and `new`. The loose match is
only accepted when it is a **unique 1:1 pairing** on both sides; an ambiguous loose match (two
candidates sharing the same loose key) is left unmatched and counted as `resolved` + `new` rather than
silently guessed.

**Output shape:**

```json
{
  "audit_diff": {
    "vs_prior_run": {
      "prior_run_at": "2026-07-01T00:00:00.000Z",
      "resolved": 12,
      "new": 3,
      "aged": 5,
      "unchanged": 47,
      "newly_p0": 1
    },
    "aging_buckets": [
      { "bucket": "0-7d", "count": 28 },
      { "bucket": "8-30d", "count": 12 },
      { "bucket": "31-90d", "count": 9 },
      { "bucket": "90+d", "count": 1 }
    ]
  }
}
```

- `resolved` — fingerprints present in the prior digest with no match in the current run.
- `new` — current findings with no match in the prior digest.
- `aged` / `unchanged` — matched findings split on `first_seen` age: **> 30 days** old is `aged`,
  otherwise `unchanged`. `first_seen` carries forward across matches; a matched finding never resets
  its clock just because it showed up again.
- `newly_p0` — findings (matched or new) whose severity is `critical` this run but was not `critical`
  the prior run (a matched finding that got worse, or a brand-new finding that started critical).
- `aging_buckets` — every *current* finding bucketed by age (`0-7d`/`8-30d`/`31-90d`/`90+d`), computed
  the same way regardless of whether a prior run exists.
- `vs_prior_run` is `null` on the very first run at a given history path — there is nothing to diff
  against yet. `aging_buckets` still renders (everything lands in `0-7d`).

**Rendering.** The Markdown report prints a one-line trajectory summary right under the quality-gate
banner (before §1), and the aging-bucket breakdown beneath it. The `--agent` JSON summary carries the
identical object under `audit_diff`.

## Demonstration (fixture, run 2026-07-25)

Two consecutive `render-report.mjs` invocations 45 days apart, isolated to a scratch history file via
`--trajectory-history`:

- Run 1: `F1` (high, `src/auth/mfa.ts:42`), `F2` (critical, `src/db/query.ts:10`).
- Run 2 (45 days later): `F1` fixed (absent), `F2` still present, `F3` (critical,
  `src/config/secrets.ts:5`) newly introduced. `coverage.perFile` shows `src/db/query.ts` fully
  covered and `src/config/secrets.ts` with an empty `tests` array.

Run 2's `--agent` output:

```json
{
  "audit_diff": {
    "vs_prior_run": {
      "prior_run_at": "2026-07-01T00:00:00.000Z",
      "resolved": 1, "new": 1, "aged": 1, "unchanged": 0, "newly_p0": 1
    },
    "aging_buckets": [
      { "bucket": "0-7d", "count": 1 }, { "bucket": "8-30d", "count": 0 },
      { "bucket": "31-90d", "count": 1 }, { "bucket": "90+d", "count": 0 }
    ]
  },
  "coverage_gate": {
    "state": "NOT CLEAN", "ratio": 0.5, "severity": "critical",
    "no_test_files": ["src/config/secrets.ts"]
  }
}
```

`F1` resolved, `F3` is new-and-critical (`newly_p0: 1`), `F2` survived 45 days so it moved from
`0-7d`/`unchanged` into `31-90d`/`aged`. Coverage gate is `critical` because `src/config/secrets.ts`
touched `loadSecrets` with zero covering tests, even though the aggregate ratio (0.5) alone would only
be borderline.
