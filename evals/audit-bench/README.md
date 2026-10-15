# audit-bench

Benchmark seed for Audit v2 (design ADR-6, phase 1). It measures what an installed `legion audit`
finds in small repositories whose defects were planted on purpose, so engine changes can be gated
on recall, location recall, clean rate and precision bounds instead of on impressions.

## Layout

```
evals/audit-bench/
  README.md
  build-fixtures.sh              rebuilds the bundles deterministically
  fixtures/
    <name>.bundle                git bundle of the fixture repository
    <name>.cases.json            planted and clean cases for that bundle
```

Seed corpus: `rust-ledger`, `ts-orders`, `py-inventory` (see `build-fixtures.sh` for the sources).

## Fixture repositories

Each bundle holds `main` (the base commit, tagged `base`) and one tag per case. A case is exactly one
commit on a detached branch off `base`, so cases never see one another's changes. Commit ids are
stable because the build fixes author, date and file content.

Rebuild (work dir must be new or empty, and on a large volume):

```
evals/audit-bench/build-fixtures.sh <work-dir>
```

## cases.json

```json
{
  "schema": "legion-audit-bench-cases/1",
  "fixture": "rust-ledger",
  "language": "rust",
  "base": "base",
  "cases": [
    {
      "id": "rust-cr-frozen-debit",
      "kind": "planted",
      "scope": "range:base..rust-cr-frozen-debit",
      "category": "caller-regression",
      "ruled": true,
      "ruling": "construction",
      "summary": "one line on what was planted",
      "expected": [
        {
          "path": "src/transfer.rs",
          "lineRange": [11, 11],
          "lens": "read-beyond-diff",
          "severity": "high",
          "alt": [{ "path": "src/account.rs", "lineRange": [20, 30] }]
        }
      ],
      "rulings": []
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `kind` | `planted` (a known defect) or `clean` (a change a human ruled defect-free). |
| `scope` | `range:A..B` audits `A..B` with `B` checked out; `commit:X` audits `X^..X`. Refs are tags or commit ids. |
| `category` | Planted cases only: `security`, `correctness`, `perf`, `lean` or `caller-regression`. |
| `ruled` | Defaults to `true`. `false` marks a row without a human ruling; it is never scored. |
| `ruling` | Free text naming the basis of the ruling. The seed rows use `construction`: the planter built the defect and wrote the expectation. |
| `expected[]` | One item per planted defect: location, rule or lens, severity. Clean cases list none. |
| `expected[].alt` | Other locations that also count as finding the item. |
| `rulings[]` | Optional rulings on extra finding locations in a planted case: `{path, lineRange, verdict: right\|wrong}`. They override expectation matching and resolve findings that would otherwise be unresolved. |

A caller regression is a change in one file that breaks behaviour in an unchanged caller. Its
primary expected site is the unchanged caller (finding it needs read-beyond-diff); the changed line
is listed under `alt`, so a reviewer that only flags the diff still gets recall credit but not caller
recall.

The seed contains 18 planted cases (4 caller regressions) and 8 clean changes. Unknown JSON fields
are rejected so a typo cannot silently drop a ruling.

## Runner

```
legion-dev audit-bench --legion <installed legion> [--fixture <name>]... [--repeat N] [--aa]
                       [--work-dir <dir>] [--keep] [--json]
```

For each fixture, repeat and case, the runner clones the bundle, checks out the case head, resolves
the base to a commit id, and runs

```
legion audit <clone> --base <base-commit> --quiet --out <case-out>
```

then reads `<case-out>/report.json`. A finding location is `path`, `path:line` or `path:start-end`.
Only the deterministic phase runs; `--with-lenses` is reserved and currently rejected. A case whose
audit produces no `report.json` is listed under `caseErrors`, excluded from every ratio, and makes
the command exit non-zero. A non-zero `legion audit` exit with a report is normal (findings).

Default scratch directory is `<repo>/.cache/audit-bench` (git-ignored); it is removed unless `--keep`.

## Metrics

Counts are summed across fixtures before ratios are taken.

- **recall**: expected items with a finding on the expected (or an alternate) path / items.
- **location recall**: expected items with a finding whose lines overlap the expected (or an alternate) range / items.
- **caller recall**: caller-regression items found at the primary caller range / caller-regression items.
- **clean rate**: clean cases with no finding / clean cases.
- **precision lower bound**: right / (right + wrong + unresolved), unresolved counted wrong.
- **precision upper bound**: (right + unresolved) / (right + wrong + unresolved), unresolved counted right.

A finding is right when it overlaps an expected site or a `rulings` right entry, wrong when it lands
on a clean case or a `rulings` wrong entry, and unresolved otherwise. Rows with `ruled: false` are
skipped and counted in `unruledSkipped`.

## Repeats and the A/A band

`--repeat N` runs the whole corpus N times per arm. `--aa` adds an identical twin arm. The A/A band
half-width is half of (max - min) over every per-run recall of both arms, reported next to the two
arm means. A deterministic engine gives a zero band; a reasoning phase will not. Per ADR-6 the
corpus grows until the half-width is 10 percentage points or less, and a gate passes when recall is
at or above `baseline - band`.

## Limits

- No per-case timeout yet; a hung `legion audit` blocks the run.
- Cases run sequentially.
- The planted defects are semantic. Deterministic rules are expected to find few of them; the
  baseline measures that, it does not assume it.
