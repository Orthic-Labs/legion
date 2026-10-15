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

Seed corpus: `rust-ledger`, `ts-orders`, `py-inventory`, `audit-behavior`, `heldout-controls` (see
`build-fixtures.sh` for sources).

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
  "split": "tuning",
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
| `split` | Fixture-level `tuning` or `heldout`; omitted metadata is reported as `unknown`. |
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

The seed contains 23 planted cases (4 caller regressions) and 14 clean changes. `audit-behavior`
adds Redis session TTL positives & controls, local `Map.set` & documentation URL controls, an
executable unpinned download, & two distinct Redis finding locations. `heldout-controls` is a separate
five-case held-out split with paired Redis expiry & executable-bootstrap controls. Unknown JSON fields
are rejected so a typo cannot silently drop a ruling.

## Runner

```
legion-dev audit-bench --legion <installed legion> [--fixture <name>]... [--case <id>]...
                       [--repeats N] [--aa] [--with-lenses] [--token-budget N]
                       [--case-token-budget N]
                       [--claude <path>] [--model <id>] [--work-dir <dir>] [--keep] [--json]
```

Bounded single-case runtime validation:

```
legion-dev audit-bench --legion <installed legion> --fixture audit-behavior \
  --case audit-redis-session-no-ttl --with-lenses --token-budget 10000 --keep --json
```

For each fixture, repeat and case, the runner clones the bundle, checks out the case head, resolves
the base to a commit id, and runs

```
legion audit <clone> --base <base-commit> --quiet --out <case-out>
```

then reads `<case-out>/report.json`. A finding location is `path`, `path:line` or `path:start-end`.
Each fixture case file may declare top-level `split: "tuning"` or `"heldout"`; missing split is
reported as `unknown`, never inferred. Results remain partitioned in `splitResults`, so held-out
scores & A/A bands stay separate from tuning scores. `--case` selects one or more case ids and
restricts scoring denominators to selected cases; unknown ids fail before scratch data is created.
Each ruled selected case enters first-attempt denominators before execution. Failed or unstarted cases remain
denominator misses and appear under `failedOrUnstartedCases`; `caseOutcomes` records `completed`,
`failed` or `unstarted` for each planned attempt. A non-zero `legion audit` exit with a report is
normal (findings). `git` is bounded to 30 seconds & audits to 10 minutes, then timed-out
process trees are terminated through RightKit.

With `--with-lenses`, the same installed executable also runs
`legion audit run-reasoning --run <case-out> [--claude <path>] [--model <id>]` under a 10-minute bound.
`--claude` and `--model` pin native runtime identity; otherwise installed PATH/default identity applies.
The aggregate token allowance is shared across every selected case, repeat and A/A arm. Its default
is 100,000 tokens; `--case-token-budget` defaults to 10,000 and sets maximum reservation per case.
Each reservation is bounded by current aggregate remaining, forwarded as
`legion audit --run-token-budget`. Actual input, output and retry tokens are
reconciled before the next case (cached input is already part of input totals); known unused reservation returns to shared allowance. Missing or
malformed actual usage burns full case reservation & halts further model cases, preserving their
planned denominator as unstarted. A measured case overrun also halts later model cases.
Usage reconciliation includes parent and security-variant follow-up runtime receipts.
Cases reached after budget exhaustion remain denominator misses with `status: unstarted`; budget
diagnostics report limit, actual known tokens, unknown usage cases, remaining allowance and overruns.
Any A/A band uses only complete arms; exhausted arms remain in score denominators but cannot create
an A/A estimate. No model calls are synthesized by the benchmark. The benchmark reads
`review-runtime.json`, requires `complete: true` & `status: "done"` for completion, then rereads
the reconciled `<case-out>/report.json` for final scoring. Incomplete runs retain any final partial
findings, record every runtime/report failure, & remain failed in the first-attempt population.
Each case metric keeps deterministic/raw-stage & final-report metrics separate, including
scanner candidates, findings, provider phases, reported actual token/cache/cost values, and unknowns.
`wallTimeMs` is measured for both stages; phase-level values not emitted by runtime remain unknown.

Default scratch directory is `<repo>/.cache/audit-bench` (git-ignored); it is removed unless `--keep`.

## Metrics

Counts are summed across fixtures within each split before ratios are taken. Top-level `armA` and
`armB` preserve all-selected-fixture aggregates for continuity; tuning & held-out decisions use
their independent `splitResults` entries.

- **semantic recall proxy**: expected items with a finding on an expected (or alternate) path / all planned expected items. Path matching is a label proxy, not proof of semantic equivalence.
- **localization proxy**: expected items with a finding whose lines overlap an expected (or alternate) range / all planned expected items.
- **caller recall**: caller-regression items found at the primary caller range / caller-regression items.
- **clean rate**: clean cases with no finding / clean cases.
- **precision lower bound**: right / (right + wrong + unresolved), unresolved counted wrong.
- **precision upper bound**: (right + unresolved) / (right + wrong + unresolved), unresolved counted right.

A finding is right when it overlaps an expected site or a `rulings` right entry, wrong when it lands
on a clean case or a `rulings` wrong entry, and unresolved otherwise. Rows with `ruled: false` are
skipped and counted in `unruledSkipped`.

Output separates pre-adjudication scanner candidate evidence from final report findings. Raw
candidate count is `null` with explicit unavailable or malformed status when report lacks usable
candidate evidence. When raw locations are recognizable, raw candidates receive separate
expectation-based score; unavailable locations are misses. Per-provider phase, actual token use,
cached input use, cost & timing values
appear only when reported; absent values are `unknown`. `wallTimeMs` measures full `legion audit`
process time without `--with-lenses`, and both deterministic audit plus reasoning runtime when
`--with-lenses` is enabled. An incomplete runtime with a partial report can contribute observed
findings, but it does not count as a completed case. Runtime usage is aggregated from persisted
host receipts; any missing receipt/token field makes aggregate totals `null` while known subtotals
remain visible. Runtime cost stays `unknown` unless the host reports it.

## Repeats and the A/A band

`--repeats N` runs the whole corpus N times per arm (`--repeat` remains an alias); values are
bounded to 1..=10. Default remains one run. `--aa` adds an identical twin arm. Each split reports
its own A/A recall band, keeping held-out results out of tuning aggregates. With at least two
repeats, `repeatIntervals` reports empirical min/max/range for measured full-run latency & host
input/output/cache/retry tokens, per arm & across both arms. These are observed ranges, not
confidence intervals; incomplete evidence produces `unknown`, while fewer than two repeats reports
`insufficient-repeat-evidence`. No general performance or accuracy threshold is implied before repeated
measurements establish variance; the CI sample below uses case-specific assertions. `ablationIdentity` names `deterministic-only` or
`deterministic-plus-reasoning` for each output.

## CI deterministic sample

macOS CI runs `audit-behavior` against assembled installed `legion`, with two repeats & an A/A twin,
without model reasoning. For this fixture only, deterministic stage selects
`legacy.data.internal-suite` & `legacy.security.binary-pins`; JSON names this restricted provider
scope & separately reports full-Audit completeness. CI asserts selected-stage coverage, first-attempt
denominators, expected raw-candidate location hits for three planted cases, zero raw candidates
for three controls, identical raw-candidate scores across repeats & A/A arms, and repeated latency
ranges. Raw candidates remain separate from final report findings, so this sample does not claim
semantic recall. CI prints machine-readable JSON before assertions exit; it does not add diagnostics
to installed app or installer payloads.

## Limits

- Cases run sequentially.
- Semantic recall & localization are expectation-based proxies; they do not replace human review.
- The deterministic CI gate covers only the named `audit-behavior` sample; it does not establish
  performance on all planted cases or on held-out controls.
