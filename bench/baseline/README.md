# Legion benchmark baseline

Captured at PR04 from the frozen starting commit `4e82122e713341f9a27545207a00ba45645d8e8f`.

- `bench-baseline.json` — deterministic output of `node bench/run-bench.mjs --json` at PR04 (bench-local detectors over the 13-fixture planted corpus).
- Every deterministic rule family in the planted corpus has at least one negative control fixture in `bench/fixtures/`:

| Class | Positive fixture | Negative control |
|---|---|---|
| secret | `001-hardcoded-secret` | `002-negative-apikey-label`, `010-negative-commented-credential` |
| dependency_cve | `003-vulnerable-dep` | `004-negative-dep-latest` |
| dead_code | `005-dead-code` | `006-negative-reachable` |
| duplication | `007-duplicated-logic` | `008-negative-similar-shape` |
| type_error | `009-type-error` | `013-negative-type-ok` |
| drift | `011-doc-drift` | `012-negative-doc-matches` |

The qualification receipt digest in `bench-baseline.json` is the versioned baseline marker. A future benchmark run that changes recall/precision must update this baseline deliberately, not silently.
