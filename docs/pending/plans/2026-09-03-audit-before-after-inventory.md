# Audit skill: before/after inventory across the product extraction

BEFORE is `tools/skills/audit/` in the `<workspace>` workspace repo at `52a90cf0^` — the
parent of the commit that deleted it. AFTER is the shipped Legion product. Produced
2026-09-03 by an independent read-only pass; every claim cites a path.

Section 5 has been acted on: rows 1-4 are done (see `bench/` and
`tests/run-audit-conformance-tests.mjs`), row 5 is resolved by downgrading the tier rather
than substantiating it, and rows 6-10 remain open.

**Correction to the brief's provenance:** commit `52a90cf0` is in the **`<workspace>` workspace repo** (not a separate `bogusyogi` repo — that path is a subdirectory), and it is the commit that **deleted** `tools/skills/audit/`. The BEFORE tree is therefore its parent, `52a90cf0^`. All BEFORE citations below use `git -C <workspace> show 52a90cf0^:tools/skills/audit/<path>`.

---

## 1. FILE INVENTORY

BEFORE = 93 files under `tools/skills/audit/`. AFTER = the `legion` repo, where the engine was split: skill prose → `skills/audit/`, runner → `tools/audit/`, providers/registry/schemas → `src/`, references → `references/`.

| BEFORE group | n | Status in AFTER |
|---|---|---|
| **root** (`audit-{run,plan,runtime,verify,finalize,complete}.mjs`, `collect-facts.mjs`, `render-report.mjs`, `security-pipeline.mjs`, `audit_provider.py`, `audit_store.py`, `manifest.json`, `SKILL.md`, `UPGRADE-PLAN.md`) | 14 | 12 kept (renamed → `tools/audit/*`); `manifest.json` → `legion/manifest.json` (v2→v3); `SKILL.md` → `skills/audit/SKILL.md` (54→82 lines). **`UPGRADE-PLAN.md` absent.** |
| **`_selfcheck/`** (`clean.html`, `perf.html`) | 2 | **Both absent** (no `_selfcheck` anywhere; `git ls-files \| grep selfcheck` empty). |
| **`adapters/`** | 3 | 2 kept → `src/adapters/ecosystem-manifests.mjs`, `src/adapters/security-adjudication.mjs`. **`cortex-projection.mjs` absent** (only a schema, `src/schemas/core/cortex-projection-receipt-v1.schema.json`, remains). |
| **`bench/`** (6 detectors, 15 fixture files, `manifest.json`, `run-bench.mjs`, `precision-recall.mjs`, `real-scan.mjs`, `run-provider-selection-benchmark.mjs`) | 26 | **All 26 absent.** No `bench/` directory exists in `legion`. |
| **`evals/`** | 2 | Both kept → `skills/audit/evals/evals.json` (236→212 lines), `src/evals/ground_truth/labeled_samples.json` (now orphaned — see §4). |
| **`providers/`** (8 suites) | 8 | All 8 kept → `src/providers/*.mjs`, plus ~40 new provider directories alongside. |
| **`references/`** (13 `.md`) | 13 | All 13 kept → `legion/references/`; 8 of them mirrored into `skills/audit/references/`. `a11y-checklist`, `desktop-tauri-checklist`, `performance-checklist`, `security-checklist`, `sqlite-local-first` live only at engine level, not in the shipped skill dir. |
| **`registry/`** | 4 | All 4 kept → `src/registry/`. |
| **`schemas/`** (2) | 2 | Both kept → `src/schemas/provider-result-v1.schema.json`, `src/schemas/security-verdict-v1.schema.json` (plus subdirectory copies). |
| **`scripts/`** (`generate-manifest`, `normalize-provider-result`, `report-to-sarif`, `self-test`) | 4 | All 4 kept → `legion/scripts/`. |
| **`tests/`** (15) | 15 | 14 kept → `legion/tests/`. **`tests/provider-architecture.test.mjs` absent.** |

**Totals — BEFORE 93 · surviving 62 · lost 31.**
Lost = 26 bench + 2 `_selfcheck` + `cortex-projection.mjs` + `provider-architecture.test.mjs` + `UPGRADE-PLAN.md`.

AFTER-side additions in the same footprint: `tools/audit/provider-benchmarks.mjs`, `tools/audit/security-chain-pipeline.mjs`, `skills/audit/{RIGHTS.json,dependencies.json,agents/openai.yaml}`, `skills/audit/references/{audit-design-decisions,execution-contract}.md`, `src/registry/coverage/*` (12 files), `src/lib/coverage/index.mjs`.

---

## 2. THE BENCH / CORPUS (the whole of this is lost)

### 2.1 What each detector detects
All six are deliberately offline, deterministic, zero-shell-out approximations of a production tool (`bench/detectors/*.mjs`):

| Detector | Approximates | Mechanism |
|---|---|---|
| `secrets.mjs` | gitleaks | Four regexes over **literal values** — `AKIA[0-9A-Z_]{10,}`, `EXAMPLE/NOTREAL/SECRETKEY…`, `sk-[A-Za-z0-9]{20,}`, `-----BEGIN … PRIVATE KEY-----`. Skips lines starting `//` or `*`, so a credential *name* in a comment cannot fire. Returns `{line, match}`, 1-indexed. |
| `deps-cve.mjs` | `npm audit` / `deps_cve` | Static table `KNOWN_VULNERABLE = {lodash: "<4.17.21", minimist: "<1.2.6"}` with a hand-rolled numeric `versionLessThan`, over merged `dependencies` + `devDependencies`, stripping `^`/`~`. |
| `dead-code.mjs` | knip / eslint unreachable | Line scanner: on `^(return\b.*;\|throw\b.*;)` it records the indent, then flags every subsequent non-blank, non-comment line at ≥ that indent until it sees `}` or a dedent. |
| `duplication.mjs` | jscpd | Brace-matches `function name(...) {` bodies, normalises (trim each line, drop blanks), and flags any **byte-identical** normalised pair. Shape-alike bodies with different literals do not match. |
| `types.mjs` | tsc / basedpyright / mypy | Two regexes only: `const x: number = "<string literal>"` and `const x: string = <number>`. The file's own header calls this an "HONEST LIMITATION … not a real type checker". |
| `drift.mjs` | (nothing in production) | Pulls `up to **N** times` from the doc and `MAX_RETRIES = N` from the code; returns non-null **only when they disagree**. |

### 2.2 The 13 fixtures and the positive/negative pairing
Six planted defects, seven negative controls, paired class-by-class so a detector cannot score by firing indiscriminately:

| Class | Positive | Negative control(s) |
|---|---|---|
| `secret` | 001 — `awsAccessKeyId = "AKIA_EXAMPLE_NOT_REAL_00000001"` | 002 — `const apiKey = "Enter your API Key"` (UI label); 010 — comment naming `STRIPE_SECRET_KEY` with no value |
| `dependency_cve` | 003 — `lodash 4.17.15`, `minimist 1.2.0` | 004 — `lodash 4.17.21`, `minimist 1.2.8` |
| `dead_code` | 005 — `console.log` + `applyLegacyDiscount(total)` after an unconditional `return total;` | 006 — `applySeasonalDiscount` conditionally called but reachable and exported |
| `duplication` | 007 — `validateUsSignupForm` / `validateEuSignupForm`, identical bodies | 008 — `validateShippingAddress` / `validateBillingAddress`, same if/return skeleton, different predicates and reasons |
| `type_error` | 009 — `const finalPrice: number = "not-a-number"` | 013 — same function, consistent number |
| `drift` | 011 — README says 3 retries, `MAX_RETRIES = 5` (2 files) | 012 — README says 4, code says 4 (2 files) |

The pairing is the design: 002/010 exist to punish a naive "variable named apiKey" secrets regex; 008 exists to punish shape-based duplication; 006 to punish reachability guessing. A detector that flags everything scores recall 1.0 and precision 0.5 and the gate still fails, because the gate requires `false_positives === 0`.

### 2.3 What `run-bench.mjs` computes
Standard confusion-matrix scoring, per class and overall:

- `overall_recall = TP / (TP + FN)`, i.e. planted defects caught ÷ planted defects scored (1 when the denominator is 0)
- `overall_precision = TP / (TP + FP)`
- per class: `recall = caught/planted` (`null` when planted = 0), `precision = caught/(caught+falsePositives)` — both `.toFixed(3)`
- **Gate:** `passed = !noCoverage && overall_recall >= threshold && false_positives === 0`, default threshold `0.7`; `process.exit(passed ? 0 : 1)`.

Two modes, and the header says the difference *is the point*:
- default — bench-local detectors; "a high score proves the HARNESS is wired — never that /audit catches these classes."
- `--real` — routes each entry through `real-scan.mjs` → the production `collect-facts.mjs --only <check>`, materialised into `mkdtempSync` temp dirs so fixture defects never leak into the workspace's own audits. A class whose tool is missing returns `state:"unavailable"`, is excluded from **every denominator**, and is named in the output: *"A missing binary silently reading as 'no findings' is the exact failure the bench was built to detect."* `drift` maps to `null` in `PRODUCTION_CHECK_BY_CLASS` — an honest declaration that `/audit` has no deterministic drift scanner. `noCoverage` (nothing scorable) forces `gate_passed: false` with `gate_failure_reason`.

It also emits a **qualification receipt**: `corpusDigest = sha256(JSON of sorted entry ids)`, metrics, threshold, gate result, `{node, platform, arch, timestamp}`, unavailable/scored classes, then `receiptDigest = sha256(receipt)`.

`real-scan.mjs` additionally synthesises `AU20-S01` at run time (`sk_live_<redacted>`, a PAT-shaped string) rather than committing token-shaped bytes, because gitleaks deliberately ignores the committed `AKIA_EXAMPLE_*` shape — so the committed secret fixture can only measure the bench regex, never production recall.

### 2.4 What `precision-recall.mjs` computes
A general labels-vs-detections scorer, independent of AU20. `calculatePrecisionRecall(labels, detections)` joins on unique `id` (duplicate id throws; a detection with an id absent from labels throws — `detections contain unlabeled ids`), then emits `{precision = TP/(TP+FP), recall = TP/(TP+FN), specificity = TN/(TN+FP), f1 = 2PR/(P+R)}`, each `null` on a zero denominator — never defaulted. `run-provider-selection-benchmark.mjs` feeds it: for each sample it runs `selectProviders(registry, sample.projection)` and asks whether `sample.provider` was selected, i.e. it measures **provider-routing** accuracy against `evals/ground_truth/labeled_samples.json`, exiting 1 on any FP or FN.

### 2.5 What `manifest.json` declares
`{schema_version: 1, bench: "AU20-planted-findings", description, entries[13]}`. Each entry: `id` (`AU20-001`…`AU20-013`), `class`, `planted` (true = must catch, false = must not flag), `file`, `line`, `detector`, optional `doc_file`, plus prose `signal` and `note`. The description states the contract exactly: *"each entry with planted=true is a defect a correct audit MUST catch; each planted=false entry is a negative control that a correct audit MUST NOT flag."*

### 2.6 Does any of it survive?
**No.** Nothing under `bench/` exists in `legion`. What survives is only its *shadow*:

- `skills/audit/references/manual.md:343-347` — "## AU20 — planted-finding recall/precision bench … Not shipped in this repo … deliberately removed. There is no equivalent tooling in this package today."
- `skills/audit/references/provider-architecture.md:114-116` — "(The benchmark harness that once produced these artifacts, `bench/precision-recall.mjs`, was removed from this repo…)"
- `tools/audit/collect-facts.mjs:395` — a comment preserving a real defect the bench caught: "false-clean on the highest-stakes check. Found by the AU20 bench."
- `tools/audit/provider-benchmarks.mjs:1-10` — a **rewritten replacement harness** ("Restores the capability lost with `bench/precision-recall.mjs`"), digest-bound and schema-validated against `references/audit-provider-benchmarks.schema.json`. It is a harness with **no corpus**: no file of `kind: "audit-benchmark-fixtures"` exists anywhere in the repo except the schema itself. It can measure nothing.
- `src/evals/ground_truth/labeled_samples.json` survives with **no code consumer** (its only reader, `run-provider-selection-benchmark.mjs`, is gone).
- **Hard breakage:** `tests/run-audit-conformance-tests.mjs:205` still does `readFileSync(join(AUDIT_ROOT, 'bench/run-bench.mjs'))` and line 236 asserts CI runs it. Verified by running it read-only: 6 cases pass, then `Error: ENOENT … <workspace>\legion\bench\run-bench.mjs` at `test_qualification_receipts`. The suite is unrunnable, and it is not referenced from `package.json` or `.github/workflows/ci.yml`, so nothing notices.

---

## 3. COVERAGE CLAIMS

**What `measured-pack` is supposed to mean.** Its meaning is defined operationally by `src/lib/coverage/index.mjs`, not by prose. When `record.tiers['measured-pack']` is truthy the validator demands (lines 37-44): a `corpusRoot`, a `corpusDigest` that recomputes byte-exactly, an `artifactPath`/`artifactDigest` and a `qualificationPath`/`qualificationDigest` that both hash-match, `corpusDigest !== artifactDigest`, a qualification whose `casesRequired` equals the corpus's declared case ids, an artifact with `status: 'pass'` and a raw log whose digest **and byte length** match, and `record.providerVersions[id] === provider.providerVersion` for every provider. It is also the monotonicity hinge: `runtime > measured-pack` is rejected, so nothing can claim runtime coverage without it. `provider-architecture.md:110-113` gives the intent: "A provider is marked `measured` only when its own rule outputs—not merely provider selection—have reproducible precision and recall artifacts."

**What produced those digests.** `scripts/seal-coverage-evidence.mjs`. For each of the 13 records it: derives `corpusRoot = bench/corpora/<lang>` (or `bench/corpora/frameworks/<name>`); runs a per-record test from a hardcoded `tests` map (`tests/providers/javascript/javascript.test.mjs`, `tests/providers/python/python.test.mjs`, …) via `spawnSync(node --test …)`; writes the raw log to `bench/qualifications/book-3/coverage/<stem>.test.log`; computes `corpusDigest` over every corpus file except `qualification.json`, concatenated as `relpath \0 bytes \0` (requiring ≥4 fixtures — "positive negative unsupported and denominator"); writes the qualification and artifact JSON; and **writes the digests back into `index.json`**. So the digests in `src/registry/coverage/index.json` are genuine outputs of a real run — of inputs that no longer exist in the repo.

**Is the AU20 bench the thing meant to substantiate them? No — something else entirely.** Three independent discriminators:

1. **Shape.** AU20 is one flat corpus partitioned by *defect class* (secret, dead_code, drift…). `bench/corpora/` is partitioned by *language and framework*, one corpus per coverage record, each with its own `qualification.json` declaring `cases[]` — a schema AU20's `manifest.json` does not have.
2. **Grader.** AU20 scores its own six detectors or `collect-facts.mjs`. The seal script scores `tests/providers/<lang>/<lang>.test.mjs` — files that **do not exist** in `legion` (`tests/providers/` is absent entirely; only `coverage-long-tail`, `framework-suite`, `generic-source-suite` from the map are present).
3. **Verdict vocabulary.** The seal script stamps `decision:'source-measured-runtime-unproven'` and `kind:'legion-coverage-qualification'`; AU20 stamps `kind:'audit-qualification-receipt'` with `gate_passed`. Different schemas, different eras.

So `bench/corpora` + `bench/qualifications` is a **later, per-language qualification scheme** that shared only the `bench/` prefix with AU20. Both are gone; they were never the same artifact, and restoring AU20 would not substantiate a single `measured-pack` claim.

**Current status: the claims are unsubstantiated and known to be.** All 13 records carry `"measured-pack": 1`. `validateCoverageRegistry` throws `ENOENT` on the first `corpusDigest(bench/corpora/javascript)`. `tests/coverage/registry-v2.test.mjs:2-6` marks the assertion `{todo:'bench/corpora is absent; measured-pack claims are unsubstantiated'}`, and `docs/pending/plans/2026-09-03-dogfood-findings.md` DF-8 records it: "*The registry asserts measured coverage it cannot substantiate* … Either ship the corpora or drop those records to an unmeasured tier." The same `"measured-pack": 1` values are propagated into `qualification/generated-catalogs.json`.

---

## 4. CAPABILITY DELTA

### BEFORE could, AFTER cannot
1. **Measure `/audit`'s real recall against known-answer defects.** `bench/run-bench.mjs --real` ran production `collect-facts.mjs` over planted defects and produced a pass/fail gate. AFTER has no corpus for `tools/audit/provider-benchmarks.mjs`, so no precision or recall figure can be produced for any provider — and by design it *refuses to invent one*: `throw new Error('precision is undefined: no candidates emitted and none planted; refusing to synthesize a metric')` (`provider-benchmarks.mjs:238,241`). The result is that `audit-plan.mjs:194` computes `precisionMeasured: benchmarkGaps.length === 0` over providers that can never leave `benchmark.status !== 'measured'` (`audit-plan.mjs:58` defaults every provider to `{status:'unproven', requiredForCleanClaim:true}`).
2. **Detect a false-clean from a missing binary.** `real-scan.mjs`'s three-state `scored / unavailable / error` contract, with `unavailable` excluded from every denominator, has no AFTER equivalent. This is not hypothetical value: `collect-facts.mjs:395` documents a real false-clean on the highest-stakes check that this mechanism found.
3. **Measure provider-selection accuracy.** `run-provider-selection-benchmark.mjs` + `precision-recall.mjs` scored routing against labelled samples and exited 1 on any FP/FN. `labeled_samples.json` survives at `src/evals/ground_truth/` with no reader.
4. **Run the conformance suite at all.** `tests/run-audit-conformance-tests.mjs` aborts at case 9 (verified above).
5. **Self-check rendering fixtures.** `_selfcheck/clean.html` and `_selfcheck/perf.html` are gone.
6. **Project Cortex facts into the audit.** `adapters/cortex-projection.mjs` is gone; only its receipt schema remains. Correspondingly the manifest's `discovery_owner` changed from `"cortex"` (BEFORE `manifest.json`) to `"blueprint"` (AFTER).
7. **Assert the provider architecture in a test.** `tests/provider-architecture.test.mjs` is gone; only the prose `provider-architecture.md` remains.

### AFTER can, BEFORE could not
1. **Scale.** `src/registry/providers.json` declares **78** providers versus BEFORE's ~31 `legacy` + 1 runtime + 2 reasoning entries in a single-line `providers.json` — plus whole new families under `src/providers/`: `codeql`, `opengrep`, `osv`, `sbom`, `privacy`, `provenance`, `ai-quality`, `licenses`, `i18n`, `compliance`, `container-iac`, `monorepo`, `governance`, `requirements`, `remediation`.
2. **A typed coverage registry.** BEFORE expressed coverage as `coverageFamilies[]` with a flat `qualification: "partial"|"unproven"` string. AFTER has a 7-tier ordinal model with enforced monotonicity and digest-bound evidence (`src/lib/coverage/index.mjs`) plus `accountCoverage`, which maps any undetected format to `{id:'unknown.<x>', cleanClaim:'never'}` — a genuinely stronger honesty guarantee than BEFORE had.
3. **Digest-bound, schema-validated benchmark records.** `provider-benchmarks.mjs` binds results to implementation and rule-pack file digests and reclassifies stale bindings as `unproven` — strictly better machinery than `precision-recall.mjs`, and strictly emptier.
4. **A security *chain* pipeline** (`tools/audit/security-chain-pipeline.mjs`) alongside the ported `security-pipeline.mjs`.
5. **Ship as a product**: `skills/audit/RIGHTS.json`, `dependencies.json`, `agents/openai.yaml`, packaged `dist/native/…` payloads, and a standalone `.github/workflows/ci.yml`.

The net: the AFTER engine is several times larger and better-specified, and simultaneously has **less measured evidence about itself than the BEFORE skill did** — it has more scaffolding for proof and no proof.

---

## 5. LOST AND WORTH RESTORING

| # | Item | Evidence path | Why it matters | Restore cost |
|---|---|---|---|---|
| 1 | **AU20 planted-defect corpus** (13 fixtures + `manifest.json`) | `52a90cf0^:tools/skills/audit/bench/fixtures/*`, `bench/manifest.json` | The only known-answer ground truth the product ever had. Everything else on this list is a consumer of it. Restoring the *data* is pure `git show` — no design work, no dependencies. | **Small** |
| 2 | **`real-scan.mjs` production bridge** | `52a90cf0^:…/bench/real-scan.mjs` | The `scored/unavailable/error` contract is the only mechanism that ever caught a false-clean (`tools/audit/collect-facts.mjs:395`). Needs `COLLECT_FACTS` repointed to `tools/audit/collect-facts.mjs`. | **Small** |
| 3 | **`run-bench.mjs` + 6 detectors** | `52a90cf0^:…/bench/run-bench.mjs`, `bench/detectors/*.mjs` | Restores an executable gate (`recall ≥ threshold && FP === 0`) and the qualification receipt. Path-only edits. | **Small** |
| 4 | **Repair `tests/run-audit-conformance-tests.mjs`** | `tests/run-audit-conformance-tests.mjs:205,236` | The suite is dead at case 9 today and nothing runs it. Items 1-3 fix it as a side effect; otherwise the assertion must be dropped. Either way it should be wired into `.github/workflows/ci.yml`. | **Small** |
| 5 | **Resolve the `measured-pack` claim** | `src/registry/coverage/index.json`; `tests/coverage/registry-v2.test.mjs:2`; DF-8 | 13 records assert measured coverage the validator throws on. Truthful cheap fix: drop the tier to 0 and re-run `seal-coverage-evidence.mjs`. Honest expensive fix: author `bench/corpora/<lang>` (≥4 fixtures each) **and** the 9 missing `tests/providers/<lang>/*.test.mjs`. | **Small** (downgrade) / **Large** (substantiate) |
| 6 | **A fixture corpus for `provider-benchmarks.mjs`** | `tools/audit/provider-benchmarks.mjs`; `references/audit-provider-benchmarks.schema.json` | The successor harness is complete and unusable. One `audit-benchmark-fixtures` document per rule pack unblocks `precisionMeasured` and every clean claim gated on it. AU20's fixtures are a starting seed, not a drop-in. | **Medium** |
| 7 | **Provider-selection benchmark** | `52a90cf0^:…/bench/{run-provider-selection-benchmark,precision-recall}.mjs`; `src/evals/ground_truth/labeled_samples.json` | Its labels already ship, unread. Restoring re-couples them; the registry API (`selectProviders`) still exists at `src/registry/provider-registry.mjs`. Sample `projection` fields may need reshaping for the 78-provider registry. | **Medium** |
| 8 | **`tests/provider-architecture.test.mjs`** | `52a90cf0^:…/tests/provider-architecture.test.mjs` | `provider-architecture.md` is now prose with no test enforcing it. Likely needs rewriting against the expanded registry rather than lifting. | **Medium** |
| 9 | **`adapters/cortex-projection.mjs`** | `52a90cf0^:…/adapters/cortex-projection.mjs`; `src/schemas/core/cortex-projection-receipt-v1.schema.json` | Probably a **deliberate** retirement — discovery ownership moved `cortex` → `blueprint` between `manifest.json` v2 and v3. Restore only if the orphan receipt schema is meant to be live. | **Medium** (verify intent first) |
| 10 | **`_selfcheck/*.html`, `UPGRADE-PLAN.md`** | `52a90cf0^:…/_selfcheck/`, `UPGRADE-PLAN.md` | Low value. The HTML fixtures are superseded by `/audit-visual`; the upgrade plan is a historical document. | **Small** (low priority) |

**Smallest high-value move:** `git checkout 52a90cf0^ -- tools/skills/audit/bench` into `legion/bench/`, repoint `real-scan.mjs`'s `COLLECT_FACTS` to `tools/audit/collect-facts.mjs`, and run `node tests/run-audit-conformance-tests.mjs` — that single check goes from ENOENT to a full pass and restores an executable recall gate.

*Read-only: nothing was modified, created, committed, or pushed. The one command executed against the working tree was `node tests/run-audit-conformance-tests.mjs`, which only reads.*
