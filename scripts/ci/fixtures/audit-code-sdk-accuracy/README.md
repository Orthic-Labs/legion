# Constructed code SDK known-answer controls

Source-only implementation candidate under #56. No native execution or qualification is claimed by these files.

`real_code_command_accuracy` uses frozen shipped `code.go` selection & self-sourcing production adapter, actual `AuditExternalProjectTool`/`EffectExecutor`, native macOS deny-network sandbox & exact constructed authorizer. Production `OwnerAdmissionRequired` stays unchanged. Fixtures contain no external module dependencies. Existing CI pinned Go1.26.7 archive/root supplies genuine Go/gofmt binaries; no fake tools, analyzer payloads or copied effect receipts.

Run selector: `--test real_code_command_accuracy real_code_command_accuracy -- --ignored --exact --nocapture --test-threads=1`. Explicit `LEGION_CODE_COMMAND_SCRATCH` & `LEGION_PROVIDER_BENCHMARK_DIR` must be separate external roots. Existing `LEGION_GO_ROOT` & `LEGION_GO_ARCHIVE` must remain provisioned. Child isolates HOME & PATH. Output includes original child streams & child-execution descriptor.

Seven controls exercise fixed Go module/format/vet/test scope:

- `positive`: unformatted `answer.go`, real gofmt path diagnostic & native `gofmt` finding, real passing Go test.
- `nonempty-clean`: formatted sources & test, all four actual commands exit0, no native findings.
- `test-failure`: genuine test body fails, original nonzero test process receipt remains failure/gap.
- `malformed`: invalid Go version declaration creates genuine process failure, never clean evidence.
- `missing-tool`: empty resolver directory, typed missing-tool gaps & no fabricated SDK runs.
- `rejected-admission`: genuine `OwnerAdmissionRequired` decisions, no launched processes.
- `absent-sandbox`: separate SDK boundary control requires network sandbox but supplies none; exact constructed admission permits request, genuine executor refuses before version/main launch. It is not provider execution evidence.

Exact command scope: `go list -m`, `go vet ./...`, `gofmt -l .`, `go test -count=1 ./...`. Go uses `version`; gofmt version probe uses same authenticated wrapper with pinned adjacent `go version <exact-gofmt>`; policy binds inspector, target, wrapper, profile, argv, cwd, environment, limits & accepted exits. No version skip.

Wire schema `legion-code-command-sdk-accuracy/1`, kind `code-command-sdk-constructed`, original line marker `CODE_COMMAND_SDK_ACCURACY `. Exactly ten provider files `code_<family>.json` correspond to source-owned `code::evidence::config_for` population. Top-level `requiredContract` retains actual tools/extensions/variants/requiredContext. `binding` retains provider spec sans benchmark, source closure & fixture-source digests. `toolchain` binds pinned archive digest, root & actual binary digests. `toolchain.tree` points to retained `toolchain-tree.json`, which records every regular file in full extracted compiler/linker/stdlib tree; symlinks or special files are rejected & complete tree is rechecked after controls. Go has `status: observed-controls-incomplete-provider`; remaining nine have `status: unavailable`, no cases & explicit entire-contract missing controls.

Every record has `qualificationEligible:false`, `productionQualification:false`, `claimScope:known-answer-fixture-cases`. Go vulnerability & whole language/platform/runtime contract are explicit missing controls. Subset success cannot register or qualify any provider. Full Go vulnerability controls require separately integrated #84 producer/provisioning & a new reviewed candidate.

Cases retain `fixtureFiles`, `fixtureSources`, original `inventory`, `planDigest`, `frozenProvider`, actual `nativeResult`, `policyDefinition`, `policyDecisions`, `sdkExecutions`, literal `expected` & observed `matched`. Each SDK execution retains complete original `request`, faithful full `executionReceipt` field projection & `stdout`/`stderr` descriptors plus exact raw byte arrays. Stream paths stay in original retained `cases/<case-id>/artifacts/` root; digest/length/immutable fields are checked. `sdk-execution-N.json` saves original receipt before stream verification or provider assertions can fail. `case-observation.json` persists observed result before assertions; final matched flag is written only after controls succeed. No effect receipt is regenerated, re-signed, transformed into success or assigned provider eligibility.

Validator must reject registration of every current record, validate original child/source/policy/receipt/artifact linkage & preserve incomplete diagnostics. File-only benchmarks remain separate & ineligible.

`nonempty-clean.requestMutationControls` contains four additional SDK boundary controls. Each clones genuine captured module request, establishes a fresh valid request-ID baseline, then changes exactly one of argv, cwd, executable or frozen-plan binding. Same exact policy definition/digest authorizes through genuine executor; original no-process refusal receipt & stream references remain retained under `cases/code-go-nonempty-clean/mutations/<field>/`. These controls confer no provider qualification.
