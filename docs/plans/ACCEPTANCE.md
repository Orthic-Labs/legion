# Acceptance & verification

This matrix defines what implementation must prove. It does not assert any case has run. Root integration owns execution; workers author code & fixtures only.

## Four separate claims

| Claim | Required evidence |
|---|---|
| Implemented | Integrated source, compatible public surfaces, source assurance & passing relevant Rust checks. |
| Fixture-qualified | Exact rule/provider/tool/config revision; broken + valid cases; raw outcomes, false-positive/false-negative counts & excluded cases. |
| Host-qualified | Actual trusted owner invocation, containment, termination, receipt validation & exact host/toolchain capability. |
| App-qualified | Exact repository set, target/variant/deployed artifacts, required production journeys & current receipts satisfy selected profile. |

A rule may be implemented but shadow-only. A complete audit may contain blocking findings. A fixture-qualified provider may leave release incomplete. Report all four distinctly.

## Cross-stack acceptance

| Surface | Required source/semantic cases | Required build/runtime evidence |
|---|---|---|
| Node ecommerce | BOLA/tenant isolation, transaction boundaries, money units/rounding, idempotency/replay, duplicate payment/webhook delivery, oversell concurrency, secret/PII handling, blocking/event-loop risks | Authenticated real Node type/build/test receipts; checkout/payment/refund/stock races with isolated data; measured workload latency/error rate/resource use |
| React admin | Authorization enforced beyond UI, untrusted HTML, hooks/effect cleanup, stale closures, permission transitions, accessible interactions, responsibility-based component decomposition | Native lint plus authenticated app type/build/test & browser journeys; bundle/render measurements |
| Qwik storefront | Server/client trust boundary, secret serialization, QRL captures/serialization, resumability, server functions/loaders/actions, cache/tenant interaction, progressive enhancement | Version-bound framework fixtures; authenticated Qwik build & navigation/checkout/resume behavior, bundle/network/a11y measurements |
| PostgreSQL | Existing Squawk coverage plus dangerous DDL, transactional migration assumptions, RLS/tenant boundaries, indexes & query shape, lock/backfill/data loss scenarios | Exact server/schema/data-volume/config; isolated migration & compatibility tests, safe query plans/benchmarks, recovery evidence when required; never auto-use production URL |
| Nginx | Includes/inheritance, location/alias/proxy interactions, forwarded-header trust, cache keys, auth/cookie/cache interaction, TLS/body/rate/time limits | Effective sanitized deployed config bound to modules/version, native config validation & isolated request behavior |
| Rust core/GUI | Existing compiler/Clippy/advisory coverage plus unsafe/FFI boundaries, ownership/error handling, async cancellation/locks, feature/target combinations, UI-thread blocking | Actual supported feature/target matrix, representative GUI workflows, startup/memory/crash & responsiveness evidence |
| Tauri + React | Capability/ACL scope, command argument/path validation, IPC origin/input trust, CSP/navigation, sidecar/resource scope, updater verification, shutdown/cancellation | Authenticated packaged artifact + capabilities; UI→IPC→Rust denied/allowed cases; update/install behavior tested without publishing |
| Swift macOS/iOS | Actor isolation, Sendable/concurrency, lifecycle/cancellation, Keychain/privacy/entitlements, permission flows, persistence/backup, offline & background behavior | Exact Xcode workspace/scheme/config/destination; iOS cannot borrow macOS SwiftPM qualification; simulator/device & packaged-artifact evidence per declared target |
| Kotlin/Android | Source detekt without JVM contract; typed detekt separate; coroutine/lifecycle/dispatcher misuse, intent/exported components, storage/permissions, background work | Variant-aware compilation/tests + Android Lint; SDK/API/manifest/target evidence; permission denial/regrant, process death/restore, background transitions on required device matrix |
| Every stack | Dependency advisories/freshness/EOL/licenses, dead-code candidates, duplication, YAGNI, coupling/cohesion, tests/contracts, secrets, error handling & observability | Missing runtime/graph/metadata cannot become clean; third-party & generated scope explicit; packaged dependency inventory where applicable |

Minimum first end-to-end slices: ecommerce checkout across Node/React/Qwik/PostgreSQL/Nginx; Tauri UI→IPC→Rust; Android coroutine/lifecycle→Lint→variant. Swift/iOS & Rust GUI target cases remain required portfolio cases, not inherited qualifications.

## Required negative cases

All listed deterministic cases must pass. “Pass” means expected rejection/gap/finding occurs; not that scanned fixture is clean.

| ID | Mutation / trigger | Expected behavior |
|---|---|---|
| N01 | Required scanner absent, crash, malformed output or zero examined inputs despite nonempty expected scope | Incomplete obligation, retained diagnostics |
| N02 | Tool resolves, but owner admission absent; version probe attempts launch first | No probe/target spawn; named admission gap |
| N03 | Grant replay, stale policy, changed argv/cwd/env/output roots, executable substitution | Rejection before execution |
| N04 | Child survives timeout/cancel, output cap hit, resource enforcement unavailable | Failed/incomplete execution receipt; no clean claim |
| N05 | Config loads JS/TS/Python plugin, build hook launches interpreter indirectly, helper executable renamed | Denied by enforced runtime closure or declared unsupported confinement; PATH filtering alone insufficient |
| N06 | Signed artifact has wrong issuer/repo/revision/target/variant/toolchain/config/dependency/workload | Cannot satisfy matching obligation |
| N07 | Self-attested empty SARIF, partial test selection, valid signature over inadequate scope | Candidate/import record retained with unmet scope |
| N08 | Archive traversal/symlink/decompression bomb; secret-bearing artifact | Bounded safe handling; no filesystem escape or secret export |
| N09 | Fixture-qualified macOS result reused for iOS/Android/release target | Qualification mismatch |
| N10 | Missing dependency format/transitive resolution, stale advisory database or offline latest-version miss | Precise coverage/freshness gap |
| N11 | Same code changes caller/domain unit/config/target/dependency/rule revision | Invalidate affected reuse |
| N12 | Symbol renamed/deleted; scanner removed; narrow diff omits earlier finding | Prior finding persists until valid resolution evidence |
| N13 | Corrupt finding cache/history or incomplete run offered as baseline | Reject/rebuild derived cache; no history promotion |
| N14 | CRLF, Unicode, duplicate snippets, rename, deletion, outside-diff anchor | Exact source binding or explicit unpositioned result; findings remain reportable/gating |
| N15 | No Blueprint edge, oversized source, unknown consumer | Missing semantic context retained; no fabricated call graph/deletion proof |
| N16 | Budget exhausted, parallel race, timeout/retry/continuation, verifier unavailable | Preserve candidates, scope gaps & charged usage; no duplicate spend or automatic clean |
| N17 | Large cohesive component vs small responsibility-tangled component | Contextual recommendation; no universal line threshold or cosmetic split |
| N18 | Different benchmark hardware/data/traffic mix, excluded slow routes | Incomparable trend, not performance improvement |
| N19 | Repository drops obligation, edits waiver or claims itself trusted | Frozen minimum/profile & host authority prevail |
| N20 | Old v1/v2 report lacks assurance extension; malformed/future extension | Legacy remains readable; cannot silently gain modern release eligibility |
| N21 | Full intended audit emits zero findings with valid examined scope | Valid zero-finding result permitted; no quota or forced criticism |
| N22 | Legitimate authority dismisses finding without repair | Dismissed/accepted risk, never verified-fixed |

## Root verification batch

Before running any command, apply build admission from INTEGRATION. Commands below are payloads for approved local RustRight/managed CI execution, not permission to bypass it. Run after all coding & generators settle; no worker executes them.

1. Compile/check relevant Rust crates & execute affected unit/integration suites. Include `legion-audit`, `legion-effects`, `legion-contracts`, `legion-provider-sdk`, `legion-report`, `legion` & `legion-dev`; this change crosses their boundaries. Respect existing host-gated tests. Native interpreter boundary target lives in `legion-workspace-tests`.
2. Required new integration targets: `native_owner_admission`, `production_obligations`, `authenticated_artifacts`, `kotlin_detekt_accuracy`, `android_lint_accuracy`, `xcode_target_accuracy`, `javascript_native_accuracy`, `dependency_health`, `structure_quality`, `postgres_assurance`, `nginx_assurance`, `domain_contracts`, `platform_pattern_cards`, `source_anchor_projection`, `finding_history`, `runtime_obligations`, `review_budget_completeness`, `assurance_qualification`.
3. Preserve relevant existing regressions: native provider boundary, native legacy external tools, native audit/reasoning, report review payloads, v1/v2 projection, completed history, process-tree cancellation & budget continuation. Run native interpreter tests under environment without Node/Python availability, plus indirect-child runtime-constraint cases.
4. Run native generator drift checks, `check-skill-references`, `check-skill-evals`, `check-native-cli-surface --phase enforce` & new `check-audit-assurance`. Use existing managed CI registration for qualification; never author successful enrollment records manually.
5. Run actual scanner/SDK fixtures only through qualified A01 owner or authenticated A03 upstream path. Root captures raw outputs, exact versions, input/config digests, scope & receipts. Unsupported host tests remain visibly unexecuted.
6. Use current audit benchmark runner for held-out semantic cases. Report counts per lens/stack, precision/recall where defined, clean-case false positives, unresolved cases & cost. No minimum finding count, unanimous-vote severity or borrowed benchmark percentages.
7. Independent source assurance reads integrated diff & results; no test reruns. Final documentation lists observed support/qualification & remaining target obligations.

Representative Cargo payloads after admission (one coordinated batch; choose exact test selection from final diff):

```sh
cargo fmt --manifest-path engine/Cargo.toml --all -- --check
cargo test --locked --manifest-path engine/Cargo.toml -p legion-audit -p legion-effects -p legion-contracts -p legion-provider-sdk -p legion-report -p legion -p legion-dev --all-targets
cargo test --locked --manifest-path engine/Cargo.toml -p legion-workspace-tests --test native_no_interpreter --test native_python_surfaces
```

No measured runtime, accuracy or app coverage claim may come from authored fixture existence alone. Acceptance closes with actual evidence attached to exact scope.

