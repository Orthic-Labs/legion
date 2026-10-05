# Legion full entrypoint inventory & fix plan — 2026-10-05

## Scope & evidence

Follow-up acceptance found `8c23e45b` advertised plugin-root transport broken on both hosts:
`serve --stdio --plugin-root current/plugin` exits 2 before JSON-RPC because validator requires
`.mcp.json` byte equality with `mcp.json`. Prior five-request receipts exercised bare stdio only.
Assembler intentionally removes `${PLUGIN_ROOT}` arguments for Claude; validator now accepts
only that exact argument projection while preserving every other field. Antigravity alias retains
exact-byte validation. Qualification now probes both bare & plugin-root transports, all three
canonical tools & Apple catalog/apps/simulator dry plans.

Transport repair revision: `d54bea8cf41ecbacee7cfd2a626f3719e0ed3c54`.
Full CI [37322449386](https://github.com/Orthic-Labs/legion/actions/runs/37322449386)
passed: **7,336 tests, zero failures, two ignored, 289 suites**. Apple qualification
[37322449254](https://github.com/Orthic-Labs/legion/actions/runs/37322449254) & macOS
development qualification [37322522026](https://github.com/Orthic-Labs/legion/actions/runs/37322522026)
passed. Windows development qualification
[37322522844](https://github.com/Orthic-Labs/legion/actions/runs/37322522844) passed.

Mac stable runtime SHA256 is
`640e030102636ae58997dc5c0c4358bf315e088b7edc497bc9e183a0f48a02ae`; asset generation remains
`51cf3b32952c706a4c079d82fa9ac337b6d67ae49e9eeb6bfcabc231c816131f`.
All 1,036 skill files match payload, Claude & Codex projections. Both client readbacks report
COMPLETE, installed origin & stable current. Both real transports return five successful replies,
three canonical tools & Apple catalog/apps/simulator plans. Six installed hook decisions pass;
native Minimize binds installed Rust executable & packaged policy, then rejects staged-tree drift.
Mac is ready for iOS work. Normal installer activated this runtime but exited 1 during aggregate
setup repair because optional Pi/Baseline configuration remains defective; scoped Claude & Codex
repairs each exited 0. Aggregate all-client installation is not certified.

Windows stable runtime SHA256 is
`fa827809030976d482a20f4c05b9d690b7be014a57feb2fa8d3261f76e5a5e05`; asset generation matches Mac.
Qualified artifact ZIP SHA256 is
`a0d104ecc68300489c4ae7653280df2dce0dc67d4713cfeee7cb22099b27b960`;
installer SHA256 is `e4f9b66d46929ce30048e5e444e8c2c0cc60a756702421f4302089790db0ce8e`.
First same-version installation exited 0 but actual plugin-root startup rejected obsolete
`skills/alchemist/scripts` directory. Official uninstall exited 0, then exact qualified installer
reinstall exited 0 with documented 180-second child budget. Stable setup reads COMPLETE,
installed origin & stable current. All 1,036 skill files match payload, Claude & Codex; both MCP
paths return five successful replies with canonical tool set & Apple dry plans. Six hook cases &
native Minimize receipt/staged-tree-drift checks pass. Existing Windows checkout & parent staged
work remain untouched. Same-version upgrade cleanup remains a source defect listed below.

Portable readback evidence: [legion-installed-readback-d54bea8c.json](legion-installed-readback-d54bea8c.json).
Mac artifact ZIP SHA256: `3562eaabfe20682b09dd4e42bd775e0391fa098cf1dbcf1f926f7994fc8f0971`;
installer archive SHA256: `c182b241ffd2f49c3e5887ef4e2aed4282cb1429b735f274e903aa007640d955`.
Both requested Claude/Codex installations now share exact production source `d54bea8c` & asset
generation; iOS acceptance chat was informed Mac is ready before Windows delivery.

This is source-bound inventory for Legion's primary checkout. Reports read:

- `/tmp/legion-full-audit-cli-runtime.md`
- `/tmp/legion-full-audit-mcp-scripts.md`
- `/tmp/legion-full-audit-dev-release.md`
- `/tmp/legion-full-audit-skills-assets.md`

Primary source inventory revision: `251de32200cb14882dbed794139393c2a869dadd`.
Earlier production repair revision: `8c23e45b49e41cc2eec3b8f5e776564d077647f0`.
Full CI run [37307458066](https://github.com/Orthic-Labs/legion/actions/runs/37307458066)
passed: **7,333 tests, zero failures, one ignored, 288 suites**. Apple qualification & macOS
native/installer qualification passed. Windows installer qualification & stable installation passed.

Earlier Mac installation matched qualified runtime SHA256
`bb9d303e131879eec60a308e97aeb4410e6a1f13b56d79587c9e9f4c3fe23893` & asset generation
`51cf3b32952c706a4c079d82fa9ac337b6d67ae49e9eeb6bfcabc231c816131f`.
Claude & Codex setup repair/readback are COMPLETE, installed-origin & stable-current.
All 29 bundles / 1,036 manifest-listed files match payload, Claude & Codex projections.
Installed hook admits Windows-MCP Snapshot/Click & docs query without overriding host
permissions; classified write/send/delete remain denied. Native Minimize init-review → receipt →
verify passed in isolated Git fixture, bound installed Rust executable & shipped policy, & rejected
staged-tree drift. Those five MCP responses covered bare stdio only; current acceptance above
supersedes that incomplete transport claim.

Local compilation/check/test admission was unavailable, so builds & tests ran on GitHub CI.
Exact qualified installers are used for explicitly requested stable installation. Status labels:

| Label | Meaning |
|---|---|
| `R` | source reviewed |
| `T` | direct focused test exists |
| `CI` | recorded CI stage exists; does not prove every route |
| `I` | no successful end-to-end fixture found |
| `A` | auth, network, browser, OS, tool, or dependency required |
| `U` | unmapped, stale, or disputed; resolve before closure |
| `P` | proposed fix/acceptance; not evidence of completion |

## Count reconciliation

| Surface | Source count | Evidence | Current disposition |
|---|---:|---|---|
| Root `legion` top-level commands | 43 | `engine/bins/legion/src/cli.rs` `Command` enum | all enumerated below; many `I` |
| `legion script` keys | 77 | `engine/bins/legion/src/commands/script.rs:56-134` | all enumerated below; dispatcher direct coverage is partial |
| `legion-dev` subcommands | 27 | `engine/bins/legion-dev/src/main.rs` `Command` enum | all enumerated below |
| `xtask` subcommands | 16 | `engine/xtask/src/main.rs` `Commands` enum | all enumerated below |
| `package.json` scripts | 37 checked in | key enumeration | source report's 36 count corrected; all 37 listed |
| Canonical MCP tools | 3 | `src/registry/mcp-tools.json` | `legion_m1_status`, `legion_m1_invoke`, `legion_apple` |
| Standalone MCP binary | 1 | `engine/bins/legion-mcp/src/main.rs` | shipped requirement; current gate rejects initialization |
| Tracked skill script/data files | 10 | `git ls-files skills` filtered `/scripts/` | eight metadata/HTML fixtures plus shell wrapper & browser UI module; no legacy Python source |
| Public skill bundles | 29 | `skills/*/SKILL.md`, manifests, registries, host projection | sets match; canon's 30 atomic capabilities are a different denominator |

## Priority order

1. **Claude/native installed path first.** Qualify `d54bea8c` through GitHub: Claude hook/MCP
   permissions, native Minimize policy/validator assets, exact macOS same-version reinstall,
   then exact installed readback. Do not call source/unit coverage release completion.
2. **Canonical MCP/runtime parity.** Choose one registry and adapter, repair or remove inert
   standalone `legion-mcp`, then prove list/call parity.
3. **Native CLI truthfulness & high-risk core defects.** Fix schedule, audit claims, doctor root,
   authority evidence, receipt persistence, policy/JSON flags, root help, hooks, handoff, and
   visual route behavior.
4. **Native script parity & coverage.** Cover all 77 dispatch keys with safe fixtures, isolate
   real I/O, and replace dead public docs paths.
5. **Release/process hardening.** Bound subprocesses, align Windows timeout contracts, enforce
   CLI surface checks, gate macOS local builds, harden Swift installer rollback/version paths,
   derive workflow version, broaden change detection, and add host guards.

## Complete root `legion` inventory (43)

All rows are live top-level routes from `engine/bins/legion/src/cli.rs`. `native_*` helpers not
reached by dispatch are excluded from this route count.

| Command | Source route | Evidence |
|---|---|---|
| `apple` | `commands::apple::AppleArgs` | `T` Apple CLI/MCP lanes; operation matrix incomplete |
| `status` | `native_m1_status` | `T` M1 vertical slice; installed positive recorded at `8c23e45b` |
| `serve` | `native_m1_serve` | `T` M1/M2; malformed-release matrix `I` |
| `init` | `commands/init.rs` | `T` characterization/migration |
| `doctor` | `commands/doctor.rs` | `T`; external-root naming defect |
| `bind` | `commands/bind.rs` | `T` check/migration; installed asset parity `I` |
| `inspect` | `commands/topology.rs` | `T` empty repo; installed positive `I` |
| `targets` | `commands/topology.rs` | `T` empty repo; installed positive `I` |
| `components` | `commands/topology.rs` | `T` empty repo; installed positive `I` |
| `stacks` | `commands/topology.rs` | `T` empty repo; installed positive `I` |
| `controls` | `commands/topology.rs` | `T` empty repo; installed positive `I` |
| `governance` | `commands/governance.rs` | `T` truthfulness/characterization |
| `skills` | `commands/skills.rs` | `T` characterization; installed positive `I` |
| `languages` | `commands/languages.rs` | `T` characterization/projection |
| `providers` | `commands/providers.rs` | `T` characterization/projection |
| `rules` | `commands/rules.rs` | `T` `rules_cli`; installed assets `I` |
| `schedule` | `commands/schedule.rs` | `I`; trigger writes `STARTED` without dispatch |
| `plan` | `commands/plan.rs` | `T` fail-closed; authenticated positive `I/A` |
| `audit` | `commands/audit.rs` | `T` artifacts/rules; visual behavior defective; quality-gate semantics need reconciliation |
| `verify` | `commands/verify.rs` | `T` migration; full positive `I` |
| `explain` | `commands/explain.rs` | `T` missing/unknown ID; positive `I` |
| `report` | `commands/report.rs` | `T` product parity; format/output matrix `I` |
| `fix` | `commands/fix.rs` | `T` missing plan; action is silent no-op |
| `hooks` | `commands/hooks.rs` | `T` stub truthfulness only; install/uninstall `I` |
| `mcp` | `commands/mcp_config.rs` | `T` config/preview; client install `I/A` |
| `run` | `commands/run.rs` | usage/auth only; lifecycle success `I` |
| `budget` | `commands/budget.rs` | usage/key absence only; positive `I/A` |
| `contract` | `commands/contract.rs` | missing-input only; seal success `I` |
| `assurance` | `commands/assurance.rs` | intentionally unknown-command characterization |
| `completion` | `commands/completion.rs` | missing-auth only; receipt persistence defect |
| `host` | `commands/host_runtime.rs` | empty inspect only; valid ledger `I` |
| `harness` | `commands/harness.rs` | characterization rows; positive host matrix `I/A` |
| `authority` | `commands/authority.rs` | empty/usage only; corrupt evidence falsely succeeds |
| `state` | `commands/state.rs` | `T` cutover/migration |
| `minimize` | `commands/minimize.rs` | `T` native CLI receipt, tamper & staged-tree tests; macOS/Windows installed qualification & readback passed at `8c23e45b` |
| `catalog` | `commands/catalog.rs` | no focused CLI fixture; M1 catalog only |
| `policy` | `commands/policy.rs` | file validation only; `--effect` and JSON mode inert |
| `decision` | `commands/decision.rs` | route exists; positive decision lifecycle `I` |
| `handoff` | `commands/handoff.rs` | help only; missing input exits success |
| `research` | `commands/research.rs` | native route source reviewed; domain classification `U` |
| `review` | `commands/review.rs` | help only; authorized provider `I/A` |
| `setup` | `commands/setup.rs` | install/projection source reviewed; Claude/Codex installed readback passed on macOS & Windows at `8c23e45b` |
| `script` | `commands/script.rs` | 77 keys; 18 direct invocation paths, remainder `I` |

### Root CLI fixes & acceptance

| Priority | Finding | Exact source-bound fix | Acceptance |
|---|---|---|---|
| P1 | `schedule --trigger` persists `STARTED`, never consumes `runArgs` or starts workflow (`commands/schedule.rs:78-96`). | validate target; persist signed pending receipt; dispatch once; atomically write success/failure; reject terminal replay. | executable fixture runs exactly once; duplicate key returns terminal dedupe; launch failure has non-null failure. |
| U | `audit` derives `qualityGate=proven` from clean provider report & emits `completionValidation=not-run` (`audit.rs:221-237,308-312`). | reconcile quality-gate predicate with manual: gates are separate & Oracle is conditional. Do not invent mandatory validation from `not-run` alone. | verify each configured/required gate independently; missing required evidence stays unproven; optional validation remains optional. |
| P1 | `doctor <root>` naming ignores root and reads package checkout (`doctor.rs:247-253,290-298`). | pass requested root for repository findings; keep release rules separate. | two temp repos produce distinct naming findings; binary outside checkout uses target root. |
| P1 | `authority proof inspect` skips unreadable/invalid entries and exits 0 (`authority.rs:43-82`). | typed error collection; nonzero/incomplete if any candidate is bad. | valid + malformed proof reports path/error; empty directory remains valid empty. |
| P1 | Completion receipt append errors are discarded; `ReceiptStore::append` unwraps and drops write/head errors. | fallible append; propagate error; verify chain/head before success. | unwritable store cannot emit success; successful evidence appears in list and chain check. |
| P2 | Hooks returns success with `implemented:false`, performs no write. | implement owned install/uninstall or typed unavailable/incomplete. | install is idempotent; uninstall removes only owned hook; conflict visible. |
| P2 | Handoff absent `--input` exits success with `valid:false`. | missing input is usage 4; invalid supplied packet remains usage 4. | missing, malformed, valid cases return 4, 4, 0. |
| P2 | Policy `--effect` only echoes; `catalog/policy --json` does not select rendering. | evaluate effect or remove/document unsupported flags; branch JSON/text. | allowed/denied effect decisions and distinct output modes. |
| P2 | Root help omits live public commands including `status`, `serve`, `catalog`, `policy`, `assurance`, `decision`, `handoff`, `research`, `review`, `setup`, `script`. | generate help from Clap/public surface or update contract. | every live non-excluded route appears exactly once. |
| P2 | `fix` always returns `mutationApplied:false` with no action consumer. | rename as validate or implement guarded remediation + receipt. | no-op is explicit; actionable plan applies or typed unavailable. |
| P2 | Duplicate `native_*` helpers in `cli.rs` are not dispatch routes (`native_report`, `native_host`, `native_run`, `native_completion`, `native_state`, `native_schedule`). | delete stale helpers or add route/coverage; no dead claimed surface. | inventory test maps each helper to dispatch or marks retired. |
| P2 | Topology/rules/providers/bind embed checkout assets; no installed positive fixture. | bind release assets by versioned composition. | installed candidate reads packaged assets, not checkout fallback. |

## Visual route dispute & required native fix

The sibling report’s literal “missing `visual.core` alias” claim is not supported by current
source: `src/registry/provider-aliases.json:40` contains `visual.core -> legacy.visual.core`.
The actual unresolved mapping is stronger: `src/registry/providers-runtime.json:322` also declares
native `visual.core`, while `src/registry/providers.json:5392` declares `legacy.visual.core` and
native execution tests still enumerate the legacy ID. Resolve one canonical mapping; do not claim
visual parity from alias text alone.

Confirmed source behavior remains defective: `audit.rs:15-32,462-466` accepts `--url`,
`--surfaces`, `--visual-spec`, `--visual-baselines`, `--width`, and `--height` but documents them
as accepted-and-inert; audit output writes `plan.json`, `report.json`, `report.sarif`, `facts.json`,
and `execution.json`, with no named `visual.json` artifact. `AUDIT_PLAN_SIGNING_KEY` is required
for native plan/signing paths, supplied only by focused fixtures in this checkout; no installed
qualification evidence proves host key injection. Fix order: map `visual.core` to one native
provider, wire args into provider selection/capture, emit a signed visual artifact, and fail
closed when key or visual evidence is absent.

Acceptance: alias/registry/runtime IDs are one set; visual args alter frozen plan and execution;
`visual.json` contains source revision, provider ID, digest, captures, denominator, and gaps;
missing key is typed incomplete; no visual-clean claim appears without required capture/qualification evidence.

## MCP inventory: canonical 3 + standalone binary

| Tool / binary | Advertised contract | Runtime | Evidence |
|---|---|---|---|
| `legion_m1_status` | closed object, no args | `M1McpApi::invoke`; status normalization | `T` M1 vertical slice/server/tools |
| `legion_m1_invoke` | required `capabilityId:string`, `policyContext:any`; closed object | `M1Application::invoke` | `T` policy/capability receipt path |
| `legion_apple` | required `operation:string`; optional `arguments`, `policyContext` objects | `apple_mcp.rs` | partial `T`; full operation matrix `I/A` |
| standalone `legion-mcp` | separate stdio binary | `main.rs` builds app then uses `RejectingBindingGate` | installed macOS standard initialize exits 1: versioned config missing; configured source path still has rejecting gate |

### MCP fixes & acceptance

1. **P1 registry split:** canonical JSON has 3 tools; `NativeApplicationEngine::tool_definitions`
   advertises hard-coded legacy 11 (`legion_doctor`, `legion_plan`, `legion_audit`,
   `legion_verify`, `legion_get_run`, `legion_get_finding`, `legion_explain`,
   `legion_list_providers`, `legion_list_languages`, `legion_list_families`,
   `legion_list_skills`). Choose canonical registry/adapter; load verified schema at runtime;
   remove or wire legacy adapter. Acceptance: registry = advertised = dispatchable names.
2. **P1 standalone inert path:** use same versioned composition/binding as `legion serve`, or
   remove binary from release contract. Acceptance: installed standalone initialize/list/call
   fixture succeeds and malformed config fails closed with typed repair evidence.
3. **P2 duplicated CLI schema:** bind `M1McpApi::tool_definitions` to checked-in schema and
   assert name/schema/hash parity against `src/registry/mcp-tools.json`.
4. **P2 shallow validator:** validate nested objects, non-string types, and recursive
   `additionalProperties`, or explicitly declare opaque fields. Acceptance covers malformed
   nested `arguments`/`policyContext` and unknown fields.
5. **P2 stale fixture:** `tests/fixtures/mcp/initialize.ndjson` calls removed
   `legion_list_providers`; update to canonical M1 calls or label legacy-only.
6. **P2 Apple matrix:** table-drive every `legion_apple` operation, unknown/malformed operation,
   dry-run/execute, policy-context, and effect denial.

## Complete `legion script` inventory (77 keys)

`script.rs` exact dispatcher keys:

```text
alchemist/parse_events, alchemist/viewer,
brand-identity/color-check, coder/api-worker,
covenant/validate-external-review-packet,
designer/context, designer/context-signals, designer/critique-storage, designer/detect,
designer/detect-csp, designer/export-deck-pdf, designer/export-deck-pptx,
designer/export-deck-stage-pdf, designer/fetch-images, designer/gen-deck-thumbs,
designer/hook, designer/hook-admin, designer/hook-before-edit, designer/live,
designer/live-accept, designer/live-commit-manual-edits, designer/live-complete,
designer/live-inject, designer/live-insert, designer/live-poll, designer/live-resume,
designer/live-server, designer/live-status, designer/live-target, designer/live-wrap,
designer/narrate-pipeline, designer/palette, designer/mix-voiceover,
designer/render-narration, designer/render-video, designer/render-video-seek,
designer/tts-doubao, designer/verify,
dispatch/validate-dispatch, foundation/validate-atom-report,
handoff/transcript-handoff, handoff/validate-handoff,
ios-development/tool_preflight, macos-development/tool_preflight,
qa/qa-functional, qa/qa-shot,
seo/banana-cost-tracker, seo/banana-generate, seo/banana-presets, seo/bing_webmaster,
seo/crux_history, seo/edit, seo/fetch_page, seo/ga4_report, seo/google_auth,
seo/gsc_inspect, seo/gsc_query, seo/gsc_query_v2, seo/indexing_notify, seo/indexnow,
seo/keyword_planner, seo/nlp_analyze, seo/pagespeed_check, seo/parse_html,
seo/provider_registry, seo/question_inventory, seo/query_ownership, seo/rank_tracker,
seo/render_gap, seo/search_ops, seo/seo_closure, seo/seo_project, seo/site_audit,
seo/google_report, seo/templated_metadata, seo/youtube_search,
tasklist/validate-tasklist
```

Direct `script_cli.rs` coverage is only a subset (report counts 22 list/smoke references, 18
actual invocations; exact count depends whether list-only assertions are counted). Underlying
runtime tests cover modules, not every dispatcher/argv/env/filesystem path. More than 50 keys
have no direct dispatcher invocation.

| Group | Reviewed behavior | Required acceptance |
|---|---|---|
| Alchemist, Covenant, Dispatch, Foundation, Handoff, Tasklist | native handlers and selected direct tests `T`; Handoff docs still dead-Python `I` | invoke each with safe help/invalid/valid packet fixtures; no unknown-key exit 4 |
| Designer | module tests for several adapters; live/hook/browser/server paths `I/A` | temp project/server/Chrome fixtures; writes confined to temp root; every key reaches intended adapter |
| Apple preflight | native catalog source reviewed; platform tools `A` | Windows/macOS CI preflight parity against installed assets |
| QA | module tests; CLI capture/actions `I/A` | disposable local server and artifact readback; no checkout-relative JS requirement |
| SEO | selected module tests; most HTTP/credential/filesystem routes `I/A`; provider registry requires ancestor `skills/` | fake transports and temp HOME; env-key absence typed; redaction; provider registry works from installed root |

Script-wide fix: generate table-driven safe dispatch coverage for all 77 keys, then add fake
HTTP/Chrome/process fixtures for real-I/O keys, temp HOME for Banana, and env redaction tests for
`GA4_*`, `INDEXNOW_KEY`, `GOOGLE_INDEXING_BEARER_TOKEN`, `YOUTUBE_API_KEY`, `BING_API_KEY`, and
Ads credentials. Add parity manifest mapping each key to retained legacy source or approved
Rust-only contract; current checkout has no legacy source oracle.

## Complete `legion-dev` inventory (27)

```text
check-portability, check-version-parity, check-publication-surface,
check-authority-parity, evaluate-authority-replay, generate-catalogs,
check-canonical-names, check-blueprint-config, check-publication-policy,
check-distribution-contract, check-release-obligations, generate-schemas,
generate-manifest, normalize-provider-result, native-cli-inventory,
check-native-cli-surface, generate-host-projection, generate-skill-catalog,
generate-codex-skill-sidecars, refresh-local-skill-manifests, verify-plugin-parity,
report-to-sarif, plugin-dev, check-dependency-closure, check-packed-import-closure,
native-cli-parity-installed, native-cli-capture-rust
```

`legion:check` runs 20 and omits publication policy, provider normalization, SARIF reporting,
replay evaluation, installed parity, Rust characterization, and plugin-dev/write mode. The
native CLI surface command defaults to `record`; package/CI calls omit `--phase enforce`.

| Priority | Fix | Acceptance |
|---|---|---|
| P1 | make package/CI native surface checks `--phase enforce`; keep record explicit | stale Node/native route mismatch fails CI |
| P1 | add omitted 7 commands to a deliberate gate or document why each is out-of-gate | generated gate manifest names every command and status |
| P2 | make installed parity and Rust characterization CI-visible | exact installed binary and source route readback |

## Complete `xtask` inventory (16)

```text
verify-release, assemble-native-release, package-windows-release,
prepare-unsigned-candidate, prepare-windows-candidate-finalization,
finalize-macos-candidate, qualify-windows-release, release-admission,
release-stage-summary, release-evidence-verification, release-finalize-windows,
release-finalize-macos, release-qualify-installed, release-publish-qualified,
release-local-windows-development, native-installed-smoke
```

`main.rs` retains unused `delegate_to_node()` and stale docs naming deleted JS implementations;
no command dispatches through it. Unit seams exist for release evidence, packaging, rollback,
and process diagnostics; real RightKit/GitHub/Inno/PowerShell/Apple signing/notary paths are
`CI/A` only.

### Release/process fixes & acceptance

| Priority | Finding | Exact fix | Acceptance |
|---|---|---|---|
| P1 | Rust subprocess timeouts are inert: blocking `Command::output()` in `qualify_windows/tree.rs`, `release/paths.rs`, and ignored `_timeout` in `native_installed_smoke.rs`. | one killable runner with timeout, process-tree kill, bounded output, diagnostic evidence; route all Rust subprocesses through it. | sleeping child terminates, nonzero result, clipped diagnostics, no false qualification. |
| P1 | Windows activation defaults 60s while setup qualification permits 180s. | one explicit Inno → PowerShell → setup timeout contract; pass from qualification. | stalled child produces bounded failure/retry evidence; normal repair respects budget. |
| P1 | Same-version Windows installer merges payload into existing `versions/0.3.21`; obsolete directories survive & strict plugin-root validation rejects them. Real `d54bea8c` upgrade reproduced `package contains extra directory skills/alchemist/scripts`. | stage fresh version payload, validate before activation & replace owned version tree; preserve prior current for rollback. Add upgrade qualification with obsolete files/directories present. | exact normal same-version upgrade removes obsolete package entries & both MCP transports pass without manual cleanup; forced failure restores prior current. |
| P1 | macOS local build bypasses RightKit admission (`dev:build:mac`). | shared admission wrapper or CI-only route. | active/recent/missing inventory refuses local work and points to GitHub. |
| P1 | Swift installer accepts `..`, `.`, slash, non-SemVer; switches `current` before setup/doctor and lacks rollback. | strict stable SemVer/path validation; stage/verify then pointer swap or durable rollback. | invalid versions cannot escape `versions`; forced setup failure restores prior current. |
| P1 | `932d1074` fixes same-version stale payload by staging/replacing payload; macOS CI & installed readback passed at `8c23e45b`. | complete GitHub macOS installed qualification and record exact payload comparison. | second same-version install replaces stale Minimize policy and passes readback. |
| P2 | `activate.ps1` scans every package LocalCache mirror. | scope declared package IDs; rollback-safe non-destructive mirror failures. | unrelated package trees untouched. |
| P2 | CI change detector omits package/lock/scripts/release config and can skip toolchain setup before gate. | include all build/release inputs or make gate install tools independently. | each release-affecting diff gets toolchain + gate coverage. |
| P2 | macOS workflow hardcodes `0.3.21`. | derive from `release/version.json`; assert metadata/payload match. | version bump changes artifact identity without edit to workflow. |
| P2 | release-finalize host guards incomplete. | fail fast before mutation on wrong OS/tool absence. | wrong-host Windows/macOS finalize has no output mutation. |
| P2 | `Command::output()` capture unbounded in ports. | bounded pipes/files with clipped diagnostics and hashes. | noisy child cannot exhaust memory; evidence retains diagnostic hash. |

## `package.json` inventory (37 current; report count 36)

```text
ci:unsigned-candidate, ci:unsigned-candidate-check, closure:check,
deps:cargo:outdated, deps:cargo:upgrade, deps:pnpm:outdated, deps:pnpm:upgrade,
legion:check, naming:check, native-cli:capture-rust, native-cli:inventory,
native-cli:parity-installed, native-cli:surface-check, native:assemble,
native:check:local, native:smoke, plugin:dev, plugin:surface, plugin:verify,
release:admission, release:build:win:unsigned, dev:build:win, dev:build:mac,
release:doctor, release:finalize-macos, release:finalize-windows,
release:local:win:unsigned, release:publish-qualified, release:qualify-installed,
release:stage-summary, release:verify-evidence, schemas:check, test,
windows:finalize, windows:package, windows:publish, windows:qualify
```

| Class | Entries | Status |
|---|---|---|
| CI/build/check | `ci:unsigned-candidate`, `ci:unsigned-candidate-check`, `closure:check`, `legion:check`, `naming:check`, `schemas:check`, `test` | CI gate/candidate; native surface phase defect |
| dependency mutation/report | four `deps:*` entries | `I/A`; upgrades mutate declarations/lock and need explicit operator scope |
| native CLI/catalogue | `native-cli:*` (4), `native:assemble`, `native:check:local`, `native:smoke` | mixed CI; installed parity/capture not always called |
| plugin | `plugin:dev`, `plugin:surface`, `plugin:verify` | structural verify in CI; write modes `I` |
| release admission/evidence | `release:admission`, `release:stage-summary`, `release:verify-evidence` | release-candidate CI |
| Windows | `release:build:win:unsigned`, `dev:build:win`, `release:local:win:unsigned`, `release:qualify-installed`, `windows:*` | Windows CI; local paths subject RightKit admission |
| macOS | `dev:build:mac`, `release:finalize-macos` | signing/toolchain `A`; local build gate defect |
| publication | `release:publish-qualified`, `release:finalize-windows`, `windows:publish` | protected publication `A`; no local execution |
| release doctor | `release:doctor` | `I/A`; no workflow call found |

## Shipped scripts, skills, and public documentation

Tracked script/data files under `skills/**` are only:

```text
skills/designer/engine/huashu/scripts/render-narration.sh
skills/designer/engine/scripts/command-metadata.json
skills/designer/engine/scripts/live/ui-core.mjs
skills/designer/engine/scripts/detector/tests/structure/{app-shell,bad-landing,cta-competition,
good-landing,hover-header,site-exists,site-index}.html
```

Ignored `__pycache__/*.pyc` files are generated artifacts, not shipped source. Public bundle sets
match at 29 each across `skills/*/SKILL.md`, `skills/manifests/*.json`,
`src/registry/skills/index.json`, and `src/registry/host-projection.json`. Canon's 30 atomic
capabilities include catalog resolution/projection & explicit roles, so that count does not
imply a missing thirtieth bundle. The source report's count-mismatch finding is rejected.
Historical RELEASED claims still need current behavioral evidence for each promised observable,
especially Audit Visual; matching bundle counts cannot establish behavioral closure.

### Public documentation defects

| Priority | Broken public path | Fix | Acceptance |
|---|---|---|---|
| P1 | Handoff docs call missing `skills/handoff/scripts/transcript-handoff.py`. | native `legion script handoff/transcript-handoff` and `handoff/validate-handoff`. | POSIX/Windows examples resolve from installed release; no missing path. |
| P1 | Foundation docs call absent `scripts/validate_atom_report.py`. | native `foundation/validate-atom-report`. | stage examples run native command or typed unavailable. |
| P1 | Dispatch docs call absent `scripts/validate-dispatch.py`. | native `dispatch/validate-dispatch`. | packet examples run installed native path. |
| P1 | Audit Visual docs call absent QA JS files. | native `qa/qa-shot` and `qa/qa-functional`; emit visual artifact. | capture/action docs work from installed release. |
| P1 | Designer references call deleted `detect.mjs`, `run-structure-smoke.mjs`, `lib/qa-engine/qa-shot.mjs`. | native `designer/*` keys or existing packaged fixtures. | every executable reference maps to `script --list` or packaged file. |
| P1 | SEO docs call absent Python (`coverage.py`, `ai_visibility_import.py`, `checklist_compiler.py`, `tools/lib/okf.py`) and no matching native keys for some operations. | port/document native key or typed `UNAVAILABLE/UNPROVEN`; remove imperative dead paths. | every procedure resolves or reports typed gap. |
| P1 | Audit docs call deleted `tools/audit/*.mjs`, `audit_provider.py`, `minimize_gate.py`, `validate-route.py`. | native `legion audit` workflow; package all required adapters if retained. | clean install can follow run/finalize instructions. |
| P1 | Research docs admit native route freezes all domains at `general`. | implement legal/medical/technical/market/scholarly classification or narrow contract. | representative routes emit domain/provider denominator; unsupported route typed. |
| P2 | Coder docs disagree on `lib/coder-api-worker/api-worker.py` vs `src/lib/...`. | canonical native `coder/api-worker`; verify packaged source path. | installed help works; no unresolvable path. |

`README.md` setup promises require host-visible projection/MCP registration readback on both
clients. `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json` are present; that proves
declaration, not installed registration. Historical `docs/DOGFOOD.md` counts/version are not
current closure evidence.

## CI-only acceptance matrix

Run after RightKit admission in GitHub, with exact source SHA and artifacts:

1. `node --test scripts/release/local-build-route.test.mjs` (5 route-policy cases).
2. Focused Rust packages: `legion-dev`, `xtask`, `legion-contracts`; then workspace all-targets
   check/test/build on selected host.
3. `legion-dev check-native-cli-surface --phase enforce` and
   `legion-dev verify-plugin-parity --check --structural-only`.
4. Table-driven all-43 CLI route characterization plus positive fixtures for schedule, audit,
   doctor, authority, completion, policy, handoff, contract/run/completion/review/host, and
   installed topology/rules/provider assets.
5. All-77 script safe dispatch fixture; fake network/browser/process fixtures; temp HOME/env
   isolation/redaction; parity manifest.
6. MCP registry/adapter equality, standalone initialize/list/call, recursive schema validation,
   full Apple operation matrix, malformed package-root/config/digest/symlink fail-closed cases.
7. Windows: whole native workspace check → unsigned installer → isolated qualification → exact
   stable-`current` install/readback; timeout, rollback, host-guard, output-cap evidence.
8. macOS: same sequence plus Swift invalid-version/path traversal, setup/doctor rollback,
   same-version payload digest/readback, native Minimize policy removal fail-closed, Claude hook
   and MCP permission readback.

## Remaining unmapped or unproven entries

- All 77 script keys now have direct help/precondition probes; successful operational fixtures remain incomplete. Module tests & exit-zero help responses do not close functional parity.
- Root positive lifecycle routes (`schedule`, `run`, `contract`, `completion`, `review`, valid
  host ledger, installed topology/assets) remain `I/A`.
- Standalone `legion-mcp` has no successful shipped initialization path.
- MCP canonical 3-tool registry vs hard-coded legacy 11-tool adapter is unresolved.
- `visual.core` alias/legacy/native mapping is ambiguous; visual args are inert and no named
  visual artifact is emitted.
- Installed plan/audit signing key injection is unproven outside fixture env; no installed
  qualification receipt proves key custody or signed visual output.
- Map canon observables to installed behavior; its atomic-capability count is distinct from bundles.
- Source report's package count corrected from 36 to 37; no runtime defect follows from that typo.
- Real external RightKit, GitHub, Inno, PowerShell, Swift, codesign, notarization, browser,
  provider credentials, and network paths remain platform/dependency/auth gated.
- Green `8c23e45b` full CI & macOS qualification remain scoped to named stages; Windows qualification & stable installation passed.

Root owner records each acceptance receipt in GitHub CI, then updates this inventory with exact
SHA, artifact digest, platform, and installed readback.

## Live Minimize consumer & dormant receipt path

Windows parent workspace `.git/hooks/pre-commit` resolves installed stable `current/bin/legion.exe`
& executes `minimize commit verify .audit/minimize/commit-receipt.json`. Native asset repair
reaches that consumer. Existing receipts must be regenerated through reviewed native flow;
changing executable digest deliberately invalidates prior receipts. Parent workspace staging
& commits are outside this Legion repair.

`engine/crates/legion-runtime/src/wf_port/w2_046/discipline_controls.rs:524-526` still names
workspace-relative deleted policy/JavaScript files in `pre_effect_discipline`. Only its own
tests call full function; live `r51/pipeline.rs` calls prefix only. This dormant implementation
is a parity gap, not evidence that repaired native CLI still needs JavaScript. Consolidate
receipt validation behind one native implementation before enabling full discipline consumer.

Source challenge: missing optional Oracle validation alone is not an Audit defect. `skills/audit/references/manual.md:130-144` explicitly separates quality gate from overall audit; current AGENTS.md makes Oracle conditional. Gate-vector semantics remain an open reconciliation item, not a confirmed blanket CV requirement.


## Executed offline entrypoint probes

Diagnostic run [37310348598](https://github.com/Orthic-Labs/legion/actions/runs/37310348598)
compiled & executed source `a553be4f` in a separate network namespace with no routes, isolated
HOME/config/cwd & no provider credentials. All **77 script keys, 43 root commands, 27 developer
commands & 16 xtask commands** were invoked. Raw result contains 169 rows because discovery
calls & two synthetic Clap help commands are included: 94 exit-zero, 74 nonzero, one timeout,
zero unexercised rows. These are help/precondition outcomes, not functional PASS labels.

Report artifact SHA256: `f30c6bbf68ab0222a373119e1b0821aef469f79c3a2ef6a863e546402c95e6d3`.
Machine-readable corrected rows: [entrypoint evidence](legion-entrypoint-inventory-ca568a74.json).

Confirmed discovery failure: root help advertises 32 of 43 routes, omitting `apple`, `status`,
`serve`, `catalog`, `policy`, `decision`, `handoff`, `research`, `review`, `setup` & `script`.
`alchemist/viewer --help` starts Citadel server instead of showing help, then exceeds five-second
limit. CI kills its owned process group. Fix argument handling & require help to exit without
opening a listener. Two developer/xtask count errors were probe bookkeeping: Clap's synthetic
`help` command was counted against enum totals. Probe parser now excludes that synthetic route;
raw original evidence is retained. Diagnostic remains red until genuine help defects close.

Full CI for `a553be4f` stopped at portability gate because this report included two developer-local
workspace paths. Paths are replaced with portable descriptions; no runtime defect caused that gate.

## Additional installed macOS setup defect

Normal qualified installer activated exact `8c23e45b` payload but global setup-finish exited 1:
optional Pi profile reports Baseline fidelity & missing executableToolSurface, mcpLifecycle,
releaseBinding, executableResolution & hostEnforcement. Claude & Codex selected repair each
exited 0 & read back COMPLETE. This mixed-client aggregate failure predates this repair & does
not invalidate requested clients' installed evidence.

P1 fix: global setup aggregation must distinguish optional explicit-only Baseline clients from
requested supported clients, report their actual fidelity, & produce a truthful exit/result.
Acceptance: qualify installer with Claude + Codex + optional Pi present; requested clients install
cleanly & optional profile has an explicit disposition. Add that mixed-client fixture to macOS
qualification, which currently tests a narrower disposable host.


### Confirmed native dispatch panics

P1: offline CLI probes exit 101 for `designer/detect`, `designer/live-complete`,
`seo/banana-generate`, `seo/ga4_report`, `seo/indexing_notify`, `seo/indexnow` &
`seo/site_audit`. Each reports Tokio runtime shutdown panic: blocking runtime cannot be
dropped inside async context. `commands/script.rs` calls synchronous production adapters
directly from Tokio-driven CLI; several construct blocking Reqwest clients before validating
help/preconditions. Source adapter tests do not exercise that actual CLI boundary.

Fix: run synchronous adapter ownership on a blocking thread, or migrate adapters fully async;
parse help/required arguments before constructing network/browser clients. Preserve exit semantics
& credentials. Acceptance: invoke each real CLI route through async root with help, malformed
input & offline provider fixture; no panic, no help side effects, explicit dependency/auth errors.
Browser probes under privileged isolated CI report Chrome sandbox preconditions; those results
are recorded as dependency outcomes, not evidence of failure on user's desktop.

Corrected probe run [37311568382](https://github.com/Orthic-Labs/legion/actions/runs/37311568382)
at `ca568a74` confirms **167 rows: 94 exit-zero, 72 nonzero, one timeout, zero unexercised**.
Only genuine root-help denominator/missing-command findings remain among 12 structural errors;
seven script panic reproductions remain unchanged. Artifact SHA256:
`2af184d575dc20671398bdff318f60abe55d328e40c078023015856e470289c1`.
Original `a553be4f` evidence is retained in Git history & its named Actions artifact.

Installed macOS standalone `legion-mcp` was invoked with standard initialize request, isolated
HOME/cwd & no composition override. It exited 1 with `versioned native application configuration
is missing`, emitted no JSON-RPC response. Installed `legion serve --stdio` passed five requests.
Standalone composition/binding repair remains P1; these transports have distinct behavior.


## Earlier Windows stable installation (`8c23e45b`)

Windows run [37307457541](https://github.com/Orthic-Labs/legion/actions/runs/37307457541)
passed full repository gate, whole native workspace/all targets, hook behavior, exact unsigned
installer build & isolated installed qualification including rollback/stalled-child tests.
Qualified source: `8c23e45b49e41cc2eec3b8f5e776564d077647f0`.

- Artifact ZIP SHA256: `ecec246d7514e52c8790c1e7d313046e26eeedac98f8c18261c7a77dd98ed07b`.
- Installer SHA256: `9ceb5ca3154e88b545ec8aad49ff58ad6ee3d3d6f02854222cca2f5a132fe31e`.
- Stable native CLI SHA256: `7adac1ab0e12250793663747c031add5c4975feba773969f990d849f5b8296a3`.
- Assets generation: `51cf3b32952c706a4c079d82fa9ac337b6d67ae49e9eeb6bfcabc231c816131f`.

Exact normal installer completed exit 0 on operator's Windows host, using documented 180-second
child budget to avoid known 60s/180s mismatch. Installed status reads COMPLETE, installed-origin
& stable-current. All 1,036 manifest-listed files match across payload, Claude & Codex. Standard
hook payloads at parent workspace admit Snapshot/Click/docs query without host permission override;
write/send/delete deny. Five MCP requests succeed. Isolated native Minimize receipt workflow passes,
binds shipped Rust CLI/policy & rejects staged-tree drift. Parent workspace Git hook resolves this
installed CLI; unrelated staged work & prior receipts were not recertified.

Earlier production source changes are committed in `932d1074` & `8c23e45b`.
Transport repair `d54bea8c` supersedes those runtime installations; current delivery is recorded
at report start. Earlier five-response transport evidence exercised bare stdio only.
