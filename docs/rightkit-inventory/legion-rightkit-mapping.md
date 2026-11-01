# Legion: RightKit mapping

Repo `legion` at `16ba35b7` (main). Generated 2026-11-01. Every tracked code file (Rust, TS/JS, Swift, Kotlin, Python, shell, CSS/HTML, TOML, SQL) is assigned to exactly one target. Full per-file list: [`legion-rightkit-files.json`](legion-rightkit-files.json).

Package names are final, after cross-app merging (see master plan in RightKit `docs/audits/2026-11-01-rightkit-package-master-plan.md`).

## Summary

| Action | Meaning | Files | Lines |
|---|---|---:|---:|
| NEW | new RightKit package (or new piece of one) | 847 | 374,578 |
| EXTEND | existing RightKit package gains this | 572 | 198,531 |
| ADOPT | RightKit already ships it; delete app copy & use owner | 6 | 1,357 |
| LEGION | skill/doctrine code: lives in Legion (suite skills owner), not RightKit | 130 | 71,060 |
| APPTEST | app journey/e2e test: stays with the app (P7, §6), runs on rightkit-qa | 35 | 16,967 |
| SHELL | thin app composition that stays in app | 11 | 583 |
| CONFIG | app manifest/config that stays | 41 | 457 |
| **Total** | | **1,642** | **663,533** |

Code leaving the app (NEW + EXTEND + ADOPT + LEGION + vendor + DROP): **645,526 lines**. Staying in the app as product code: **0 lines**; as shell/config: **1,040 lines** (0% of code), plus **16,967 lines** of app journey/e2e tests.

## Mapping table

| RightKit target | Kind | Action | What moves | Files | Lines | Where (sample) |
|---|---|---|---|---:|---:|---|
| `rightkit-agent-orchestration` | crate | NEW | capability routing runtime: plan, route, task, budget, grant, escalation, delivery, inventories, platform layers, skills/designer checks | 185 | 41,212 | `engine/crates/legion-runtime/`, `engine/crates/legion-runtime/src/`, `engine/crates/legion-runtime/src/l3_inventory/` +17 dirs |
| `rightkit-agent-orchestration` | crate | NEW | handoff packets, continuity gate, live state | 22 | 8,813 | `engine/crates/legion-handoff/`, `engine/crates/legion-handoff/src/`, `engine/crates/legion-handoff/src/l1_port/` +2 dirs |
| `rightkit-agent-orchestration` | crate | NEW | run, budget & schedule commands | 5 | 1,253 | `engine/bins/legion/src/commands/` |
| `rightkit-agent-policy` | crate | NEW | policy model, rules & enforcement | 39 | 9,043 | `engine/crates/legion-policy/`, `engine/crates/legion-policy-model/`, `engine/crates/legion-policy-model/src/` +9 dirs |
| `rightkit-apple-ops` | crate | NEW | Apple ops: App Store Connect API & upload, build analysis, preflight, profiling, SwiftUI traces | 12 | 10,150 | `engine/crates/legion-apple/`, `engine/crates/legion-apple/src/` |
| `rightkit-apple-ops` | crate | NEW | Apple ops CLI/MCP gate | 2 | 1,156 | `engine/bins/legion/src/`, `engine/bins/legion/src/commands/` |
| `rightkit-code-audit` | crate | NEW | repository audit engine: native providers (security, architecture, data, frontend, platform), DAG & scheduler, evidence issuers, findings history, review runtime, provider SDK, rule registry & qualification corpora | 425 | 233,866 | `engine/crates/legion-audit/`, `engine/crates/legion-audit/assets/`, `engine/crates/legion-audit/examples/` +96 dirs |
| `rightkit-code-audit` | crate | NEW | audit/verify commands & audit bench | 8 | 18,098 | `engine/bins/legion-dev/src/`, `engine/bins/legion/src/commands/` |
| `rightkit-code-audit` | crate | NEW | audit CLI commands | 7 | 2,926 | `engine/bins/legion/src/commands/` |
| `rightkit-doctor` | crate | NEW | doctor command | 1 | 1,720 | `engine/bins/legion/src/commands/` |
| `rightkit-engine-host` | crate | NEW | engine binary framework: sidecar + headless CLI modes, command registration, contract export & TS codegen, human/JSON presentation, engine client | 3 | 2,235 | `engine/bins/legion/src/`, `engine/bins/legion/src/commands/` |
| `rightkit-evidence` | crate | NEW | contracts, effect execution & receipts, decision store, evidence/SARIF/HTML reports, certification & governance lifecycle | 97 | 27,195 | `engine/crates/legion-application/`, `engine/crates/legion-application/src/`, `engine/crates/legion-arcane/` +15 dirs |
| `rightkit-evidence` | crate | NEW | evidence, freeze, contract & decision commands | 12 | 6,225 | `engine/bins/legion/src/commands/` |
| `rightkit-github` | crate | NEW | GitHub delivery observation | 1 | 596 | `engine/bins/legion/src/commands/` |
| `rightkit-research` | crate | NEW | research pipeline (sources, claims, evidence) | 27 | 9,047 | `engine/crates/legion-research/`, `engine/crates/legion-research/src/`, `engine/crates/legion-research/src/research_port/` +2 dirs |
| `rightkit-research` | crate | NEW | research command | 1 | 1,043 | `engine/bins/legion/src/commands/` |
| `@rightkit/qa` | npm | EXTEND | CI gates, validators, fixtures, python tool locks | 224 | 26,088 | `scripts/`, `scripts/ci/`, `scripts/ci/fixtures/audit-code-jvm-sdk/` +106 dirs |
| `@rightkit/release` | npm | EXTEND | xtask build/verify tasks | 36 | 18,766 | `engine/xtask/`, `engine/xtask/src/`, `engine/xtask/src/package_windows_release/` +2 dirs |
| `@rightkit/release` | npm | EXTEND | repo gates: version parity, distribution/publication contract, portability, lint qualification | 16 | 7,554 | `engine/bins/legion-dev/src/`, `engine/bins/legion-dev/src/checks/`, `engine/bins/legion-dev/src/shared/` |
| `@rightkit/release` | npm | EXTEND | release scripts | 7 | 1,902 | `scripts/release/`, `scripts/release/macos/`, `scripts/release/windows/` |
| `@rightkit/release` | npm | EXTEND | release config logic moves into @rightkit/release; app keeps a JSON data config (P8) | 1 | 399 | `./` |
| `rightkit-hooks` | crate | EXTEND | hook binary | 7 | 7,067 | `engine/bins/legion-hook/`, `engine/bins/legion-hook/src/`, `engine/bins/legion-hook/tests/` |
| `rightkit-review` | crate | EXTEND | independent review & minimal-diff review | 23 | 4,496 | `engine/crates/legion-minimize/`, `engine/crates/legion-minimize/src/`, `engine/crates/legion-minimize/tests/` +5 dirs |
| `rightkit-workflow` | crate | EXTEND | workflow port (scenario/state machine runtime) | 258 | 132,259 | `engine/crates/legion-audit/src/wf_port/`, `engine/crates/legion-audit/src/wf_port/wf010/`, `engine/crates/legion-audit/src/wf_port/wf064/` +51 dirs |
| `rightkit-mcp` | crate | ADOPT | stdio MCP transport | 6 | 1,357 | `engine/bins/legion-mcp/`, `engine/bins/legion-mcp/src/` |
| `legion` | Legion | LEGION | agent skill packs & doctrine (architect, audit, council, designer, iOS/macOS/Android dev, marketing, SEO, research, writing, etc.) | 25 | 19,290 | `skills/designer/engine/huashu/assets/`, `skills/designer/engine/scripts/`, `skills/designer/engine/scripts/detector/` +3 dirs |
| `legion` | Legion | LEGION | capability catalog & frontmatter, host detection/projection into Claude Code/Codex/AGENTS.md, plugin marketplace install | 45 | 18,364 | `engine/crates/legion-catalog/`, `engine/crates/legion-catalog/src/`, `engine/crates/legion-harness/` +8 dirs |
| `legion` | Legion | LEGION | host setup, binding & script projection | 3 | 12,837 | `engine/bins/legion/src/commands/` |
| `legion` | Legion | LEGION | Legion's own skill-corpus checks | 13 | 6,549 | `engine/bins/legion-dev/src/`, `engine/bins/legion-dev/src/checks/`, `engine/bins/legion-dev/src/shared/` |
| `legion` | Legion | LEGION | skill & designer checks | 21 | 6,445 | `engine/crates/legion-runtime/src/l5_skills/`, `engine/crates/legion-runtime/src/l6_designer_checks/`, `engine/crates/legion-runtime/src/p8_designer/` +1 dirs |
| `legion` | Legion | LEGION | catalog & inventory generators | 17 | 5,119 | `engine/bins/legion-dev/src/generators/` |
| `legion` | Legion | LEGION | Legion's own skill/host projection commands | 6 | 2,456 | `engine/bins/legion/src/commands/` |
| `app-shell` | other | APPTEST | app journey/e2e/unit tests of the app binary | 24 | 13,301 | `engine/bins/legion/tests/` |
| `app-shell` | other | APPTEST | app journey/e2e tests | 11 | 3,666 | `engine/tests/` |
| `app-shell` | other | SHELL | legion CLI & dev generators | 11 | 583 | `engine/bins/legion/`, `engine/bins/legion-dev/`, `engine/bins/legion/src/commands/` |
| `app-shell` | other | CONFIG | app manifests | 34 | 252 | `bench/_selfcheck/`, `bench/corpora/dotnet/negative/`, `bench/corpora/javascript/denominator/` +26 dirs |
| `app-shell` | other | CONFIG | engine workspace | 7 | 205 | `engine/`, `engine/.cargo/`, `engine/crates/legion-workspace-tests/` +1 dirs |

## What stays in the app (SHELL)

Entry points, command tables & app-specific wiring over RightKit packages. Largest files:

| File | Lines |
|---|---:|
| `engine/bins/legion/src/commands/authority.rs` | 99 |
| `engine/bins/legion/src/commands/providers.rs` | 94 |
| `engine/bins/legion/src/commands/plan.rs` | 87 |
| `engine/bins/legion/src/commands/topology.rs` | 69 |
| `engine/bins/legion/src/commands/languages.rs` | 52 |
| `engine/bins/legion/Cargo.toml` | 50 |
| `engine/bins/legion/src/commands/handoff.rs` | 31 |
| `engine/bins/legion/src/commands/host.rs` | 29 |
| `engine/bins/legion-dev/Cargo.toml` | 28 |
| `engine/bins/legion/src/commands/policy.rs` | 25 |
| `engine/bins/legion/src/commands/catalog.rs` | 19 |
