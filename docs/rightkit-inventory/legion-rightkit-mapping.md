# Legion: RightKit mapping

Repo `legion` at `a6486f50` (main). Generated 2026-11-01. Every tracked code file (Rust, TS/JS, Swift, Kotlin, Python, shell, CSS/HTML, TOML, SQL) is assigned to exactly one target. Full per-file list: [`legion-rightkit-files.json`](legion-rightkit-files.json).

Package names are final, after cross-app merging (see master plan in RightKit `docs/audits/2026-11-01-rightkit-package-master-plan.md`).

## Summary

| Action | Meaning | Files | Lines |
|---|---|---:|---:|
| NEW | new RightKit package (or new piece of one) | 815 | 357,424 |
| EXTEND | existing RightKit package gains this | 555 | 190,578 |
| ADOPT | RightKit already ships it; delete app copy & use owner | 6 | 1,357 |
| LEGION | skill/doctrine code: lives in Legion (suite skills owner), not RightKit | 111 | 62,055 |
| APPTEST | app journey/e2e test: stays with the app (P7, §6), runs on rightkit-qa | 11 | 3,666 |
| SHELL | thin app composition that stays in app | 102 | 47,597 |
| CONFIG | app manifest/config that stays | 42 | 856 |
| **Total** | | **1,642** | **663,533** |

Code leaving the app (NEW + EXTEND + ADOPT + LEGION + vendor + DROP): **611,414 lines**. Staying as app shell/config: **48,453 lines** (7% of code), plus **3,666 lines** of app journey/e2e tests.

## Mapping table

Tier (NEW only): public = generic, MIT/Apache on crates.io/npm; private = product domain code, private registry.

| RightKit target | Kind | Tier | Action | What moves | Files | Lines | Where (sample) |
|---|---|---|---|---|---:|---:|---|
| `rightkit-agent-orchestration` | crate | public | NEW | capability routing runtime: plan, route, task, budget, grant, escalation, delivery, inventories, platform layers, skills/designer checks | 185 | 41,212 | `engine/crates/legion-runtime/`, `engine/crates/legion-runtime/src/`, `engine/crates/legion-runtime/src/l3_inventory/` +17 dirs |
| `rightkit-agent-orchestration` | crate | public | NEW | handoff packets, continuity gate, live state | 22 | 8,813 | `engine/crates/legion-handoff/`, `engine/crates/legion-handoff/src/`, `engine/crates/legion-handoff/src/l1_port/` +2 dirs |
| `rightkit-agent-policy` | crate | public | NEW | policy model, rules & enforcement | 39 | 9,043 | `engine/crates/legion-policy/`, `engine/crates/legion-policy-model/`, `engine/crates/legion-policy-model/src/` +9 dirs |
| `rightkit-apple-ops` | crate | public | NEW | Apple ops: App Store Connect API & upload, build analysis, preflight, profiling, SwiftUI traces | 12 | 10,150 | `engine/crates/legion-apple/`, `engine/crates/legion-apple/src/` |
| `rightkit-code-audit` | crate | private | NEW | repository audit engine: native providers (security, architecture, data, frontend, platform), DAG & scheduler, evidence issuers, findings history, review runtime, provider SDK, rule registry & qualification corpora | 425 | 233,866 | `engine/crates/legion-audit/`, `engine/crates/legion-audit/assets/`, `engine/crates/legion-audit/examples/` +96 dirs |
| `rightkit-code-audit` | crate | private | NEW | audit/verify commands & audit bench | 8 | 18,098 | `engine/bins/legion-dev/src/`, `engine/bins/legion/src/commands/` |
| `rightkit-evidence` | crate | public | NEW | contracts, effect execution & receipts, decision store, evidence/SARIF/HTML reports, certification & governance lifecycle | 97 | 27,195 | `engine/crates/legion-application/`, `engine/crates/legion-application/src/`, `engine/crates/legion-arcane/` +15 dirs |
| `rightkit-research` | crate | public | NEW | research pipeline (sources, claims, evidence) | 27 | 9,047 | `engine/crates/legion-research/`, `engine/crates/legion-research/src/`, `engine/crates/legion-research/src/research_port/` +2 dirs |
| `@rightkit/qa` | npm |  | EXTEND | CI gates, validators, fixtures, python tool locks | 224 | 26,088 | `scripts/`, `scripts/ci/`, `scripts/ci/fixtures/audit-code-jvm-sdk/` +106 dirs |
| `@rightkit/release` | npm |  | EXTEND | xtask build/verify tasks | 36 | 18,766 | `engine/xtask/`, `engine/xtask/src/`, `engine/xtask/src/package_windows_release/` +2 dirs |
| `@rightkit/release` | npm |  | EXTEND | release scripts | 7 | 1,902 | `scripts/release/`, `scripts/release/macos/`, `scripts/release/windows/` |
| `rightkit-hooks` | crate |  | EXTEND | hook binary | 7 | 7,067 | `engine/bins/legion-hook/`, `engine/bins/legion-hook/src/`, `engine/bins/legion-hook/tests/` |
| `rightkit-review` | crate |  | EXTEND | independent review & minimal-diff review | 23 | 4,496 | `engine/crates/legion-minimize/`, `engine/crates/legion-minimize/src/`, `engine/crates/legion-minimize/tests/` +5 dirs |
| `rightkit-workflow` | crate |  | EXTEND | workflow port (scenario/state machine runtime) | 258 | 132,259 | `engine/crates/legion-audit/src/wf_port/`, `engine/crates/legion-audit/src/wf_port/wf010/`, `engine/crates/legion-audit/src/wf_port/wf064/` +51 dirs |
| `rightkit-mcp` | crate |  | ADOPT | stdio MCP transport | 6 | 1,357 | `engine/bins/legion-mcp/`, `engine/bins/legion-mcp/src/` |
| `legion` | Legion |  | LEGION | agent skill packs & doctrine (architect, audit, council, designer, iOS/macOS/Android dev, marketing, SEO, research, writing, etc.) | 25 | 19,290 | `skills/designer/engine/huashu/assets/`, `skills/designer/engine/scripts/`, `skills/designer/engine/scripts/detector/` +3 dirs |
| `legion` | Legion |  | LEGION | capability catalog & frontmatter, host detection/projection into Claude Code/Codex/AGENTS.md, plugin marketplace install | 45 | 18,364 | `engine/crates/legion-catalog/`, `engine/crates/legion-catalog/src/`, `engine/crates/legion-harness/` +8 dirs |
| `legion` | Legion |  | LEGION | host setup, binding & script projection | 3 | 12,837 | `engine/bins/legion/src/commands/` |
| `legion` | Legion |  | LEGION | skill & designer checks | 21 | 6,445 | `engine/crates/legion-runtime/src/l5_skills/`, `engine/crates/legion-runtime/src/l6_designer_checks/`, `engine/crates/legion-runtime/src/p8_designer/` +1 dirs |
| `legion` | Legion |  | LEGION | catalog & inventory generators | 17 | 5,119 | `engine/bins/legion-dev/src/generators/` |
| `app-shell` | other |  | APPTEST | app journey/e2e tests | 11 | 3,666 | `engine/tests/` |
| `app-shell` | other |  | SHELL | legion CLI & dev generators | 102 | 47,597 | `engine/bins/legion/`, `engine/bins/legion-dev/`, `engine/bins/legion-dev/src/` +5 dirs |
| `app-shell` | other |  | CONFIG | app manifests | 35 | 651 | `./`, `bench/_selfcheck/`, `bench/corpora/dotnet/negative/` +27 dirs |
| `app-shell` | other |  | CONFIG | engine workspace | 7 | 205 | `engine/`, `engine/.cargo/`, `engine/crates/legion-workspace-tests/` +1 dirs |

## What stays in the app (SHELL)

Entry points, command tables & app-specific wiring over RightKit packages. Largest files:

| File | Lines |
|---|---:|
| `engine/bins/legion/src/cli.rs` | 2,018 |
| `engine/bins/legion-dev/src/native_cli_gate.rs` | 1,809 |
| `engine/bins/legion/src/commands/doctor.rs` | 1,720 |
| `engine/bins/legion/tests/audit_review_runtime.rs` | 1,371 |
| `engine/bins/legion/tests/entrypoint_inventory.rs` | 1,317 |
| `engine/bins/legion-dev/src/checks/run_skill_evals.rs` | 1,239 |
| `engine/bins/legion/tests/script_cli.rs` | 1,196 |
| `engine/bins/legion/src/commands/contract.rs` | 1,187 |
| `engine/bins/legion-dev/src/checks/dependency_closure.rs` | 1,115 |
| `engine/bins/legion/src/commands/rules.rs` | 1,067 |
| `engine/bins/legion/src/commands/research.rs` | 1,043 |
| `engine/bins/legion/src/apple_mcp.rs` | 1,041 |
| `engine/bins/legion/tests/research_cli.rs` | 971 |
| `engine/bins/legion-dev/src/checks/skill_evals.rs` | 948 |
| `engine/bins/legion/tests/m2_plugin_root.rs` | 887 |
| `engine/bins/legion/src/commands/freeze.rs` | 881 |
| `engine/bins/legion-dev/src/apple_skill_integrity.rs` | 782 |
| `engine/bins/legion/src/commands/freeze_git.rs` | 779 |
| `engine/bins/legion/tests/cli_truthfulness.rs` | 772 |
| `engine/bins/legion/tests/audit_artifacts.rs` | 767 |
| `engine/bins/legion/src/commands/freeze_consumer.rs` | 766 |
| `engine/bins/legion/src/commands/hooks.rs` | 713 |
| `engine/bins/legion/tests/m1_vertical_slice.rs` | 656 |
| `engine/bins/legion/src/commands/run.rs` | 633 |
| `engine/bins/legion/tests/audit_journal_cli.rs` | 615 |
| …77 more (see JSON) | |
