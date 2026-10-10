# Retirements ledger

Every deleted skill file, script, hook, or rule gets a row here naming its successor or why it was
dropped. Rows below are seeded from the 2026-10-08 system audit
(`docs/audits/2026-10-08/evidence/01-history-parent.md` section 3 and
`evidence/02-history-legion.md` sections 2 and 7). A commit cell reading "see audit" means the
audit evidence file names the epoch but no single commit; fill in the hash when it is known.

Reason column: `successor` means a replacement exists; `intentionally dropped` means no
replacement is wanted; `dropped, restoration pending` means the loss is acknowledged and a
restoration is planned in the audit recovery plan (phase named).

## Code and tooling (Rust port, 2026-09-25 and 2026-09-26)

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `src/lib/**`, `src/providers/**`, `src/packages/kernel`, `scripts/*.mjs`, `tools/audit/*.mjs`, JS CLI (`src/lib/cli/**`) | `ebb349ae`, `1908f4f6` | `engine/crates/*`, `engine/bins/legion`, `legion-dev`, `xtask` | successor |
| `src/packages/context` (Membrane context transport) | `ebb349ae` | `u03/context_transport.rs` returns `unavailable` | intentionally dropped (Membrane is not part of this package) |
| `scripts/check-atomic-canons.mjs` (generator of the pending index) | `ebb349ae` | none; `docs/provenance/pending/README.md` is frozen | intentionally dropped (canon pipeline retired) |
| `scripts/check-authority-parity.mjs` | `ebb349ae` | `legion-dev check-authority-parity` via `pnpm legion:check` | successor |
| `shipped-skill-paths.test.mjs` (no shipped skill may name `src/`, `docs/`, `tools/`, `bench/`, `qualification/`, `tests/` paths) | `ebb349ae` | none yet; `legion-dev check-dependency-closure` covers only script paths | dropped, restoration pending (audit phase 2 dangling-path gate) |
| Hooks `arcane-hook.mjs`, `src/lib/host/arcane/*`, six Python hooks | `ebb349ae` | `engine/bins/legion-hook`, `legion-arcane`, `legion-policy` | successor |
| `bench/detectors/*`, `run-bench` | `ebb349ae` | `legion-audit/tests/bench_recall.rs` | successor (drift class has no native provider) |
| `bench/real-scan.mjs` | `ebb349ae` | none | intentionally dropped |
| Deterministic `drift` (doc-drift) detector and bench class | `ebb349ae` | none | dropped, restoration pending (audit phase 4) |
| Alchemist worker stack (`run-worker.*`, tray, start-stack, model catalog) | see audit (2026-10-03) | host-native agents | intentionally dropped (by design) |
| `skills/content` | see audit (2026-08-18) | workspace skill outside this package | intentionally dropped (by design) |
| `skills/compshop` | see audit (2026-08-18) | `/foundation compare` | successor |
| `skills/cortex` | see audit | `skills/blueprint` (host capability `blueprint-graph`) | successor |
| SEO assurance suite (6 Python test files) and 8 orphaned fixtures | `ebb349ae` | ported logic `wf_w2_028..034`; end-to-end gate not ported | dropped, restoration pending (SEO closure repair) |
| Skill scripts: alchemist `parse_events`/`viewer`, brand-identity `color-check.mjs`, coder `api-worker.py`, covenant validators, dispatch/tasklist/foundation/handoff validators, qa `qa-shot`/`qa-functional`, audit `audit-run.mjs` | `ebb349ae` | `legion script <skill>/<stem>` entries and `legion audit/plan/verify/report` | successor |
| `python-runtime` as a host requirement | 2026-10-08 repair | none; Python is not shipped or needed | intentionally dropped |
| `docs/canon/**` and `docs/pending/**` (live location) | 2026-10-08 repair | moved to `docs/provenance/canon/**` and `docs/provenance/pending/**`; current ownership is `docs/LEGION-CANONICAL-SSOT.md` | successor (frozen history) |

## Original workspace rules (2026-06-10 import, `dc863dea`) that did not survive

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| R1 WebSearch-first for factual, dated, medical, pricing claims; two URLs; say "unverified" | `2e6c7e7e` | `doctrine/arcane.md` Grounding (required for external facts, APIs, versions, prices, current events) | successor |
| R5 Verify-before-propagate: read the source file, cite path and line before multi-file edits on names, amounts, versions | see audit | none | dropped, restoration pending (audit phase 5 item 26) |
| R7 Critique, do not validate: lead with weaknesses | see audit | Review discipline in `doctrine/oracle.md`, `doctrine/covenant-seat.md`, and both agent files (ranked risk plan, two-axis review) | successor |
| R8 Sync docs as part of done, unprompted | see audit | none (only the workspace `manage.py sync` echo) | intentionally dropped |
| R11 Surgical changes; define the verifying check before writing code | `659a2380` | "smallest complete change" in the Legion identity text | intentionally dropped |
| R12 Grounded answers without verification theater | `2e6c7e7e` | `doctrine/arcane.md` Grounding | successor |
| R13 Auto-jury Stop hook (`enforce_auto_jury.py`): artifacts without a verdict file ship blocked | `2e33aa76` | Oracle is optional by design | intentionally dropped |
| R14 Dual-juror video QA, never single-juror | `6d1a6259` | none | intentionally dropped (descoped media gate) |
| R23 Sequential thinking before complex work, Tether then Sentinel | `d641bcab` | contract chain for locked or contracted work only | intentionally dropped as a universal trigger |
| R25 Context7 current-docs lookup | see audit | `doctrine/arcane.md` Grounding routes to Context7 when the host provides it | successor |
| R30 `/review-cli` manual CLI gate | `e7e0c7d6` | optional Oracle | intentionally dropped |
| R32 Open-for-review script before pointing the operator at a file | see audit | none | intentionally dropped |
| R33 Present before acting, wait for go-ahead | `ee9ad355`, reversed 07-19 | explicit, reversible, in-scope request is the authorization | intentionally dropped |
| R36 Visual plans and mermaid recaps for non-trivial work | see audit | none | intentionally dropped |
| R37 Missed-intent correction | see audit | "corrections void affected pending actions" | intentionally dropped |
| R42 Skill-router "even a 1% chance a skill might apply" | see audit | semantic routing over the compact catalog | intentionally dropped (reversed) |
| R45 Subagents must not read `~/.claude/`; close agents after consuming a result | see audit | none | dropped, restoration pending |
| R46 Skill-router loop: clarify, approve design, plan, execute, review, verify | see audit | five-tier routing in `AGENTS.md` | successor |
| `src/lenses/` (11 files) | 2026-10-08 cleanup | dead: no references (`src/registry/lenses/` is the live copy) | intentionally dropped |
| `src/recipes/` (4 files) | 2026-10-08 cleanup | `src/registry/recipes/index.json` (only a doc comment named the old path) | successor |
| `src/evals/ground_truth/` and 37 of 39 `src/evals/architecture/*.jsonl` | 2026-10-08 cleanup | `engine/crates/legion-audit/tests/fixtures/provider_selection_labeled_samples.json` for ground truth; the rest dead: no eval runner or reference (`authority-adoption*.jsonl` kept) | intentionally dropped |
| 112 of 118 `src/schemas/**` files | 2026-10-08 cleanup | dead: no references except provenance fixtures (6 schemas kept: provider-result, security-verdict, web-actor-fixture, book-qualification-v2, untrusted-evidence, judgment-receipt) | intentionally dropped |
| `src/lib/**` except `guard/compat/`, `minimize/POLICY.md`, `host/arcane-compatibility/forge/` | 2026-10-08 cleanup | dead: ~60 documentation/provenance files for code ported to Rust; `contracts/arcane-schemas` is embedded in `legion-policy` `wf068/schemas_arcane` | intentionally dropped |
| `migration/native-rust/` except `fixtures/` (plans, ledgers, `dispatches/`, `m0/`) | 2026-10-08 cleanup | dead: historical evidence, no reader (`fixtures/` kept for `engine/tests/native_audit.rs`) | intentionally dropped |
| `schemas/` 11 of 17 files (agent-definition, analysis-rule-pack, arcane-policy-pack, audit-plan, blueprint-selector, catalog, decision-record, dispatch, host-descriptor, minimize-result, task-list) | 2026-10-08 cleanup | dead: no references | intentionally dropped |
| `.commandcode/` (2 files) | 2026-10-08 cleanup | dead: editor-tool personal preferences, no references | intentionally dropped |
| `packaging/sea/`, `packaging/linux/channels.json` | 2026-10-08 cleanup | dead: no references (Node SEA and Linux archive channel retired) | intentionally dropped |
| `scripts/run-skill-evals.mjs` (eval corpus validator and routing scorer) | `ebb349ae` | `legion-dev check-skill-evals` (structure only; routing and behaviour grading is reported `requires-model`, never passed; live grader and scorer not ported) | successor (deterministic half); model-graded half dropped, restoration pending |
| Retired skill names in `skills/*/evals/**` (`optimize`, `email-pro`, `product-marketing-context`, `changelog-generator`, `offer-and-bio-writer`, `writing-pro`, `growth-*` labels, `canon` label) | 2026-10-08 gates-2 | current names `cro`, `email`, `product-context`, `changelog`, `profile-copy`, `writing`, specialist names, `foundation` | successor (retired names remain only as negative routing targets) |
| `doctrine/bundles/covenant-lenses/` (README + 16 lens files) | 2026-10-10 covenant repair | `skills/covenant/references/lenses/` | moved into the Covenant skill; lens text is embedded in each seat prompt |
| `skills/covenant/evals/legacy-council.json` | 2026-10-10 covenant repair | `skills/covenant/evals/evals.json` | cases folded into the single Covenant fixture; retired council/jury names dropped |
