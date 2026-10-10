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
| Covenant `DISPUTE_REVIEW` mode (`covenant-request-v1` and `covenant-record-v1` schemas, `p9_skills/covenant.rs` `allowed_outcomes`) | 2026-10-10 covenant stances restoration | `DECISION_CHALLENGE` (a disputed finding is a decision challenge) | intentionally dropped (no doctrine or procedure ever defined it) |
| The retired `council` and `jury` skills (explicit multi-vendor Council, revision gate, and fresh Jury; rubric and stance-lens files) | 2026-10-10 covenant stances restoration | `skills/covenant/` stage 1 Council, disposition gate, stage 2 Jury; `references/stances/`, `references/rubrics/`; `/council` and `/jury` aliases | successor (stances and rubrics generalised; vendor routing, provider engine, and private brand rules intentionally dropped) |
| Covenant lens-file text telling a seat to read `doctrine/covenant-seat.md` first, and the retired SEO slash-command and review-CLI block in `references/lenses/seo.md` | 2026-10-10 covenant stances restoration | seats are packet-only; `seo.md` is now a role-card panel and `references/rubrics/seo.md` holds the scoring | intentionally dropped |
| `skills/coder/**` (SKILL.md, agents, dependencies, evals, hooks, references, scripts) | 2026-10-10 coder retirement | Alchemist role (bounded implementation); external Pi/opencode lane dropped: no production run ever used it | successor |
| `skills/manifests/coder.json` | 2026-10-10 coder retirement | Alchemist role (bounded implementation); external Pi/opencode lane dropped: no production run ever used it | successor |
| `legion script coder/api-worker` and `coder/enforce_cheap_review_routing` routes (`engine/bins/legion/src/commands/script.rs`) | 2026-10-10 coder retirement | Alchemist role (bounded implementation); external Pi/opencode lane dropped: no production run ever used it | successor |
| `engine/crates/legion-provider-sdk/src/l1b_port/**` (`execution.rs`, `worker.rs`, `mod.rs`) and tests `l1b_worker.rs`, `u01_execution.rs` | 2026-10-10 coder retirement | Alchemist role (bounded implementation); external Pi/opencode lane dropped: no production run ever used it | successor |
| `engine/crates/legion-runtime/src/p9_skills/coder_hooks_install.rs` and `tests/u01_coder_hooks_install.rs` | 2026-10-10 coder retirement | Alchemist role (bounded implementation); external Pi/opencode lane dropped: no production run ever used it | successor |
| `pi-cli` host capability (`src/registry/capabilities.json`) | 2026-10-10 coder retirement | none: only Coder declared it | intentionally dropped |
| `engine/crates/legion-audit/src/wf_port/q_q6/**`, `engine/crates/legion-audit/src/wf_port/r66/**`, `engine/crates/legion-audit/src/wf_port/w2_058/**`, `engine/crates/legion-audit/src/wf_port/w2_059/**`, `engine/crates/legion-audit/src/wf_port/wf001/**`, `engine/crates/legion-audit/src/wf_port/wf003/**`, `engine/crates/legion-audit/src/wf_port/wf004/**`, `engine/crates/legion-audit/src/wf_port/wf005/**`, `engine/crates/legion-audit/src/wf_port/wf009/**`, `engine/crates/legion-audit/src/wf_port/wf011/**`, `engine/crates/legion-audit/src/wf_port/wf012/**`, `engine/crates/legion-audit/src/wf_port/wf013/**`, `engine/crates/legion-audit/src/wf_port/wf014/**`, `engine/crates/legion-audit/src/wf_port/wf019/**`, `engine/crates/legion-audit/src/wf_port/wf020/**`, `engine/crates/legion-audit/src/wf_port/wf021/**`, `engine/crates/legion-audit/src/wf_port/wf022/**`, `engine/crates/legion-audit/src/wf_port/wf037/**`, `engine/crates/legion-audit/src/wf_port/wf038/**`, `engine/crates/legion-audit/src/wf_port/wf039/**`, `engine/crates/legion-audit/src/wf_port/wf047/**`, `engine/crates/legion-audit/src/wf_port/wf048/**`, `engine/crates/legion-audit/src/wf_port/wf049/**`, `engine/crates/legion-audit/src/wf_port/wf050/**`, `engine/crates/legion-audit/src/wf_port/wf051/**`, `engine/crates/legion-audit/src/wf_port/wf052/**`, `engine/crates/legion-audit/src/wf_port/wf053/**`, `engine/crates/legion-audit/src/wf_port/wf054/**`, `engine/crates/legion-audit/src/wf_port/wf055/**`, `engine/crates/legion-audit/src/wf_port/wf056/**`, `engine/crates/legion-audit/src/wf_port/wf057/**`, `engine/crates/legion-audit/src/wf_port/wf058/**`, `engine/crates/legion-audit/src/wf_port/wf059/**`, `engine/crates/legion-audit/src/wf_port/wf060/**`, `engine/crates/legion-audit/src/wf_port/wf061/**`, `engine/crates/legion-audit/src/wf_port/wf062/**`, `engine/crates/legion-audit/src/wf_port/wf063/**`, `engine/crates/legion-audit/src/wf_port/wf065/**`, `engine/crates/legion-audit/src/wf_port/wf066/**` | 2026-10-10 wf_port prune (docs/audits/2026-10-10-wf-port-wiring.md) | none; kept `wf010` (provider registry) and `wf064` (plan/finalize) | ported but never wired to a command; test-only |
| `engine/crates/legion-audit/tests/wf_w2_058.rs`, `engine/crates/legion-audit/tests/wf_w2_059.rs`, `engine/crates/legion-audit/tests/wf_wf001.rs`, `engine/crates/legion-audit/tests/wf_wf003.rs`, `engine/crates/legion-audit/tests/wf_wf004.rs`, `engine/crates/legion-audit/tests/wf_wf005.rs`, `engine/crates/legion-audit/tests/wf_wf009.rs`, `engine/crates/legion-audit/tests/wf_wf011.rs`, `engine/crates/legion-audit/tests/wf_wf012.rs`, `engine/crates/legion-audit/tests/wf_wf013.rs`, `engine/crates/legion-audit/tests/wf_wf014.rs`, `engine/crates/legion-audit/tests/wf_wf019.rs`, `engine/crates/legion-audit/tests/wf_wf020.rs`, `engine/crates/legion-audit/tests/wf_wf021.rs`, `engine/crates/legion-audit/tests/wf_wf022.rs`, `engine/crates/legion-audit/tests/wf_wf037.rs`, `engine/crates/legion-audit/tests/wf_wf038.rs`, `engine/crates/legion-audit/tests/wf_wf039.rs`, `engine/crates/legion-audit/tests/wf_wf047.rs`, `engine/crates/legion-audit/tests/wf_wf048.rs`, `engine/crates/legion-audit/tests/wf_wf049.rs`, `engine/crates/legion-audit/tests/wf_wf050.rs`, `engine/crates/legion-audit/tests/wf_wf052.rs`, `engine/crates/legion-audit/tests/wf_wf053.rs`, `engine/crates/legion-audit/tests/wf_wf054.rs`, `engine/crates/legion-audit/tests/wf_wf055.rs`, `engine/crates/legion-audit/tests/wf_wf056.rs`, `engine/crates/legion-audit/tests/wf_wf057.rs`, `engine/crates/legion-audit/tests/wf_wf058.rs`, `engine/crates/legion-audit/tests/wf_wf059.rs`, `engine/crates/legion-audit/tests/wf_wf060.rs`, `engine/crates/legion-audit/tests/wf_wf061.rs`, `engine/crates/legion-audit/tests/wf_wf062.rs`, `engine/crates/legion-audit/tests/wf_wf063.rs`, `engine/crates/legion-audit/tests/wf_wf065.rs`, `engine/crates/legion-audit/tests/wf_wf066.rs` and fixtures `engine/crates/legion-audit/tests/fixtures/wf_*/**` | 2026-10-10 wf_port prune (docs/audits/2026-10-10-wf-port-wiring.md) | none; `wf_wf010.rs`, `wf_wf064.rs`, `wf_wf051.rs` kept; `audit_conformance.rs` cases 4 and the wf065 half of 10 dropped | tests existed only to exercise the deleted modules |

## Covenant renamed back to Council (2026-10-11)

The Covenant skill, seat, schemas, engine module, script routes and packet marker returned to the
name Council. The deliberation procedure is the original unified Council loop (blind positions,
one peer-debate round, disposition, fresh Jury, at most two complete loops). Old names survive only
as the `/covenant` alias, the `covenant` entry under `seats.council.aliases` in
`src/config/naming-registry.json`, and the `legion bind` migration below.

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `skills/covenant/**` (SKILL.md, agents, assets, dependencies.json, evals, lib/schemas, references/lenses, references/rubrics, references/stances) | 2026-10-11 council rename | `skills/council/**` | successor (renamed; `/covenant` stays an alias) |
| `skills/covenant/lib/schemas/covenant-record-v1.schema.json`, `skills/covenant/lib/schemas/covenant-request-v1.schema.json` | 2026-10-11 council rename | `skills/council/lib/schemas/council-record-v1.schema.json`, `skills/council/lib/schemas/council-request-v1.schema.json` (adds `loop`, seat `round`, finding `contested`/`sustainedBy`, disposition `ruledBy`) | successor |
| `src/packages/contracts/schemas/covenant-record-v1.schema.json`, `src/packages/contracts/schemas/covenant-request-v1.schema.json` | 2026-10-11 council rename | `src/packages/contracts/schemas/council-record-v1.schema.json`, `src/packages/contracts/schemas/council-request-v1.schema.json` | successor (byte-identical to the skill copies) |
| `skills/manifests/covenant.json` | 2026-10-11 council rename | `skills/manifests/council.json` | successor |
| `agents/covenant-seat.md` | 2026-10-11 council rename | `agents/council-seat.md` (host type `legion:council-seat`) | successor |
| `doctrine/covenant-seat.md` | 2026-10-11 council rename | `doctrine/council-seat.md` (adds the debate round) | successor |
| `engine/crates/legion-runtime/src/p9_skills/covenant.rs` | 2026-10-11 council rename | `engine/crates/legion-runtime/src/p9_skills/council.rs` (adds loop, debate-round and sustained-contest validation) | successor |
| `legion script covenant/digest`, `covenant/validate-record`, `covenant/validate-external-review-packet` | 2026-10-11 council rename | `legion script council/digest`, `council/validate-record`, `council/validate-external-review-packet` | successor |
| Packet marker `PACKET_ONLY — DO_NOT_RUN_COVENANT` | 2026-10-11 council rename | `PACKET_ONLY — DO_NOT_RUN_COUNCIL` | successor |
| `COVENANT_REQUESTED:` Sage escalation line; `COVENANT_MODE`, `COVENANT_OUTCOME` enums; blocker status `COVENANT_CONSULTED`; `covenantRequestId`, `covenantRecordId` fields | 2026-10-11 council rename | `COUNCIL_REQUESTED:`, `COUNCIL_MODE`, `COUNCIL_OUTCOME`, `COUNCIL_CONSULTED`, `councilRequestId`, `councilRecordId` | successor |
| `.codex/agents/covenant-seat.toml`, `.gemini/commands/legion/covenant-seat.toml` and the `[agents.covenant-seat]` Codex registration generated by `legion bind` | 2026-10-11 council rename | `.codex/agents/council-seat.toml`, `.gemini/commands/legion/council-seat.toml`, `[agents.council-seat]`; `legion bind --write` removes the old files and registration, keeping an operator-set `model` | successor |
