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
| `bench/detectors/*`, `run-bench` | `ebb349ae` | `legion-audit/tests/bench_recall.rs` | successor (drift uses a benchmark-local comparator; no production detector) |
| `bench/real-scan.mjs` | `ebb349ae` | none | intentionally dropped |
| Deterministic `drift` (doc-drift) detector and bench class | `ebb349ae` | `engine/crates/legion-audit/tests/bench_recall.rs` compares the first supported `up to N times` doc claim with first `MAX_RETRIES = N` code value for manifest `doc_file`/`file` pairs | successor (benchmark-local single-claim comparator implemented; native CI qualification pending; production `reasoning.doc-drift` remains reasoning based) |
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
| `scripts/run-skill-evals.mjs` (eval corpus validator and six-dimension routing scorer) | `ebb349ae` | `legion-dev check-skill-evals` (structure) and `legion-dev run-skill-evals` (aliases plus optional provenance-bound routing observations; no model runner; output-quality judgments remain `requires-model`) | successor (deterministic scorer restored; live model caller remains intentionally absent) |
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
| `skills/designer/engine/huashu/references/voiceover-pipeline.md`, `skills/designer/engine/huashu/references/audio-design-rules.md`, `skills/designer/engine/huashu/references/sfx-library.md`, `skills/designer/engine/huashu/assets/narration_stage.jsx`, `skills/designer/engine/huashu/scripts/render-narration.sh` | 2026-10-11 Designer audio removal | none — Designer stops at the deck, static visuals and silent rendered video; audio is not a Designer capability | intentionally dropped |
| `legion script designer/narrate-pipeline`, `designer/tts-doubao`, `designer/mix-voiceover`, `designer/add-music`, `designer/render-narration` and their ports `engine/crates/legion-runtime/src/wf_port/r02/narrate_pipeline.rs`, `engine/crates/legion-runtime/src/wf_port/r03/tts_doubao.rs`, `engine/crates/legion-runtime/src/wf_port/w2_006/add_music.rs`, `engine/crates/legion-runtime/src/wf_port/w2_007/mix_voiceover.rs`, `engine/crates/legion-runtime/src/wf_port/w2_007/render_narration.rs`, `engine/crates/legion-runtime/src/wf_port/w2_008/narrate.rs`, `engine/crates/legion-runtime/src/wf_port/w2_008/render_narration.rs`, `engine/crates/legion-runtime/src/wf_port/w2_008/tts_doubao.rs` | 2026-10-11 Designer audio removal | none — routes depended on an unshipped `tts-doubao.mjs` and an unshipped music library and could not succeed | intentionally dropped |
| `skills/writing/specialists/copywriting/references/ad-assets/generative-tools.md` | 2026-10-11 skill sweep | none — vendor tool catalogue with no backing capability in the package | intentionally dropped |
| `skills/seo/extensions/banana/references/seo-image-presets.md` | 2026-10-11 skill sweep | `skills/seo/references/image-gen-assets/seo-image-presets.md` (identical duplicate kept) | successor |
| `skills/tasklist/examples/sage-adjudication.json`, `skills/tasklist/examples/tasklist-authority.packet.json`, `skills/tasklist/examples/tasklist-authority.packet.receipt.json`, `skills/tasklist/examples/tasklist-authority.prompt.txt` | 2026-10-11 skill sweep | none — examples encoded the retired contract-per-dispatch policy | intentionally dropped |

## Designer scripts verified against history (2026-10-11 review)

Each row was checked against the deletion commit and the successor files at HEAD. PARTIAL means the successor ports only part of the behaviour; the successor cell names what is missing.

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `skills/designer/engine/huashu/scripts/html2pptx.js` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_007/html2pptx.rs`, `engine/crates/legion-runtime/src/wf_port/w2_007/html2pptx_extract.js` | successor |
| `skills/designer/engine/scripts/detector/browser/injected/index.mjs` | ebb349ae | `skills/designer/engine/scripts/detector/detect-antipatterns-browser.js` (kept in place; its header names it as the successor) | successor |
| `skills/designer/engine/scripts/detector/cli/main.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/r05/cli.rs`, `engine/crates/legion-runtime/src/wf_port/w2_011/cli_output.rs` | successor |
| `skills/designer/engine/scripts/detector/design-system.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_011/design_system.rs`, `engine/crates/legion-runtime/src/wf_port/w2_011/design_system_fs.rs`, `engine/crates/legion-runtime/src/wf_port/w2_011/design_system_dom.rs` | successor |
| `skills/designer/engine/scripts/detector/detect-antipatterns.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_011/mod.rs` (facade; each re-exported module has its own Rust successor) | successor |
| `skills/designer/engine/scripts/detector/engines/browser/detect-url-cdp.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/r07/detect_url.rs`, `engine/crates/legion-runtime/src/wf_port/r07/browser.rs`, `engine/crates/legion-runtime/src/wf_port/r07/real.rs` | successor |
| `skills/designer/engine/scripts/detector/engines/browser/detect-url.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/r07/detect_url.rs` (PARTIAL: scan path ported; the visual-contrast fallback is not, and returns unavailable) | successor |
| `skills/designer/engine/scripts/detector/engines/regex/detect-text.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_012/detect_text.rs`, `engine/crates/legion-runtime/src/wf_port/r08/detect_text_matchers.rs` | successor |
| `skills/designer/engine/scripts/detector/engines/site/sweep.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_012/sweep.rs`, `engine/crates/legion-runtime/src/wf_port/r08/sweep_live.rs` | successor |
| `skills/designer/engine/scripts/detector/engines/static-html/css-cascade.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_012/css_cascade.rs`, `engine/crates/legion-runtime/src/wf_port/r09/mod.rs` | successor |
| `skills/designer/engine/scripts/detector/engines/static-html/detect-html.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_013/detect_html.rs` | successor |
| `skills/designer/engine/scripts/detector/engines/visual/screenshot-contrast.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_013/screenshot_contrast.rs` (PARTIAL: no production caller; tests only) | successor |
| `skills/designer/engine/scripts/detector/findings.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_013/findings.rs`, `engine/crates/legion-runtime/src/wf_port/w2_014/antipatterns.rs` | successor |
| `skills/designer/engine/scripts/detector/node/file-system.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_013/file_system.rs` | successor |
| `skills/designer/engine/scripts/detector/profile/profiler.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_013/profiler.rs` (PARTIAL: async profiling wrappers profileStepAsync and profileFindingsAsync not ported) | successor |
| `skills/designer/engine/scripts/detector/registry/antipatterns.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_014/antipatterns.rs` | successor |
| `skills/designer/engine/scripts/detector/rules/checks.mjs` | ebb349ae | `engine/crates/legion-runtime/src/l6_designer_checks/css_color.rs`, `engine/crates/legion-runtime/src/l6_designer_checks/pure_checks.rs`, `engine/crates/legion-runtime/src/wf_port/r11/`, `engine/crates/legion-runtime/src/wf_port/w2_013/detect_html.rs`, `engine/crates/legion-runtime/src/wf_port/r09/mod.rs` (PARTIAL: live-DOM adapter variants not ported; they remain in the JS injected for URL scans) | successor |
| `skills/designer/engine/scripts/detector/shared/color.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_014/color.rs` | successor |
| `skills/designer/engine/scripts/detector/shared/constants.mjs` | ebb349ae | `engine/crates/legion-runtime/src/p8_designer/constants.rs` | successor |
| `skills/designer/engine/scripts/detector/shared/page.mjs` | ebb349ae | `engine/crates/legion-runtime/src/p8_designer/page.rs` | successor |
| `skills/designer/engine/scripts/detector/tests/structure/run-structure-smoke.mjs` | ebb349ae | none; no Designer route or skill depends on it. A stale comment in the detector JS still points at it. Its fixtures under `skills/designer/engine/scripts/detector/tests/structure/` are orphaned | intentionally dropped |
| `skills/designer/engine/scripts/hook-lib.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_015/mod.rs`, `engine/crates/legion-runtime/src/wf_port/r12/mod.rs`, `engine/crates/legion-runtime/src/wf_port/r13/mod.rs`, `engine/crates/legion-runtime/src/wf_port/r14/mod.rs` | successor |
| `skills/designer/engine/scripts/lib/design-parser.mjs` | ebb349ae | no successor yet; `skills/designer/engine/scripts/live-browser.js` (line 10439) fetches /design-system.json, which no route serves, so the Design System panel shows its load-failure state | dropped, restoration pending |
| `skills/designer/engine/scripts/lib/impeccable-config.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_016/impeccable_config.rs` | successor |
| `skills/designer/engine/scripts/lib/impeccable-paths.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_016/impeccable_paths.rs`, `engine/crates/legion-runtime/src/wf_port/q_q1/paths.rs` | successor |
| `skills/designer/engine/scripts/lib/is-generated.mjs` | ebb349ae | `engine/crates/legion-runtime/src/p8_designer/is_generated.rs` | successor |
| `skills/designer/engine/scripts/lib/target-args.mjs` | ebb349ae | `engine/crates/legion-runtime/src/p8_designer/target_args.rs` | successor |
| `skills/designer/engine/scripts/live-copy-edit-agent.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_018/copy_edit_agent.rs` | successor |
| `skills/designer/engine/scripts/live-discard-manual-edits.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_018/discard.rs` | successor |
| `skills/designer/engine/scripts/live-manual-edit-evidence.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_018/evidence.rs` | successor |
| `skills/designer/engine/scripts/live/browser-script-parts.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_020/browser_script_parts.rs` | successor |
| `skills/designer/engine/scripts/live/completion.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_020/completion.rs` | successor |
| `skills/designer/engine/scripts/live/event-validation.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_020/event_validation.rs` | successor |
| `skills/designer/engine/scripts/live/insert-ui.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_021/insert_ui.rs` | successor |
| `skills/designer/engine/scripts/live/manual-apply.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_021/manual_apply.rs` | successor |
| `skills/designer/engine/scripts/live/manual-edit-routes.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_021/manual_edit_routes.rs`, `engine/crates/legion-runtime/src/wf_port/r24/http_server.rs` | successor |
| `skills/designer/engine/scripts/live/manual-edits-buffer.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_021/manual_edits_buffer.rs` | successor |
| `skills/designer/engine/scripts/live/session-store.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_021/session_store.rs` | successor |
| `skills/designer/engine/scripts/live/svelte-component.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_022/svelte_component.rs` (the r31 filesystem layer its header cites has no file at HEAD; exports matched by name) | successor |
| `skills/designer/engine/scripts/live/sveltekit-adapter.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_022/sveltekit_adapter.rs` | successor |
| `skills/designer/engine/scripts/live/vocabulary.mjs` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_022/vocabulary.rs` | successor |
| `skills/designer/engine/scripts/modern-screenshot.umd.js` | ebb349ae | restored at original path; `skills/designer/engine/scripts/modern-screenshot.LICENSE.txt` records upstream MIT attribution; `/modern-screenshot.js` serves it through the packaged scripts directory in `engine/crates/legion-runtime/src/wf_port/r24/http_server.rs` | restored; live browser capture route reinstated |
| `skills/designer/scripts/design-gate.mjs` | cae05d40 | `legion script designer/design-gate` (`engine/crates/legion-runtime/src/wf_port/w2_045/design_gate.rs`; lighthouse and axe checks report unavailable, so the gate fails without a waiver) | successor |
| `skills/designer/scripts/open-for-review.mjs` | cae05d40 | `legion script designer/open-for-review` (`engine/crates/legion-runtime/src/wf_port/w2_045/open_for_review.rs`, decision logic from `engine/crates/legion-runtime/src/p7_host/open_for_review.rs`) | successor |

## Other script dispositions verified against history (2026-10-11 review)

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `skills/ads/references/generate-assets/compose-helper.mjs` | 55cab369 | none; no reference at HEAD expects the channel composition helper | intentionally dropped |
| `skills/alchemist/tests/test_posix_runner.py` | ebb349ae | none; it tested the retired run-worker stack, which host-native agents replace | intentionally dropped |
| `skills/alchemist/tests/test_windows_runner.py` | ebb349ae | none; it tested the retired run-worker stack, which host-native agents replace | intentionally dropped |
| `skills/audit-fix/scripts/audit-run.mjs` | cae05d40 | `engine/crates/legion-audit/src/wf_port/wf064/run.rs` (PARTIAL: pure helpers ported; runAuditProviders, executeUnexecutedProviders and main not ported) | successor |
| `skills/audit-visual/scripts/visual-core.mjs` | cae05d40 | `engine/crates/legion-audit/src/native_providers/p11c_experience/visual_core.rs` | successor |
| `skills/audit/scripts/audit-finalize.mjs` | cae05d40 | `engine/crates/legion-audit/src/wf_port/wf064/finalize.rs`, `engine/bins/legion-dev/src/generators/report_to_sarif.rs` | successor |
| `skills/audit/scripts/audit-sandbox.mjs` | cae05d40 | `engine/crates/legion-effects/src/sandbox.rs` (PARTIAL: total network-deny profile only; localhost-allowing profile and nonce receipt not ported) | successor |
| `skills/dispatch/legacy-source/dispatch/scripts/test_validate_dispatch.py` | 03d1928d | `engine/crates/legion-runtime/src/wf_port/r46/cli.rs`, `engine/crates/legion-runtime/tests/r46c1_goal_route.rs` | successor |
| `skills/dispatch/minimize/minimize_gate.py` | ebb349ae | `engine/crates/legion-minimize/src/review.rs`, `engine/crates/legion-minimize/src/decision.rs`, `engine/bins/legion/src/commands/minimize.rs` | successor |
| `skills/dispatch/scripts/test_validate_dispatch.py` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/r46/cli.rs`, `engine/crates/legion-runtime/tests/r46c1_goal_route.rs` | successor |
| `skills/handoff/legacy-source/handoff/scripts/test_transcript_handoff.py` | 03d1928d | `engine/crates/legion-handoff/tests/l1_port_pointer.rs` | successor |
| `skills/handoff/legacy-source/handoff/scripts/test_validate_handoff.py` | 03d1928d | `engine/crates/legion-handoff/tests/l1b_validate.rs` | successor |
| `skills/handoff/scripts/test_transcript_handoff.py` | baf6ee5f | `engine/crates/legion-handoff/tests/l1_port_pointer.rs` | successor |
| `skills/handoff/scripts/test_validate_handoff.py` | ebb349ae | `engine/crates/legion-handoff/tests/l1b_validate.rs` | successor |
| `skills/qa/legacy-source/qa/scripts/qa.mjs` | 03d1928d | `engine/crates/legion-runtime/src/wf_port/r54/` | successor |
| `skills/qa/scripts/qa.mjs` | ebb349ae | `engine/crates/legion-runtime/src/p9_skills/qa.rs` | successor |
| `skills/research/scripts/research-core.py` | cae05d40 | `engine/crates/legion-research/src/research_port/stopping.rs`, `engine/crates/legion-research/src/research_port/query.rs`, `engine/crates/legion-research/src/research_port/failure_taxonomy.rs`, `engine/crates/legion-research/src/research_port/effects.rs`, `engine/crates/legion-research/src/research_port/common.rs` (PARTIAL: 5 of 9 modules ported) | successor |
| `skills/seo/extensions/banana/scripts/batch.py` | ebb349ae | standalone SEO repository: extensions/banana/scripts/batch.py | successor |
| `skills/seo/extensions/banana/scripts/cost_tracker.py` | ebb349ae | standalone SEO repository: extensions/banana/scripts/cost_tracker.py | successor |
| `skills/seo/extensions/banana/scripts/generate.py` | ebb349ae | standalone SEO repository: extensions/banana/scripts/generate.py (content differs from the deleted copy) | successor |
| `skills/seo/extensions/banana/scripts/presets.py` | ebb349ae | standalone SEO repository: extensions/banana/scripts/presets.py | successor |
| `skills/seo/extensions/banana/scripts/setup_mcp.py` | ebb349ae | standalone SEO repository: extensions/banana/scripts/setup_mcp.py | successor |
| `skills/seo/extensions/banana/scripts/validate_setup.py` | ebb349ae | standalone SEO repository: extensions/banana/scripts/validate_setup.py | successor |
| `skills/seo/hooks/pre-commit-seo-check.sh` | ebb349ae | standalone SEO repository: hooks/pre-commit-seo-check.sh (content differs from the deleted copy) | successor |
| `skills/tasklist/engine/validate-dispatch.py` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/r46/cli.rs`, `engine/crates/legion-runtime/src/wf_port/w2_044/` | successor |
| `skills/tasklist/engine/validate-tasklist-legacy.py` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/w2_044/tasklist.rs` (PARTIAL: dispatch-packet and receipt path only; timeline and clock-gap checks, LINES_PER_MINUTE, PARALLEL_LANES_JSON, DEFERRED/DELETED_WORK_JSON, COMPLETE-requires-DONE, goal-route and minimize sibling checks not ported) | successor |
| `skills/tasklist/goalroute/scripts/validate-route.py` | ebb349ae | `engine/crates/legion-runtime/src/wf_port/r46/goal_route_validator.rs` | successor |
| `skills/tasklist/legacy-source/tasklist/scripts/test_validate_tasklist.py` | 03d1928d | `engine/crates/legion-runtime/tests/wf_w2_044.rs` (PARTIAL: timeline cases target checks not ported) | successor |
| `skills/tasklist/minimize/minimize_gate.py` | ebb349ae | `engine/crates/legion-minimize/src/review.rs`, `engine/crates/legion-minimize/src/decision.rs`, `engine/bins/legion/src/commands/minimize.rs` | successor |
| `skills/tasklist/scripts/test_validate_tasklist.py` | ebb349ae | `engine/crates/legion-runtime/tests/wf_w2_044.rs` (PARTIAL: timeline cases target checks not ported) | successor |
| `skills/tasklist/tests/tasklist-entrypoint.test.py` | ebb349ae | none; it validated the retired example packet listed in the 2026-10-11 skill sweep row | intentionally dropped |
| `tools/audit/audit_provider.py` | f2cc5a77 | none; the Membrane context transport it fed is retired (row for Membrane context) | intentionally dropped |
| `tools/audit/audit_store.py` | f2cc5a77 | `engine/crates/legion-audit/src/p12_pipeline/mod.rs` (PARTIAL: finding-ID derivation only; findings store, lifecycle and show CLI not ported) | successor |
| `scripts/ci/native-installed-smoke.mjs` | 1908f4f6 | `engine/xtask/src/native_installed_smoke.rs` | successor |
| `scripts/ci/prepare-unsigned-candidate.mjs` | 1908f4f6 | `engine/xtask/src/prepare_unsigned_candidate.rs` | successor |
| `scripts/lib/skill-frontmatter.mjs` | 1908f4f6 | `engine/bins/legion-dev/src/shared/skill_frontmatter.rs` | successor |
| `scripts/native-cli/capture-node-characterization.mjs` | fc366b5b | none; it served the retired Node CLI. Its frozen outputs stay as data under `tests/native-cli-characterization/` | intentionally dropped |
| `scripts/native-cli/gate.mjs` | 1908f4f6 | `engine/bins/legion-dev/src/native_cli_gate.rs` | successor |
| `scripts/native-cli/inventory.mjs` | 1908f4f6 | `engine/bins/legion-dev/src/generators/native_cli_inventory.rs` | successor |
| `scripts/native-cli/run-installed-parity.mjs` | 1908f4f6 | `engine/bins/legion-dev/src/generators/native_cli_installed_parity.rs` | successor |
| `scripts/native-cli/run-rust-characterization.mjs` | 1908f4f6 | `engine/bins/legion-dev/src/generators/native_cli_rust_characterization.rs` | successor |
| `scripts/native-cli/test-helper.mjs` | 1908f4f6 | none; it served the retired Node product test suite. The successor env contract LEGION_TEST_NATIVE_CLI_PATH is set by `engine/xtask/src/prepare_unsigned_candidate.rs` | intentionally dropped |
| `scripts/release/admission.mjs` | 1908f4f6 | `engine/xtask/src/release/admission.rs` | successor |
| `scripts/release/admission.test.mjs` | 1908f4f6 | `engine/xtask/src/release/admission.rs` (8 Rust test functions replace the six Node cases) | successor |
| `scripts/release/installer-release-chain.mjs` | 1908f4f6 | `engine/xtask/src/release/installer_release_chain.rs` | successor |
| `scripts/release/local-windows-development.mjs` | 1908f4f6 | `engine/xtask/src/release/local_windows_development.rs` | successor |
| `scripts/release/macos/build-installer.mjs` | 1908f4f6 | `engine/xtask/src/release/macos_build_installer.rs` | successor |
| `scripts/release/macos/finalize.mjs` | 1908f4f6 | `engine/xtask/src/release/macos_finalize.rs` | successor |
| `scripts/release/process-boundary.mjs` | 1908f4f6 | `engine/xtask/src/process_boundary.rs` | successor |
| `scripts/release/windows/finalize-installer.mjs` | 1908f4f6 | `engine/xtask/src/release/windows_finalize_installer.rs` | successor |
| `scripts/release/windows/finalize.mjs` | 1908f4f6 | `engine/xtask/src/release/windows_finalize.rs` | successor |
| `scripts/release/windows/qualify-installed.mjs` | 1908f4f6 | `engine/xtask/src/release/windows_qualify_installed.rs` | successor |
| `scripts/release/windows/qualify-installed.test.mjs` | 1908f4f6 | `engine/xtask/src/release/windows_qualify_installed.rs` (PARTIAL: the success-path no-failure-receipt case has no named Rust test) | successor |

## Workspace-era skills (pre-package)

These skills lived at `tools/skills/<name>/` in the parent workspace, not in this repository. Their paths are relative to that workspace root.

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `tools/skills/architecture/` | pre-package (workspace) | `skills/architect` (merged) | successor |
| `tools/skills/architecture-design/` | pre-package (workspace) | `skills/architect` (merged) | successor |
| `tools/skills/review/` | pre-package (workspace) | `skills/council` (merged) | successor |
| `tools/skills/review-self/` | pre-package (workspace) | `skills/council` (merged) | successor |
| `tools/skills/hormozi/` | pre-package (workspace) | `skills/council/references/rubrics/offer.md` (rubric only) | successor |
| `tools/skills/plan/` | pre-package (workspace) | `skills/marketing` (strategy) | successor |
| `tools/skills/competitor/` | pre-package (workspace) | `skills/foundation` (compare) | successor |
| `tools/skills/route/` | pre-package (workspace) | `skills/dispatch` (merged) | successor |
| `tools/skills/swarm/` | pre-package (workspace) | `skills/dispatch` (merged) | successor |
| `tools/skills/jfdi/` | pre-package (workspace) | `skills/alchemist` (merged) | successor |
| `tools/skills/justdoit/` | pre-package (workspace) | `skills/alchemist` (merged) | successor |
| `tools/skills/verification-before-completion/` | pre-package (workspace) | AGENTS.md evidence rule and `skills/oracle` (merged) | successor |
| `tools/skills/morph/` | pre-package (workspace) | none; served the retired preference mining | intentionally dropped |
| `tools/skills/adapt/` | pre-package (workspace) | none; served the retired preference mining | intentionally dropped |
| `tools/skills/claude-api/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/connect/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/contentcreation/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/context-metrics/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/demo-recorder/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/dictate/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/doctor/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/fable/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/file-organizer/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/hatch-pet/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/illustrate/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/image-enhancer/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/invoice-organizer/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/kdp/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/meeting-insights-analyzer/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/mem-recency/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/raffle-winner-picker/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/remotion-best-practices/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/scrapegraph/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/seedance/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/skillopt-sleep/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/token-audit/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/transcribe/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/video-downloader/` | pre-package (workspace) | none; workspace-only, never part of this package | intentionally dropped |
| `tools/skills/test-author/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/file-search/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/script/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/status/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/init/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/brief/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/context-hygiene/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/hooks-automation/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/workflow-automation/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/writing-skills/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/doc-coauthoring/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/internal-comms/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/brainstorming/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/writing-plans/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/hardeningscan/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `tools/skills/review-frontend/` | pre-package (workspace) | none yet; no decision recorded | dropped, restoration pending |
| `engine/crates/legion-audit/src/native_providers/p10_runtime/external.rs` | 2026-10-11 unused audit port removal | none — port had no production caller; no wired successor identified | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p10_runtime/mobile.rs` | 2026-10-11 unused audit port removal | none — port had no production caller; no wired successor identified | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11b_frameworks/mod.rs` | 2026-10-11 unused audit port removal | none — port had no production caller; no wired successor identified | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11c_experience/performance.rs` | 2026-10-11 unused audit port removal | none — port had no production caller; no wired successor identified | intentionally dropped |
| `engine/crates/legion-audit/tests/p10_browser_service.rs` | 2026-10-11 unused audit port removal | none — test exercised only the removed port | intentionally dropped |
| `engine/crates/legion-audit/tests/p10_external.rs` | 2026-10-11 unused audit port removal | none — test exercised only the removed port | intentionally dropped |
| `engine/crates/legion-audit/tests/p10_mobile.rs` | 2026-10-11 unused audit port removal | none — test exercised only the removed port | intentionally dropped |
| `engine/crates/legion-audit/tests/p11b_frameworks.rs` | 2026-10-11 unused audit port removal | none — test exercised only the removed port | intentionally dropped |
| `engine/crates/legion-audit/tests/p11c_experience.rs` | 2026-10-11 unused audit port removal | none — test exercised only the removed port | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p10_runtime/browser_service.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p10_runtime/build_and_runner.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p10_runtime/desktop.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p10_runtime/mod.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11_frameworks/mod.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11c_experience/mod.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11c_experience/safety.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11c_experience/ux.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11c_experience/visual.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/p11c_experience/visual_core.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/tests/p10_desktop.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/tests/p10_build_and_runner.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `engine/crates/legion-audit/tests/wf_wf051.rs` | 2026-10-11 unused audit port removal | none — port had no production caller | intentionally dropped |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/reasoning-release-readiness/clean/release/surface.json` | 2026-10-22 3c11aa76 reasoning corpus repair | none — unused duplicate of release/surface.py; the planted defect lives only in surface.py | intentionally dropped |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/reasoning-release-readiness/planted/release/surface.json` | 2026-10-22 3c11aa76 reasoning corpus repair | none — unused duplicate of release/surface.py; the planted defect lives only in surface.py | intentionally dropped |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/reasoning-architecture/clean/ARCHITECTURE.md` | 2026-10-22 3c11aa76 reasoning corpus repair | none — never in the architecture lens denominator; restore with legion#105 | dropped, restoration pending |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/reasoning-architecture/planted/ARCHITECTURE.md` | 2026-10-22 3c11aa76 reasoning corpus repair | none — never in the architecture lens denominator; restore with legion#105 | dropped, restoration pending |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/legacy-security-adjudication/clean/src/public-config/public.toml` | 2026-10-22 3c11aa76 reasoning corpus repair | none — non-source config outside the security lenses' denominator | intentionally dropped |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/legacy-security-adjudication/planted/src/public-config/public.toml` | 2026-10-22 3c11aa76 reasoning corpus repair | none — non-source config outside the security lenses' denominator | intentionally dropped |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/legacy-security-variant-analysis/clean/src/public-config/public.toml` | 2026-10-22 3c11aa76 reasoning corpus repair | none — non-source config outside the security lenses' denominator | intentionally dropped |
| `scripts/ci/fixtures/audit-reasoning-runtime-accuracy/fixtures/legacy-security-variant-analysis/planted/src/public-config/public.toml` | 2026-10-22 3c11aa76 reasoning corpus repair | none — non-source config outside the security lenses' denominator | intentionally dropped |

## Audit provider removal (2026-10-23)

Owner decision (Adrian, 2026-10-23): "get rid of things we don't need". Removed providers: `code.go`, `code.php-ruby`, `code.c-family`, `security.scanner-brakeman`, `security.scanner-golangci-lint`, `security.scanner-tflint`, `security.scanner-kubeconform`, `security.scanner-kube-linter`. Kept: `code.jvm`, `code.dotnet`, `code.mobile`, `code.python`, `code.javascript`, `code.rust`, `code.long-tail`, `container.iac`.

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `scripts/ci/audit-c-family-sdk-accuracy.py`, `scripts/ci/audit-c-family-sdk-bootstrap.py`, `scripts/ci/audit-c-family-sdk-registration.py`, `scripts/ci/schemas/audit-c-family-sdk-accuracy.schema.json`, `scripts/ci/tests/test_c_family_sdk_adapter.py`, `scripts/ci/tests/test_c_family_sdk_bootstrap.py`, `scripts/ci/fixtures/audit-c-family-sdk-accuracy` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
| `scripts/ci/audit-php-ruby-code-sdk-accuracy.py`, `scripts/ci/audit-php-ruby-sdk-bootstrap.py`, `scripts/ci/php-ruby-sdk-inputs.json`, `scripts/ci/php-ruby-sdk-assets`, `scripts/ci/fixtures/audit-code-php-ruby-sdk-accuracy` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
| `scripts/ci/audit-govulncheck-bootstrap.py`, `scripts/ci/audit-govulncheck-inputs.json`, `scripts/ci/fixtures/govulncheck`, `scripts/ci/fixtures/audit-code-sdk-accuracy` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
| `engine/crates/legion-audit/src/native_providers/code/c_family.rs`, `engine/crates/legion-audit/src/native_providers/code/c_family_native.rs`, `engine/crates/legion-audit/src/native_providers/code/go.rs`, `engine/crates/legion-audit/src/native_providers/code/govulncheck.rs`, `engine/crates/legion-audit/src/native_providers/code/php_ruby.rs`, `engine/crates/legion-audit/src/native_providers/code/php_ruby_commands.rs`, `engine/crates/legion-audit/src/native_providers/code/php_ruby_enrollment.rs`, `engine/crates/legion-audit/src/native_providers/code/rubocop.rs` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
| `engine/crates/legion-audit/tests/real_code_command_accuracy.rs`, `engine/crates/legion-audit/tests/real_php_ruby_code_command_accuracy.rs`, `engine/crates/legion-audit/tests/c_family_sdk_accuracy.rs`, `engine/crates/legion-audit/tests/brakeman_accuracy.rs`, `engine/crates/legion-audit/tests/golangci_accuracy.rs`, `engine/crates/legion-audit/tests/kubeconform_accuracy.rs`, `engine/crates/legion-audit/tests/tflint_accuracy.rs` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
| `bench/corpora/go`, `bench/corpora/php-ruby`, `bench/corpora/c-family`, `src/registry/coverage/language.go.json`, `src/registry/coverage/language.php-ruby.json`, `src/registry/coverage/language.c-family.json` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
| `qualification/provider-accuracy/records/security.scanner-brakeman`, `qualification/provider-accuracy/records/security.scanner-golangci-lint`, `qualification/provider-accuracy/records/security.scanner-kube-linter`, `qualification/provider-accuracy/records/security.scanner-kubeconform`, `qualification/provider-accuracy/records/security.scanner-tflint`, `qualification/provider-accuracy/verification/security.scanner-brakeman`, `qualification/provider-accuracy/verification/security.scanner-golangci-lint`, `qualification/provider-accuracy/verification/security.scanner-kube-linter`, `qualification/provider-accuracy/verification/security.scanner-kubeconform`, `qualification/provider-accuracy/verification/security.scanner-tflint` | 2026-10-23 audit provider removal | none — provider removed (Adrian 2026-10-23: apps don't use Go/PHP/Ruby/C/C++/Terraform/Kubernetes) | intentionally dropped |
