# Audit advanced manual

```text
MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Re-runnable audit report plus bounded findings.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: audit_engine
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen audit checks finish with evidence-backed findings or typed degradation.
```

Canonical ownership and decomposition contract:
`docs/BLUEPRINT-AUDIT-ARCHITECT-WORKFLOW.md`.

## When to use

Whole-codebase state audit: secrets / dependency-CVEs / type errors / build & installer hygiene,
plus doc drift, architecture quality (right shape? decompose?), AI-slop, over-engineering, naming,
orphaned files, and schema/contract drift. For a runnable app it also runs a **runtime pass** —
boots the dev server and sweeps every reachable surface for visual, runtime, and performance issues
(e.g. "typing re-renders every tab") that static analysis cannot see.

Do **not** use for single-file or single-PR review (use code review) or to map the current
architecture (use `cortex`). **Out of scope, route elsewhere:** commercial/product-strategy gaps
→ `/marketing`; engineering design gaps → `/architect`; competitive/absorption analysis →
`/research` (never emit uncited competitor claims); explicitly requested multi-model launch
verdicts → `/covenant launch` (the report's `triage_top` + critical count already IS the blocker
list — don't restate it as a verdict).

**Repository versus deployed-surface boundary.** Repository Audit covers the files under the selected
repo root and any runnable surface they start locally — never the inferred health of a live site
whose source moved elsewhere (audit the owning repo separately). For a deployed URL, `/seo audit`
owns crawl/index/schema/CWV evidence and `/audit-visual` owns rendered UI/UX; neither replaces
repository Audit. Cortex documents with `lifecycle.status` `superseded|archived` are provenance
only, excluded from the doc-drift input denominator — history, never a current finding.

**Health is not optimality.** `CLEAN` means the current implementation passed the applicable scanner,
lens, runtime, and test gates. It does not prove every material flow is covered or that stronger
current approaches were considered. When the user asks for "best shape", "best architecture",
"architecturally complete", or equivalent, Audit must consume Cortex's `coverageGaps[]` and route
each material gap through `architect`'s current prior-art `adopt|morph|reject|defer` matrix before the
final response — without that artifact, architecture optimality is **UNPROVEN** even when the health
verdict is CLEAN. For an assessment-only request, consume Architect's read-only Phase-2 matrix and
report the verdict; do not plan or mutate code unless the user also asked to action the result.

**Product-boundary preservation.** Audit the product the canonical contract defines, not only the
subsystem the latest diff touched. For a context-engine target, inventory Compaction/PUSH,
Retrieval/PULL, and Curation/PERSIST; for a repository-understanding system, a doc/claim/path index
without code symbols, relationships, and cross-code/document retrieval is a material `coverageGap`
and `CODE-FELL-SHORT` even when the existing mapper/tests are clean. A healthy implementation of a
narrowed subset is not a healthy whole product.

## How it runs (parallel vs sequential)

A pipeline. Scanners fan out; the build step is the lone serial exception; stages are ordered.

| Stage | Execution |
|---|---|
| 0 · Cortex grounding (if available) | Check freshness; query the current graph + flow inventory; use `.agent/` document/claim artifacts as the verified companion layer |
| 1 · Scanners (`collect-facts.mjs`) | Consume fresh Cortex hygiene facts first; run only missing/stale checks in a **parallel**, bounded pool `min(cpus-1,4)`. Size metrics nominate review candidates; they do not emit architecture findings. |
| 1b · `build` / install check | **Sequential, alone**, after the pool (builds/installs are serial) |
| 2 · Reasoning lenses | After stage 1 (all consume `facts.json`). **Default = parallel native Claude subagents** (one Agent spawn per lens; haiku for mechanical lenses, sonnet for judgment lenses — never opus; see Lens fan-out). Running lenses inline in the main session is the fallback. **NO external model APIs** — no api-worker or any HTTP model provider (locked 2026-07-05: provider limits repeatedly hung runs) |
| 3 · Synthesize → render → open | Sequential |

## Procedure

0. **Ground in Cortex (if mapped).** Run `cortex doctor --json`, then `cortex graph status`.
   Trust generated evidence when doctor is `ready`, or when doctor is `degraded` while the graph is
   explicitly fresh and doctor reports no blocker/error; carry every degradation warning into audit
   constraints/findings instead of treating it as clean. A `missing|stale|broken|corrupt` state, a
   stale graph, or any blocker/error means rebuild/repair before consuming generated evidence.
   When a usable graph generation exists,
   use bounded `graph architecture|search|resolve|neighbors|path|impact` queries to verify finding
   loci and flows. Structural queries default to ranked reference rows under a token budget; use
   `--json` for machine parsing, inspect the freshness stamp, and follow continuation cursors rather
   than requesting an unbounded graph dump.
   For a best-shape/completeness request, `cortex graph flows --complete` is the primary flow
   inventory and `understanding.json.architecture.coverageGaps` is the secondary synthesized queue.
   Every material `partial|missing|undetermined` flow goes onward to Architect.

   Read the tracked portable contract at `<root>/.blueprint/manifest.json` plus the
   `coverage.json` / `contradictions.json` companions; the `.agent/map.json`,
   `understanding.json`, and `verdicts.json` machine-local artifacts remain the
   document/claim layer where present. Every `contradicted`/`stale` verdict is a ready-made
   **doc-drift finding** only after current code evidence re-verifies it. On a large unmapped
   repo, run Cortex first; on a small repo where Cortex is unavailable, record
   `graph-unavailable` and let scanners plus lenses stand alone. Cortex is the current-reality
   producer; Audit is the diagnosis layer.

   Run `cortex hygiene status --json`. When it is `fresh`, ingest
   `.agent/hygiene/facts.json` and exclude those completed checks from Audit scanner fan-out. When it
   is `missing|stale`, run `cortex hygiene refresh --json` (or `--offline` when network probes are
   disallowed) before Audit. Cortex owns cached facts/candidates; Audit still owns severity,
   policy, false-positive adjudication, full ponytail/minimize reasoning, and finding lifecycle.
   Never call a cached `outdated|cargo_outdated|binary_pins` result current unless its
   `refreshedAt`, command, and status are carried into the report.

   For decomposition, assess every runtime candidate in `facts.decomposition.review_candidates` as
   `not-needed|confirmed|undetermined`. A confirmed verdict MUST route through Architect and return a
   complete `decomposition_plan`; an unassessed candidate or confirmed verdict without that plan
   makes the report INCOMPLETE. LOC/bytes are triggers only, never proof. The full renderer-enforced
   assessment discipline — symbol-level sub-span evidence loci, the ≥3×-trigger/high-fan-in
   second-assessor rule, `undetermined` naming its missing evidence, mechanical-split keys, and the
   `architect_decision_ref` workspace-confinement rules (read-only `/audit` writes under
   `<root>/.audit/…`, never `docs/plans/`) — is the canonical workflow doc's contract
   (`docs/BLUEPRINT-AUDIT-ARCHITECT-WORKFLOW.md`); apply it from there, not from memory.

   For scoped lens input selection, `cortex graph candidates --task "<task>"` may supply a
   bounded `ContextCandidateSet v1`. It never narrows the scanner/check denominator, and exact files
   used to verify a finding are still read in full.

   > **Membrane status.** The typed Audit finding store (`<repo>/.audit/audit/findings.jsonl`,
   > provider `audit_provider.py`, `status == open` only) and the typed Architect
   > decision store are live in `main`; Audit still runs standalone directly after Cortex — no
   > planner prerequisite. Cross-machine parity claims stay gated on Mac evidence under
   > `rightcontext-evidence/g2/`; current runtime truth: `membrane/docs/MEMBRANE-STATE.md`.

1. **Detect + collect facts (deterministic).** Run:
   `audit-facts <root>`
   It detects the stack(s), runs every applicable required + present scanner, and writes
   `<root>/.audit/<ts>/facts.json` plus secret-redacted per-check logs. **Read `facts.json` —
   never hand-wave a deterministic check.** Absent tools are `skipped`, never "clean".

   **Clean bar (Quality gate).** `render-report` computes a scanner-driven verdict separate from the
   lens health score: **CLEAN** only when every `lint` (biome/eslint/ruff/clippy) · `types` (tsc/mypy) ·
   `build` check RAN with **0 findings** (0 warnings, 0 errors) — clippy runs `-D warnings` so a single
   rustc/clippy warning fails it. Any finding ⇒ **NOT CLEAN**; a gate tool that is absent/errored ⇒
   **UNPROVEN** (cannot certify — never silently clean). The gate is valid even on a lenses-not-run pass
   and is emitted in the `--agent` summary as `quality_gate` so the audit-fix loop stops only on CLEAN.
   The health score can read "good" while warnings remain — the gate is the literal 0-warnings line.

   **`quality_gate` is ONE gate, and `CLEAN` on it is never the audit's overall verdict.** These are
   different predicates and a single word cannot carry both: a repository can be simultaneously
   `quality_gate: CLEAN`, audit `incomplete`, security `unproven`, runtime `shallow`, tests not run,
   and architecture gaps open. Report the vector, never a scalar:

   ```json
   {"auditStatus":"pass|fail|incomplete|error",
    "gates":{"build":"pass|fail|not_applicable|not_run|error","lint":"…","types":"…","tests":"…",
             "security_static":"…","dependency_risk":"…","supply_chain":"…","runtime":"…",
             "accessibility_automated":"…","visual_review":"…","architecture_assessment":"…",
             "functionality_preservation":"…"}}
   ```

   `auditStatus` is never `pass` while any applicable gate is `not_run` or `error`. Never promote
   `quality_gate` into audit completion, and never let a green quality gate be reported as "the audit
   passed."

   **Evidence receipt — keep the rerun command AND the experiment identity.** A literal rerun command
   is necessary and not sufficient: the same command re-run against a different commit, dirty tree,
   tool version, or vulnerability database is a *different experiment* that can silently disagree.
   This does not reopen the rejected design of hashing findings to prove the agent did its work
   (`references/audit-design-decisions.md` D1 — gameable, self-referential, and defeated by non-deterministic scanner
   output). It records what the run was, so a later rerun can tell "fixed" from "measured
   differently". Per check, persist:

   ```json
   {"tool":"semgrep","toolVersion":"…","rulesetDigest":"sha256:…","command":"…",
    "repositoryRevision":"…","dirtyPatchDigest":"sha256:…","environmentDigest":"sha256:…",
    "databaseSnapshot":"…","exitCode":0,"startedAt":"…","completedAt":"…"}
   ```

   A finding whose receipt lacks `toolVersion` or `repositoryRevision` is `unproven`, not verified.

### CodeRabbit-inspired ergonomics

Local-review scope/diff flags (`--doctor`, `--dir`, `--type all|local|committed|uncommitted`,
`--base`/`--base-commit`, `--filter-dir`, `--agent`) plus the OKF bundle emit and `crypt prep`
lens-input compression are specified in `references/engine-interface.md` §CLI ergonomics. Scope
metadata is advisory context; scanner coverage remains honest — a scoped report must not claim
unscanned checks were clean, and none of this turns `/audit` into single-PR review.

2. **Run the applicable lenses over `facts.json` + the repo — as parallel native Claude subagents,
   one Agent spawn per lens, all in ONE message; inline in the main session is the always-legal
   fallback.** NO external model APIs (locked 2026-07-05). Model routing, structured task bodies,
   secret-safe inputs, and the skel-vs-RAW excerpt-compression split are owned by
   `references/lens-routing.md` — read it before this stage. Each lens is fed its facts (table
   below), then reasons: verify, contextualize, prioritize. A finding MUST point to a real
   `file:line` or an evidence locus in a log. **Security lenses may not emit clean-bill
   language for any check whose `status != ran`** — render the NOT-SCANNED banner instead.

3. **Synthesize.** Dedup across detectors (a finding flagged by a scanner *and* a lens =
   one entry citing both); assign severity; assign fix tier (AUTO/GUIDED/MANUAL); cap each
   lens to ~5 in the body (overflow → appendix); build the top-10 triage.

4. **Emit `report.json`** (shape below) next to `facts.json` — it MUST include `lenses_ran` (only
   lenses that actually produced output; the renderer withholds the health score and stamps the
   report INCOMPLETE otherwise — a scanner-only pass is not an audit).

5. **Render + surface — ONCE, after all findings are folded in.** For a static/library target (no
   runtime pass), render + open here. **For a runnable app, do the runtime + visual pass (step 6) FIRST,
   fold its findings into `report.json`, and render + open only then** — otherwise you open a report that
   is missing the runtime/visual findings. Render + open:
   `audit-report --facts <facts.json> --report <report.json>`
   then `open-for-review <audit-report.md>`.
   **MANDATORY durable-knowledge emit (Skill Output Contract):** after the report is written, run
   `skill-emit report <audit-report.md> --type audit --repo <repo>` —
   emits the findings as OKF concepts into the memory engine (recallable; one human report stays, no
   stray markdown). `facts.json`/`report.json` remain the gitignored machine cache. **Typed store
   is now the authority for planner-side findings (G4):** `audit_provider.py` reads
   `<repo>/.audit/audit/findings.jsonl` and emits real `ContextCandidate` records from
   `status == open` findings — resolved / dismissed / superseded are deliberately suppressed and
   MUST NOT surface to the planner (G4 acceptance rule #3). The OKF emit remains the
   human-recall path; the typed store is the planner path. Findings no longer flatten into
   ordinary memories.

6. **Runtime pass (app-only — runnable apps).** Static analysis reads code at rest; this is the
   only pass that *runs* the app and *measures* behavior. If the target is a runnable app (a
   `qa:browser` script or a dev server exists):
   - Boot it: `pnpm qa:browser` (hidden loopback dev server, `?qa=1` mocks) → URL from
     `.cache/qa-browser/url.txt`. For a plain dev server, use its URL.
   - `audit-runtime --url <url> --out <root>/.audit/<ts>/runtime` —
     boots a headless debug browser, waits for the app to actually render (network-idle + interactive
     content settled — not a loading spinner), auto-enumerates SAFE surfaces (tabs / nav links only),
     and per surface captures **visual** (screenshot + layout overflow + console errors), **runtime**
     (JS exceptions / console errors), **performance** — two interaction passes: a TYPING pass (types
     into the main input; scripting-ms/keystroke + long tasks + React commit counts; the "typing
     re-renders every tab" catch) AND a CLICK pass (clicks in-viewport non-destructive in-panel controls;
     scripting-ms/click + long tasks + per-click commit burst; the "clicking a tab re-renders the whole
     tree" catch — destructive labels like delete/send/pay are excluded), and **a11y** (axe WCAG 2 A/AA per surface when `axe-core`
     is resolvable in the target — `npm i -D axe-core` enables it; results in `findings[].a11y[]` +
     `a11y_violations_total`, folded into the report under the `a11y` category. Absent axe-core →
     `a11y_axe: skipped`, NOT a clean a11y bill).
   - **Button/card-driven apps** (the perf-critical surface is behind a click, e.g. an editor behind
     a "New text" card — arbitrary buttons are NOT auto-clicked because actions like "Open file…" hang
     headless on a native dialog): pass `--surfaces targets.json`, a JSON array of click-targets like
     `[{"label":"editor","text":"New text"}]` (`text` = substring match, or `selector` = CSS) to reach
     and perf-test them. Without it the entry route + tabs/nav are all that's covered.
   - **Read the honesty flags, don't mistake them for clean:** the report carries `incomplete:true`
     (app never rendered — stuck loader / unmocked IPC: it tested NOTHING) and `shallow:true` (rendered
     but nothing typeable/navigable was reached — pass `--surfaces`). Neither is a clean bill of health.
   - Fold `runtime.json` findings into `report.json` under the `performance` category, each citing
     `runtime.json` + the surface as evidence and re-runnable via the printed `audit-runtime` command.
   - **Hand off to the visual gate (the e2e seam).** The runtime pass already screenshots every
     surface — that IS the pixel evidence the visual review needs. After the sweep, run **`/audit-visual`**
     over the captured surfaces (`<root>/.audit/<ts>/runtime/*.png` + their URLs): it sends the screenshots
     to the strict rendered frontend/UI audit — the main session judges the screenshots itself (NO external
     vision-model APIs; the old nemotron-omni + Kimi K2.6 jury lane is retired for this flow, 2026-07-05)
     for rendered-reality QA — overflow, broken/placeholder states, contrast, layout regressions, brand drift,
     hierarchy, interaction states, motion, accessibility, and anti-AI-slop that code+runtime checks cannot see.
     Division of labor: `audit` proves **code + runtime health** (does it work, is it secure, is it fast);
     the `/audit-visual` pass judges **rendered UX/UI correctness** on the same surfaces. Fold its
     Blocker-tier findings back into the report under a `ui-ux` category. (Static/library targets with no
     runnable surface skip this — there are no pixels.)
   - **Now render + open (the single, final render).** With `runtime.json` (performance) and the
     `/audit-visual` (ui-ux) findings folded into `report.json`, run `render-report.mjs` +
     `open-for-review.mjs` (step 5). For an app this is the FIRST and ONLY render — the report the user
     opens is now complete with static + runtime + visual findings, not a stale static-only snapshot.
   - **Cold-start smoke (daemon/desktop apps).** The dev-server sweep boots against an EXISTING
     profile; fresh-install bugs (journal-replay panic on empty state, first-run unwraps) hide there.
     For an app with a daemon/backend or local DB, also boot once against a clean slate (empty config
     dir + empty DB — point its data-dir env/flag at a temp dir) and capture the boot log. A
     fresh-state crash is a critical `resilience` finding.
   - **No runnable surface** (plain library/repo) → skip with a note; static lenses still run.
   - *Harness self-check* (only if you touch `audit-runtime.mjs`): run it against
     `_selfcheck/perf.html` (must flag `expensive-typing`) and `_selfcheck/clean.html` (must stay clean).

## Lenses

| Lens | Fed these facts | Gate / threshold | Cross-checked by |
|---|---|---|---|
| `doc-drift` | git diff of docs vs code, README/CLAUDE.md | — | — |
| `architecture` *(widened)* | Cortex `graph architecture`, `graph flows --complete`, relevant `impact|neighbors|path` results, size/symbol/relationship metrics, `facts.decomposition.review_candidates`, synthesized `architecture.coverageGaps[]` when present | **Size is nomination, not verdict.** Assess every runtime candidate as `not-needed|confirmed|undetermined`. Confirm decomposition only when evidence identifies distinct responsibilities, state/side effects, caller/consumer and dependency direction, stable public contracts, test seams, and a cohesion/coupling improvement. Route each `confirmed` case through Architect and fold back the exact keep/extract component map, destination files, moved symbols, public contracts, ordered TDD steps, behavior-preservation checks, risks, and ADR reference. A 420-line cohesive unit may be `not-needed`; a 180-line mixed-responsibility unit may still be found by the lens. Mechanical include-splits are strong review evidence but still do not determine the correct target boundaries. Runtime candidates require assessment; test/tooling candidates are advisory. **Coverage gaps:** ordinary audit reports gaps that contradict a documented/product-required flow; a best-shape audit treats every material `partial|missing|undetermined` flow as open architecture evidence and routes design to `architect`. **quality** only on a named anti-pattern. | `knip`, `tsc`, `facts.decomposition`, `cortex`, `architect` |
| `correctness` *(coderabbit fold)* | changed + oversized + entrypoint files, `tsc`/lint errors, tests | real logic bugs: unhandled errors/rejections, swallowed failures, edge cases (null/empty/boundary/overflow), off-by-one, races / missing `await`, resource leaks, incorrect conditionals. Each needs a real `file:line`. This is the bug-review CodeRabbit does (the earlier "CodeRabbit ergonomics" was only the `--dir/--type/--base` flags) | `tsc`/lint, test suite |
| `ai-slop` | `jscpd` dup, lint unused, dead exports | — | `jscpd`, lint |
| `naming` | lint, file listing | — | lint |
| `dead-file` | `knip` orphans / unused deps | cite knip locus or mark `inferred` | `knip` |
| `schema` | `tsc`/`mypy` errors, serialization sites | — | `tsc`/`mypy` |
| `security` | `gitleaks`, `pnpm/npm audit`, `pip-audit`, `cargo audit`, `cargo deny`, `semgrep`, `actionlint`, `hadolint`, `dep_pinning`, `binary_pins` (NO-INTEGRITY-PIN downloads = supply-chain gap), `vendored_deps`, `contract_mirror`, `tauri_capabilities` (broad-grant / exposed-command surface), `cargo_unsafe`, `tool_coverage` | **NOT-SCANNED banner if status≠ran** | the scanners |
| `minimize` *(FULL ponytail)* | deps list, scripts (`package.json`), `knip`/`jscpd`, `facts.decomposition.mechanical_splits`, and **RAW bodies** of suspect files (one-impl abstractions, wrappers, not-wired code) | the FULL 5-tag over-engineering hunt per **`references/ponytail-lens.md`** — `delete` (dead/not-wired/speculative), `stdlib`, `native`, `yagni` (one-impl trait/config/wrapper/one-export file/45-script sprawl), `shrink` (fewer lines, incl. mechanical include-splits). STRICT false-positive discipline (DI/test seams + planned extension are NOT yagni). NOT gated to deps-only | `knip`, `jscpd`, `facts.decomposition` |
| `performance` *(static + runtime)* | source + lint (react perf rules); `runtime.json` if the runtime pass ran | static = the re-render hazard *smell* (cues in `references/lens-cues.md`); runtime findings MUST cite `runtime.json` evidence | eslint react rules + `audit-runtime` |
| `a11y` *(app/web only)* | JSX/HTML/templates, `eslint-plugin-jsx-a11y`, `runtime.json` axe results (`findings[].a11y[]`) | semantic accessibility per `references/a11y-checklist.md` — missing labels/alt, ARIA misuse, focus order / keyboard traps, non-semantic interactive elements, contrast-as-policy. Only runs for a UI target; skip pure-backend/library | `eslint-plugin-jsx-a11y` (static) + **axe-core in `audit-runtime`** (WCAG 2 A/AA per surface, runs when axe-core is resolvable); NOT-SCANNED if both absent |
| `data-safety` *(migrations/SQL **and PII/privacy** in scope)* | migration files, raw SQL, ORM destructive ops, client storage sites, telemetry/analytics init, `tsc`/lint | per `references/migration-safety.md` — irreversible/no-down migration, blocking DDL on a large table, column/table drop = **data loss**, non-`CONCURRENTLY` index, unbatched backfill, `DELETE`/`UPDATE` without a guarded `WHERE`. Plus unbounded retention (history/log/telemetry tables or an outbox with no pruning/orphan sweep) and, when payments/FSM code is in scope: idempotency keys on refund/settlement paths, unique constraint on `(tenant, provider_ref)`, gateway-call-inside-DB-txn, attacker-supplied-tenant-id tracing. **PII & privacy** (any app target): plaintext PII in `localStorage`/`AsyncStorage`/plain SQLite instead of OS keychain/keystore, analytics/telemetry firing before user consent (GDPR/CCPA) or before an EULA/first-run gate, secrets/tokens persisted unencrypted at rest, and **PII leaking into logs/telemetry** (full request bodies, tokens, emails). Runs when the target/diff touches a migration, SQL, a payment/state-machine seam, client-side storage, or telemetry | greppable (migration dirs, DDL keywords, storage APIs, analytics init); high-value, low false-positive |
| `resilience` *(app/daemon targets — trigger: sidecar/child-process/server/queue code present)* | source, `facts.checks[negative_space].meta` (unsafe_sites), runtime pass cold-start result | per `references/desktop-tauri-checklist.md` §5 — sidecar/child death+hang (watchdog, RPC timeouts), crash/corrupt-file recovery, partial-artifact cleanup, graceful shutdown, backpressure, offline/degraded-network static cues (fetch without retry/backoff/last-known-good), observability (persistent structured logs — is a field bug diagnosable post-hoc? no log file in a shipped desktop app is a finding) | greppable (spawn/Command sites, fetch sites, log-init); runtime cold-start smoke |
| `platform-parity` *(trigger: `#[cfg(target_os` or `usePlatform` present)* | per-OS branches, CI workflows, marketing/docs claims | per `references/desktop-tauri-checklist.md` §6 — matrix every per-OS branch × shipped OSes; flag stubs (`Empty`/`unimplemented!`/silent `Ok(())`) behind cross-platform claims, per-OS CI coverage, rule-14 window-chrome/hotkey conformance | `git grep cfg(target_os` (deterministic branch inventory) |
| `release-readiness` *(trigger: publish/signing/updater scripts or `tauri.conf.json` bundle config present)* | publish scripts, `tauri.conf.json`, license/attribution files, `facts.checks[dep_pinning\|vendored_deps\|binary_pins]` (STALE + MANUAL-CHECK pins = shipping outdated bundled binaries; surface each to the user with its upstream latest) | third-party attribution completeness (LGPL/CC-BY notices linked in-app, not just LICENSE-exists), signing symmetry (Windows Authenticode checked wherever Mac notarization is), updater pubkey = suite key + endpoint config sanity (one `curl` for `latest.json` liveness is in scope; auditing deployed infra beyond that is NOT), prod CSP carrying dev origins, entitlements posture, EULA/pricing placeholder sweep | scripts + config are static files; `dep_pinning`/`vendored_deps` scanners |

| `citation-integrity` *(trigger: >1 doc file in scope)* | doc graph (`cites`/`supersedes`/`mentions-code` edges), filesystem, section anchors | doc-vs-**doc** hygiene, distinct from `doc-drift`'s doc-vs-code: cites to nonexistent paths, anchors that moved, links into superseded docs, circular/self cites, cross-doc contradictions, missing `README`/`LICENSE` | path + anchor resolution are deterministic |
| `okf-hygiene` *(trigger: `.agent/okf/` present)* | the OKF bundle at `.agent/okf/` (`index.md` + one markdown concept per file, `type` frontmatter — **not** a JSON manifest), the `type: risk` / `type: contradiction` debt concepts, and their `supersedes` links | the audit consumes OKF as ground truth but never audits it: `open` debt aged >30d, `in_progress` with no linked commit in 30d, `acknowledged` with no owner, supersession chains that never terminate at a `current` concept, contradictions >0 with 0 acknowledged | all fields are structured — objective, read-only; never closes debt |
| `synthesis-consistency` *(trigger: `understanding.json` present)* | `understanding.json`, `verdicts.json`, the graph, `claims.json` | catches a synthesis lying about its own evidence: `coverageGaps: []` while verdicts hold `contradicted` claims; `untested: []` while graph nodes have no `tests` edge; a component citing a file that does not exist; `deadWeight` naming a node with incoming edges; a material gap with no `architect` handoff | cross-checks two artifacts against each other; structural contradictions only, not wording drift |
| `process-discipline` *(trigger: a prior `.agent/` run exists)* | `verdicts.json` (`verifierCount`, `verifierTiers`, `sourceGenerationId`), `phase2-plan.json`, graph manifest, `doctor --full --json` | audits whether the rules were actually followed: single-verifier on a high-stakes/`done`/`shipped` claim, artifact generation mismatch, reuse without a fingerprint, a planned verify entry with no verdict and no reuse, a synthesis dimension missing with no recorded reason, recomputed fingerprint ≠ stored | every cue is a structural field comparison |
| `feature-coverage` *(trigger: feature-flag / plan-tier / env-gate pattern present)* | flag-pattern scan, `capabilityCoverage[]`, OKF `references`, the test set | Pro-gated and flag-gated paths are invisible to ordinary coverage: a gate with no test on both branches, a gate with no `capabilityCoverage` row, `unimplemented!()` inside a gated branch, inconsistent tier checks (`plan === 'pro'` vs `subscription.tier === 'PRO'`) with no normalization | gate discovery is a deterministic pattern scan; does not judge whether a gate is intentional |

**`ai-slop` additionally carries the LLM-fingerprint cues** (2025-26 era failure mode, beyond dup +
unused): comment-to-code ratio >0.6 over a body, generic-name clusters (`handleData`/`processItem`),
a method call on an object where the graph's symbol table has no such method (hallucinated API),
training-distribution rewrites of stdlib (`O(n²)` sort, manual unique, hand-rolled string reverse),
style drift >2σ from the repo baseline, try/catch around every call against a codebase that does not
work that way, and meta-commentary left in source ("let me…", "this will…"). **Highest
false-positive risk in the suite** — cap at `medium` unless a verified correctness impact exists, and
run the counter-question first: *could a competent human have written this on purpose here?* If yes,
downgrade or drop. Cues: `references/lens-cues.md`.

### Lens selection policy — profile decides the required set

Running every applicable lens on every diff is expensive and noisy; a three-file doc change does not
need `security` or `data-safety`. Derive the profile from `git diff --name-only`, take the **union**
when several match, and fail closed if a required lens is `skipped` rather than having explicitly
returned no hits.

| Diff profile | Required lenses |
|---|---|
| Doc-only (`.md`/`.txt`/`.rst`) | `doc-drift`, `naming`, `citation-integrity`, `okf-hygiene` |
| Config-only (`.json`/`.yaml`/`.toml`/`*.config.*`) | `security` (secrets), `release-readiness` if it touches a release surface |
| Code, non-test | `correctness`, `security`, `minimize`, `schema` if types touched, `process-discipline`, `synthesis-consistency`, `feature-coverage` |
| Test-only | `correctness`, `naming`, `ai-slop` |
| Migration / SQL / DDL | `data-safety` **always**, `correctness`, `schema`, `release-readiness` if in the release path |
| New dependency | `security` (CVE + license + pinning), `minimize` (stdlib/native first), `release-readiness` |
| UI (JSX / templates / styles) | `a11y`, `naming`, `performance` (static), `architecture` if a new component, `ai-slop` |
| Public API (export / route / schema) | `correctness`, `schema`, `release-readiness`, `architecture` if the shape changes |
| Performance-targeted | `performance` static + runtime, `architecture` if a hot path, `release-readiness` |

`architecture` also runs on a size trigger or an explicit best-shape request. `dead-file`,
`platform-parity`, `resilience` and `minimize` keep their own existing triggers independent of profile.
Record required-vs-ran explicitly in `lenses_ran`.

**Conditional lenses activate on deterministic triggers, not judgment** — `a11y` (UI target),
`data-safety` (migration/SQL/payment seam in scope), `resilience` (sidecar/child/server code),
`platform-parity` (`cfg(target_os`/`usePlatform` hits), `release-readiness` (publish/signing/updater
config). Record the trigger evidence (the grep hit or file) when a conditional lens runs; when it
does NOT run, its absence from `lenses_ran` must be provably not-applicable (trigger checked, zero
hits), never silently unconsidered.

Ponytail tags for the `minimize` lens: `delete`/`stdlib`/`native`/`yagni`/`shrink` — the FULL hunt,
canonical prompt `references/ponytail-lens.md`. The audit ABSORBS ponytail; never a separate round.

**CodeRabbit absorption + lens cues → `references/lens-cues.md` (canonical).** `/audit` covers
CodeRabbit's entire review surface across existing lenses — running the CLI afterward is redundant;
the class→lens ownership map and the per-lens **cue lists** (high-signal heuristics per lens) live
in that reference. If a CodeRabbit class isn't mapped there, the lens is under-running, not the
audit under-scoped (PR-inline delivery = the built-in `/review` workflow, not a coverage gap). At
lens fan-out, feed each lens its cue section from that reference alongside its `facts.json` slice.

## Scanner registry

The executable check denominator is **`collect-facts.mjs`** — it builds the check set in code at runtime;
`manifest.json` is a human-readable **documentation mirror** of that set (kept in sync by hand; the evals
reference it), NOT a config the runner loads. If you add/remove a check, edit `collect-facts.mjs` and
update `manifest.json` to match — the runner now PROVES the sync every run (`facts.manifest_drift`
lists missing/stale mirror entries; non-null drift is itself a doc-drift finding). Required checks
that are *applicable* but do not reach `ran` set `incomplete=true`. The full check → command →
runs-when registry table (the literal re-run lines the report prints, ~28 checks from `secrets`
through `runtime`) lives in `references/engine-interface.md` §Scanner registry.

## AU20 — planted-finding recall/precision bench

Not shipped in this repo. A prior benchmark harness (`bench/run-bench.mjs` and related scripts) that
measured deterministic-scanner recall/precision against a planted-defect corpus was deliberately
removed. There is no equivalent tooling in this package today.

## Output shape (`report.json`)

The complete JSON shape and field semantics — `lenses_ran`, `constraints_surface`,
`decomposition_assessments`, `triage_top`, per-finding fields (`evidence_strength`
verified|strong-inference|possible · `judgment` objective|interpretive · `status`
open|disputed|resolved|accepted-risk · `caused_by` DAG · `tier` AUTO|GUIDED|MANUAL), and the
`decomposition_plan` completeness rule that otherwise stamps the report INCOMPLETE — live in
`references/engine-interface.md` §Report shape. Emit exactly that shape; the renderer enforces it.

**Evidence-backed constraints surface (before "what's wrong?"):** extract only constraints supported
by repo evidence: deployment/runtime config, package engines, compiler targets, lockfiles, lint rules,
ADRs, documented exceptions, compatibility comments, or explicit user requirements. Every entry
names its evidence locus and status. **Unknown is an acceptable result**; never invent latency
budgets, team skill, scale, or intentional trade-offs. Render this section only when entries exist.
Constraints narrow invalid recommendations (for example, an async or file-split suggestion) but do
not suppress a verified correctness/security finding.

### Coverage-on-the-change (§2A) and trajectory (`render-report.mjs`)

Two renderer-owned additions on top of the report shape above — full contract, matching schema, and
worked examples in `references/coverage-and-trajectory.md`:

- **Per-change coverage rows.** A binary "tests pass" hides that the CHANGED symbols are untested.
  When a lens supplies `report.coverage = { ratio, perFile:[{file,touched,covered,uncovered,tests,
  verdict}] }` (the same shape locked with `/commit`'s diff-scoped gate), `render-report.mjs` renders
  it as report §2A and computes a coverage gate: ratio < 0.8 is `high`, ratio < 0.5 **or** any touched
  file with an empty `tests` array is `critical`, and a missing ratio (no test infrastructure to read
  against) is `UNPROVEN` — never `CLEAN`. This is a READ of the diff against the test set; the lens
  never re-runs tests to compute it. A whole-repo `/audit` pass with no `coverage` field simply omits
  §2A — coverage-on-the-change is diff-scoped, nothing to render against.
- **`audit_diff` trajectory.** A snapshot audit has no sense of direction. `render-report.mjs` itself
  (the runner, not a lens) persists a compact fingerprint digest at
  `<workspace>/.audit/audit-trajectory.json` (override with `--trajectory-history <path>`) and diffs
  the current finding set against it on every invocation: `resolved`/`new`/`aged`/`unchanged`/
  `newly_p0` counts plus `aging_buckets` (`0-7d`/`8-30d`/`31-90d`/`90+d`). Fingerprint = `file:line +
  category + title`, with a rename-tolerant fallback (`category+title+basename(file)`, accepted only
  as a unique 1:1 pairing). First-ever run at a given history path has nothing to diff against —
  `vs_prior_run` is `null` until a second run exists. Both fields land in the Markdown report and the
  `--agent` JSON summary (`coverage_gate`, `audit_diff`).

## Hard rules

- **Read-only in `audit` mode.** Lenses never write, patch, or emit fix artifacts to the repo —
  only the `.audit/` evidence dir + the report are written. Only `audit-fix` mode mutates the tree.
- **Proof = re-run, not trust.** Every deterministic check prints its literal command; the
  user/CI re-runs any line. No content-hashing, no in-agent verify gate.
- **No false-clean.** A security check whose tool is absent is `skipped` + NOT-SCANNED banner.
  Never report "clean" for a scanner that did not run.
- **Evidence required.** Every finding cites a real `file:line` or a log locus. The synthesis
  agent must not invent findings absent from a scanner result or a lens.
- **Prior docs are claims, not findings.** Status/handoff/CODE-HEALTH/gap-analysis/prior-audit docs
  are doc-drift INPUTS to re-verify against code — a finding sourced from one without independent
  code evidence is invalid. (This class produced every false P0 in the 2026-07 six-model bake-off:
  stale audit prose reported as current code findings.) Re-verify before repeating; a prior finding
  that code now disproves is itself a doc-drift finding against the stale doc.
- **Historical docs are not live claims.** A Cortex document explicitly classified
  `lifecycle.status: superseded|archived` remains traceable but does not enter doc-drift, business-
  constant, or public-site claim sweeps. Follow its canonical pointer when repo-local; route an
  external live surface to `/seo audit` for deployed-site SEO evidence and `/audit-visual` for
  rendered UI/UX evidence instead of re-auditing the retired snapshot.
- **Ecosystem facts must be artifact-backed.** Any "version doesn't exist / deprecated / wrong
  major" claim is auto-rejected unless it cites the lockfile, `node_modules/<pkg>/package.json`,
  `cargo tree`, or a live registry query. Model training data is not evidence — cheap API lenses
  hallucinate ecosystem facts and elevate them to P0.
- **Committed-secret claims need git proof.** Before rendering any "secret committed to the repo"
  finding: `git ls-files <path>` (is it tracked?), `git check-ignore <path>` (is it ignored?), and
  `git log --oneline -- <path>` (was it ever tracked?). file:line alone is not enough for this class.
- **Cross-lens contradiction → deterministic adjudication.** Two lenses disagreeing on the same
  locus never both ship — resolve with a deterministic check or repro before rendering; if
  unresolvable, render ONE finding with `status: disputed`, never both sides as fact.
- **INCOMPLETE is honest.** A skipped *required applicable* check stamps the report INCOMPLETE.
- **Secrets stay redacted.** Logs are written by `collect-facts.mjs` with secrets redacted.
- **Decompose/architecture findings route to `architect`** (its full `/covenant` workflow is the
  external design gate) — the loop drives the refactor autonomously, it does not hand `/architect` back to the operator.
  The eyes-gate stays the human VISUAL checkpoint; Council is not a separate manual step here.
- **CLEAN ≠ best shape.** Never promote the scanner/lens health verdict into an architectural
  optimality claim. A best-shape conclusion additionally requires a current Architect prior-art
  matrix covering every material Cortex gap; absent matrix or unresolved `undetermined` gap means
  architecture optimality is UNPROVEN.

## Lens fan-out (native parallel subagents — NO external APIs)

Before Stage 2, read [`lens-routing.md`](lens-routing.md). It owns lens routing,
secret-safe inputs, correctness verification, reconciliation, and fallback. Scanners remain the
source of truth; the main session verifies every rendered `file:line` and owns the final report.

## Audit-fix loop (when told "audit and fix" / `/audit-fix`)

`audit` is read-only. **`audit-fix` is the mutating, closed-loop mode** — it fixes, then RE-AUDITS
to prove the fix landed, and loops until the scanners **and** lenses are actually clean — nothing
skipped, no false "done". No flag is needed: the phrases "audit and fix", "audit and clean up", or
`/audit-fix` select this protocol.

### GoalRoute v2 fix-route gate

Before first nontrivial mutation, validate a Minimize decision/receipt under current audit run
through `lib/minimize/minimize_gate.py` with every new file/dependency declared; then compile GoalRoute and write
`<repo>/.audit/<timestamp>/goal-route.json` plus receipt. Set:

- `STATE_A` = latest gate vector, open finding fingerprints, behavior surfaces, dirty-state evidence;
- `STATE_B` = full clean truth gate from this skill, not merely quality-gate CLEAN;
- hard constraints = functionality preservation, user authority, safe data handling, scope, tests,
  complete applicable audit coverage, and cost;
- candidate paths = 2–3 complete fix sequences, or one with infeasibility proof;
- dependency graph = root causes before findings they cause, using `caused_by`;
- route objective = minimum expected time to verified clean, including retry and regression/rework.

Validate with `lib/goalroute/scripts/validate-route.py`; no patch begins before receipt PASS.
Fix tier controls who may safely apply a fix; it does **not** determine sequence. Prefer safe root-cause
fixes which clear multiple downstream findings. Parallelize only independent file/state clusters.

After every re-audit, compare current finding fingerprints, severity, affected spans, gate vector,
behavior surface, and constraints to route source state. Any material change invalidates route and all
remaining fix steps: recompile GoalRoute from root, issue new receipt, then continue. A semantic user
correction always triggers this path. Dependency-directed scanner/lens invalidation optimizes
verification inside selected route; it never substitutes for route selection.

### Non-negotiable functionality boundary

Audit-fix is about cleaning, optimizing, hardening, simplifying implementation, fixing scanners,
decomposing files, reducing duplication, and removing truly dead code. It must **never** change,
reduce, remove, disable, hide, narrow, or degrade product functionality. Functionality preservation is
the first invariant of the loop.

Removing features is strictly out of scope for `/audit`, `/audit-fix`, decomposition, minimize,
ponytail, dead-code cleanup, architecture cleanup, launch cleanup, "lean launch", and any inferred
"cleanup" request. No agent may infer, understand, or reinterpret audit-fix as permission to remove a
feature.

A feature includes any route family, CLI command, UI surface, tab, panel, crate, public type, setting,
configuration path, license-gated capability, feature-flagged capability, persisted schema/data, generated
client surface, documented behavior, test-covered behavior, or subsystem that was intentionally built.
This remains true even if it is optional, Pro-gated, disabled by default, not advertised at launch,
deferred in messaging, not fully polished, large, over-engineered, awkward to maintain, or poorly wired.

If audit finds a product-facing feature that is large, over-engineered, confusing, inert by default,
poorly wired, not launch-marketed, or document-drifted, the allowed fixes are:

- preserve behavior and improve structure through decomposition/refactor;
- preserve behavior and add or repair tests;
- preserve behavior and fix docs/claims/defaults;
- preserve behavior and make the implementation clearer, safer, faster, or better factored;
- report a product decision as OPEN for the user.

The only deletion allowed inside audit-fix is deletion that cannot affect functionality: unused imports,
unreachable private helpers, duplicate code after preserving behavior, stale generated artifacts that are
regenerated, scanner-proven unused dependencies with no runtime surface, or abandoned scaffolds proven to
have no route/UI/CLI/API/schema/test/documented behavior. When in doubt, preserve it and report it.

If the user explicitly asks to remove a named feature, that is no longer ordinary audit-fix; treat it as
a separate feature-removal task scoped exactly to the user's named target. Do not broaden it to adjacent
features. If the user says "audit fix" after naming a removal target, audit-fix may clean the aftermath
of that exact removal, but it still may not remove any other functionality.

Before any nontrivial fix, record the behavior surface that must be preserved: public routes, CLI
commands, UI tabs/panels, generated client helpers, public types, config keys, persisted schemas, and
documented behavior touched by the change. After the fix, verify those surfaces still exist unless the
user explicitly named that exact surface for removal. A passing build/test is not enough; missing
surfaces are functionality regressions even when tests pass.

**The loop terminates on CLEAN or NO-PROGRESS — never on an iteration count.** Keep going
fix→re-audit→fix until either every finding is resolved (clean) or no-progress is proven. A cap of 10
iterations is a runaway backstop only, not the goal.

**No-progress needs more than two identical finding sets.** LLM lens prose varies between runs even
when nothing changed, so byte-identical output is too strict — and identical finding *IDs* are too
loose, because they hide a severity drop or a partial remediation. Decide no-progress on stable
finding fingerprints plus movement: same fingerprint set AND no severity reduction AND no shrink in
affected-span count across two iterations. Record the fingerprint set per iteration so the loop's
termination is auditable rather than asserted.

**Nothing is skipped — but do not silently mutate the machine.** A missing required scanner
(`gitleaks`, `knip`, `jscpd`, `semgrep`, `tsc`, `ruff`/`mypy`, `actionlint`, `hadolint`) is something
to FIX, not a silent skip, and the run must not hide behind INCOMPLETE because a tool was absent.
**But auto-installing them is not the fix.** Unpinned installs mutate the developer's machine, pick
whatever version is current (so two runs are not comparable), can need elevated privileges, can break
PATH, and contradict the local-first promise. Instead emit an **install plan** — tool, exact pinned
version, source, checksum, and the command — and require explicit authorization once, unless a
managed audit toolchain (container / Nix / uv / checksummed binaries) is already selected. Until the
tool is present, its checks are `skipped` and the affected gate is `unproven`; that is an honest
INCOMPLETE, not a hidden one. Verified on this Mac 2026-07-25: `semgrep`, `actionlint` and `gitleaks`
are present; `ruff`, `knip`, `jscpd`, `hadolint`, `trivy`, `osv-scanner` are absent (clippy via
`cargo clippy`), so this path is live and would otherwise trigger six unpinned installs.

**Do not re-run every lens every iteration.** Deterministic scanners are cheap and reproducible; LLM
lenses are neither. Re-running all lenses after a one-line import fix produces new wording, new
severities, and unrelated new opinions — which manufactures false regressions from model variance and
can make convergence impossible. Use dependency-directed invalidation: re-run the affected
deterministic providers after every patch, re-run a lens only when its evidence dependencies changed,
and run the **full** lens suite once at the final convergence gate. Store each lens's version/model
metadata with its findings so a wording change is distinguishable from a real finding change.

**"Needs human judgment" is NOT an escape hatch for code work.** Decompose (incl. mechanical
include-splits), minimize/ponytail cuts, dead-code removal, and architecture refactors are
**code-quality** findings — when audit-fix / "best shape" was requested they are NOT human-gated.
"Large refactor" does not mean "leave OPEN"; it means **slice it until safe** — take the smallest
reversible slice from Architect's evidence-backed target design, apply it in the working tree,
re-audit, and repeat. Size may trigger the review, but the confirmed responsibility boundaries and
behavior contracts determine the work and its completion.

**The decompose method is `architect` — this is how it gets to the best architecture autonomously.**
When audit-fix is user-requested, the GOAL is to take the app to the best architecture on its own, not
to flag the work. For any `architecture` / `decompose` / `mechanical-split` finding, route to
**`architect`**: it designs the split (2-3 options → ADR decision → file map → TDD steps) and runs
the full `/covenant` workflow as its OWN external gate, and it is built to proceed without waiting for the operator.
Apply Architect's plan slice-by-slice and re-audit after each slice until the confirmed mixed
responsibilities have moved to their target components, dependency direction matches the plan, and
behavior-preservation tests pass. A shallow `include!`/part split is NOT a fix; it changes file size
without implementing the designed boundaries.
Do not hand `/architect`+`/covenant` back to the operator to run manually; that hand-off was the old stall.
When the request says best shape/architecture rather than only decomposition, Architect must also run
its external solution-space gate and record `adopt|morph|reject|defer` for every material Cortex
coverage gap; internal refactoring alone cannot close an unsearched architectural gap.
The loop may only finish with code-quality findings remaining if it hit **no-progress** (two identical
iterations) — and then it reports them OPEN, NOT clean. A confirmed decomposition finding, scanner-
proven dead code, or unused dependency reappearing means the audit is NOT done. A size candidate may
remain when its current assessment is `not-needed`; that is evidence of review, not unresolved debt.
An `undetermined` verdict gets NO such pass in audit-fix: it means evidence was insufficient, and the
loop has the tools to gather it (graph impact, caller traces, characterization tests) — resolve it to
`not-needed|confirmed`, or on genuine no-progress report it OPEN. Undetermined never folds into
"clean".

**Human gate is reserved for non-code risk and product decisions** — never for refactor size. Stop and
ask for: credentials/secrets, payments/billing, legal/compliance, destructive data ops
(drop/delete/migrate prod data), external accounts/services, **business positioning** (pricing, brand
claims, public copy), or any proposed feature/functionality removal. Everything else is the agent's to
fix while preserving functionality.

1. Run the **full** audit — `collect-facts` **AND every applicable reasoning lens** → `report.json`
   (which MUST set `lenses_ran`). A scanner-only pass is NOT an audit and can never be "clean":
   decomposition, AI-slop, architecture, correctness, and minimize all live in the lenses. Skipping
   them = the report renders WITHHELD/INCOMPLETE, not clean.
2. Apply fixes in validated GoalRoute dependency order, using tier as safety/authority classification:
   - **AUTO** — apply automatically; prefer deterministic fixers (`eslint --fix`, `ruff check --fix`,
     `cargo clippy --fix`, `swiftlint --fix`, `ktlint -F`, formatter, dep override + reinstall,
     removing the unused imports/files knip/tsc/cargo-machete identified).
   - **GUIDED** — apply only when the evidence makes the fix unambiguous; else leave for review.
   - **MANUAL** (architecture / **decompose** / **mechanical-split** / minimize) — do NOT shelve. Apply
     in the working tree for the human's review diff: architecture/decompose go **via `architect`**
     (designs the split, Council-gated) → split an oversized OR include-split module into real
     named `mod` boundaries; delete the dead abstraction/not-wired code; cut the ponytail finding.
     Large ones are **sliced** (smallest reversible slice per iteration), never left OPEN by size alone.
    A code-quality MANUAL finding only stays OPEN on genuine no-progress — and that keeps the audit
    NOT-clean. (Human-gated MANUAL = ONLY the non-code-risk/product-decision classes above:
    credentials/payments/legal/destructive-data/external-accounts/positioning/functionality-removal.)
3. **Re-run `collect-facts` AND the lenses AND the tests** — the gate. The loop advances on real
   scanner + lens + TEST results, not the agent's say-so. Size/structure candidates are deterministic;
   decomposition verdicts are evidence-backed architecture judgments. Reassess every runtime
   candidate, require the complete Architect plan for each `confirmed` verdict, and prove the plan's
   behavior contracts. Test/tooling size candidates are advisory unless the lens finds real harm.
   **Run the project's tests** (`pnpm test` / `cargo test` / `pytest` — the repo's own command) after each
   iteration: scanners prove *shape*, only tests prove *behavior survived the refactor*. A decompose/split
   can pass `tsc`+lint+dup and still break behavior — that's exactly what "clean scanners ≠ working code"
   means. **Run the fast/unit suite or the tests covering the changed files; do NOT auto-run
   integration/e2e suites that hit a live DB/network** — those are flagged-not-run (the `prod-db-guard`
   exists because prod data is one command away). If only an integration suite covers the change, say so
   and treat it as user-gated, never silently skip-and-call-clean.
4. Convergence check:
   - **clean** — **NO findings remain at ANY tier (AUTO + GUIDED + MANUAL)** AND `lenses_ran` is
     non-empty AND every runtime decomposition candidate is assessed `not-needed|confirmed` (zero
     `undetermined` — see above) AND required scanners pass
     **AND the test suite is GREEN** → DONE. A confirmed decomposition or other MANUAL finding left
     open, an unassessed candidate, an incomplete target plan, or a failing/needed-but-unrun test means
     **NOT clean** — report it OPEN, never "100/100".
   - **regression** — a fix introduced a NEW finding (new tsc error, new dup) **OR made a previously-passing
     test fail** → revert it, re-tier MANUAL. A newly-red test is the strongest regression signal there is.
   - **no-progress** — same finding set as the previous iteration → stop; surface the remainder as OPEN.
   - else → loop to step 2.
5. On exit, emit a final report with a before→after: what was fixed (with the change), what's still open
   (GUIDED/MANUAL), and the working-tree `git diff`. Run `audit-verify` to prove the final state.
   **Do not `git commit` / `push`** — committing/pushing is a shared action that requires explicit approval.

### Final-response truth gate

Before saying or implying "passed", "clean", "done", "all clear", "100/100", "audit fixed", or
"goal complete", print or summarize the actual audit state from the latest `facts.json`/`report.json`:

- `facts.incomplete`
- every check with `status != "ran"` and whether it was manually covered elsewhere
- `lenses_ran` count/list; if no `report.json` or no lenses ran, the audit is incomplete
- decomposition candidate count, assessment coverage, verdicts (any `undetermined` counts as OPEN for
  a clean/audit-fix claim), and complete target-plan references (each `architect_decision_ref`
  existing on disk)
- open findings by tier/category
- tests run and any required-but-unrun tests
- functionality-preservation check for touched public surfaces
- for any best-shape/completeness claim: Cortex material coverage gaps plus the path to Architect's
  current prior-art decision matrix, including every `defer|undetermined` row

If any value is unknown, missing, skipped without manual coverage, or nonzero for confirmed open
findings, the final wording must be "not clean" / "open", not "passed". It is acceptable to say a
specific gate passed, e.g. "SAST passed" or "tests passed"; never collapse that into "the audit passed".
Likewise, CLEAN with no prior-art matrix may be called internally healthy or hardened, never best-shaped.

Hard rules: code-quality MANUAL fixes (decompose / mechanical-split / minimize / dead-code) go in the
working tree, never committed — large ones are SLICED until safe, not left OPEN by size; only genuine
no-progress or a non-code-risk/product-decision gate (credentials/payments/legal/destructive-data/
external-accounts/positioning/functionality-removal) leaves a finding **OPEN**; never commit/push in the
loop (shared action — explicit approval required).
**Never report "clean" or a health score when `lenses_ran` is empty — a scanner-only pass renders
WITHHELD/INCOMPLETE.** Runtime size candidates must be assessed, but they are not findings by size
alone. Every confirmed decomposition requires an Architect target plan and remains OPEN until that
plan's boundaries and behavior contracts are verified. Test/tooling size candidates are advisory.

## Compatibility note

Older SampleApp asset copies may use `name: repository-auditor`. Public shared invocation is
`/audit`. Locked design decisions: `references/audit-design-decisions.md`.
