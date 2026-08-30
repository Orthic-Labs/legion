# Canon pipeline + repairs — 2026-08-30

Location: `legion/docs/pending/plans/`. All paths in this document are workspace-rooted
(`D:\Claude`), not legion-repo-rooted, unless prefixed `legion/`.

## Execution state (audited 2026-08-30)

| Item | Status |
|---|---|
| Part A — Blueprint runtime repair | **NOT STARTED** (git hooks still stale cortex copies; 7 probe files present; watcher down; root `map.json` missing) |
| Parts B–I | NOT STARTED |
| Legion docs cleanup (canon adoption, supersession pruning) | DONE 2026-08-30, committed + pushed as `7e98a10268b5ae9953ed6283dc60454c7e257034` |

This plan is the single source of truth for the **canon-pipeline program** (Parts A–I +
absorption checklist). Two companion ledgers track Legion-internal pending work and are NOT
duplicated here:

1. **Capability closure** — generated `legion/docs/pending/README.md`: 95 committed atoms,
   0 closure-proven. Audit verdict 2026-08-30: implementation DELIVERED for 87/95,
   PARTIAL for 8 (`REPAIR_WIRE`: LEG-005, LEG-015, ARC-001, ARC-005, ARC-006, GRD-009;
   evidence dispositions: ARC-002, ARC-009);
   every atom awaits verification + qualification + evidence. The canon is structurally
   sound (`legion:check` PASS, 0 unclassified, no duplicate tuples); closure evidence is
   the outstanding work.
2. **Active dispatch** — `legion/docs/dispatch/2026-08-30-pending-work.json`, executing
   `PENDING-WORK-2026-08-29.md` rev 5 (archived in `legion/docs/provenance/migrations/`).

Consolidated plan from the Blueprint investigation and Sol's review, iteratively source-checked
with known factual corrections incorporated.
Verdict recap: Blueprint's repo-truth stages migrated to Membrane correctly and the Legion skill
removal broke nothing; the comparative-intelligence workflow (Canon) was never built as one
pipeline; the Blueprint runtime is separately broken and must be repaired regardless.

Target pipeline:
`Blueprint (our code) → Canon (best existing code → atoms → bakeoff → reuse/license disposition) → Architect (coherent whole) → Dispatch (waves/lanes) → Legion executes → Oracle`.

## Doctrine — adopting any new mechanism

Every mechanism absorbed into a skill lands as all four, or it is not adopted:

1. **Hot path** — the invariant lives in SKILL.md or a mandatory gate, not only in references.
2. **Reference** — the detailed method loads progressively.
3. **Eval** — a test that fails when an agent takes the shortcut.
4. **Runtime evidence** — the terminal contract emits proof the mechanism actually ran
   (evals prevent regressions; runtime evidence catches per-run silent bypass).

Ownership guardrail for ingesting external "cathedral" documents: Legion owns WHEN/WHO;
the skill owns HOW; Membrane/Blueprint owns current repository truth; Canon owns reference
implementation truth; Architect owns target decisions; Dispatch owns work decomposition;
critics judge choices mid-workflow; Oracle alone judges completion. A proposed mechanism
that changes how a specialist works is absorbable; anything that schedules agents, retains
global memory, becomes a second evidence authority, or issues final validation routes to
its existing owner. Verify the exact ownership contract before relocating an artifact —
never move it because a subsystem's name sounds right.

Recurring primitive (domain-owned schema in Canon, Research, and SEO — never one shared
framework): `requested universe → evaluated universe → unresolved universe → coverage declaration`.

---

## Part A — Blueprint runtime repair (do first; everything downstream reads this truth)

1. **Reinstall git hooks.** `D:\Claude\.git\hooks\post-merge` / `post-checkout` / `post-rewrite`
   are stale pre-rename copies calling deleted `cortex/scripts/cortex-watch.mjs` (silent no-op).
   Copy current hooks from `tools/pipelines/blueprint/git-hooks/`.
2. **Prune `~/.blueprint/watch.json`.** Keep real repos only (`D:\Claude`, `D:\Claude\legion`,
   plus any intentional enrollments); delete the ~50 dead `Temp\membrane-windows-qualification-*`
   / `bp-test*` / `blueprint-cli-contract-*` entries and the duplicate `\\?\` root variants.
3. **Rebuild Phase 1 at both roots.** `blueprint build` then `blueprint doctor --full --json` at
   `D:\Claude` (currently `state: missing`, no `map.json`) and `D:\Claude\legion`.
4. **Restore the watcher.** Watcher crashed 2026-08-27/28 (`generation envelope is missing
   manifest`, `refusing mutable store on shared storage`) around the daemon relocation to
   `Membrane Hub`. Restart the Hub watcher and confirm `blueprint status --json` reports
   `watcherRunning: true` for both roots; diagnose from `.agent/graph/watchman.log` if it
   re-crashes (the envelope error is a real defect, not just a stale process).
5. **Delete debris.** Remove the seven `D:\Claude\blueprint-watch-probe-*` files (failed-startup
   relics from Aug 27).

Acceptance: `watcherRunning: true` both roots; fresh `map.json` at workspace root; a test commit
triggers a hook nudge; `.agent` mtimes advance.

## Part B — Canon: one comparative-intelligence skill (absorb Atom + CompShop)

Canon = create **and** maintain. Keep existing AUDIT / NORMALIZE / RECONCILE as maintenance
modes; add creation stages. Extend the existing vocabulary in
`tools/skills/canon/references/model.md` — do not invent a parallel one.

1. **Install Atom protocol as Canon's creation engine.** Source: `D:\Downloads\Archive-2.zip`
   (SKILL.md, `references/protocol.md`, `scripts/validate_atom_report.py`). Atom's Stage 1/2
   become Canon Stage 2/3. Keep intact: two independent passes, source-only inspection, semantic
   union, immutable canon during comparison, dirty-list reconciliation against source (never
   voting), evidence tuples, batching ≤25 atoms, validator-plus-semantic-review.
2. **Add Stage 0 — Scope plan.** Partition the product into comparison surfaces using the fixed
   hierarchy `Product → Scope → Domain → Atom` (no sub-atoms). A **Scope** exists only when one
   of these materially changes: reference-repo applicability, runtime/deployment boundary,
   platform-native contract, state/data authority, independent lifecycle. Language alone never
   splits the taxonomy. Examples: HeardRight = shared + per-OS overlays; CodeRight =
   daemon/desktop/iOS; Legion & Membrane = semantic subsystems.
3. **Add Stage 1 — Corpus discovery.** Find strongest OSS repos per scope (route search through
   `/research`), reconcile candidates, freeze exact commits into the corpus manifest, then hand
   to Stage 2. Overlap across scopes is fine; no fixed repos-per-platform quota.
4. **Atom split test (standardize the criterion, not the count):** an atom is the smallest
   independently meaningful product/reliability contract *for which another implementation could
   reasonably be the better implementation*. Different possible winners → split; necessarily
   shared state machine/caller/failure semantics → keep together. Use NORMALIZE mode to bring
   drifted canons (CodeRight daemon vs desktop) to this standard.
5. **Add Stage 4 — Reuse + license disposition, layered.** License facts first, policy second:
   store observed license/SPDX identity, evidence location, and obligations; derive permitted
   actions under project reuse policy (`License evidence → obligations → project policy →
   permitted reuse actions`); `COPY_ALLOWED / DEPENDENCY_ALLOWED / REFERENCE_ONLY` is the
   *derived* execution policy, never the license model (MIT/Apache/MPL/LGPL/GPL/AGPL do not
   collapse into one binary; a translated port may still be derivative). Extend `Action`
   vocabulary to `ADOPT`, `DIRECT_PORT`, `TRANSLATE_PORT`, `BEHAVIORAL_REIMPLEMENT`, `COMPOSE`,
   `GREENFIELD`. Dispatch consumes the derived decision only — it never interprets licenses.
6. **Universe vs target, bounded.** "Complete" means complete relative to frozen
   `Scope × Corpus × Applicability Map`, with declared unresolved coverage — Canon finishes
   with `requested / evaluated / unresolved (with reason) / excluded`, never an impossible
   global claim. Provenance (`USER_REQUIRED`, `CURRENT_PRODUCT`, `REFERENCE_CANDIDATE`,
   `EXCLUDED`) maps onto existing Scope/REFERENCE/EXCLUSION registers. Architect, not Canon,
   decides which atoms the product owns.
7. **Legion-mediated Research transition.** Canon never calls skills itself:
   `Canon emits CORPUS_DISCOVERY_REQUIRED → Legion routes Research → Research returns frozen
   corpus evidence → Canon resumes Stage 2` (same ownership correction as Writing's dropped
   DELEGATED mode).
8. **Corpus saturation, not quotas.** Stage 1 freezes the corpus on evidence of saturation:
   applicable production implementation, inspectable source, meaningful mechanism diversity,
   diminishing unique-atom/mechanism yield — with a recorded stop reason.
9. **Stable atom identity/lineage.** Verify (and add if absent) stable atom keys plus
   merge/split/alias lineage across NORMALIZE and RECONCILE, so a persistent Canon cannot
   rename or split an atom and silently break historical bakeoff/Dispatch references.
10. **Canon receipt + freshness.** A Canon receipt fingerprints: product/scope, relevant
    target commit for existing software, scope-affecting requirements/ASRs, platform/runtime
    set, corpus repos + exact commits, exclusions, and Canon protocol/schema version. A
    material fingerprint change invalidates only affected scopes. Orchestration state is
    explicit: `ARCHITECT → CANON_REQUIRED(scope, reason) → LEGION → CANON → CANON_RECEIPT →
    ARCHITECT_RESUME(phase 5.5)` — this is the literal answer to "who runs the stages, when,
    and what triggers them," and it prevents Architect↔Canon recursion.
11. **Retire CompShop** into Canon (temporary alias to `/canon compare` if desired); fold its
    unique doctrine lines (no-README rule, adversarial self-review bound) into the protocol.
    One canonical location; delete divergent copies (`tools/skills/compshop`, Mac copy).
    Canonicalize the name once — on-disk history says `compshop`, original description said
    `CompShot`; pick one and record the alias.

**Execution baseline caveat:** `canon`/`compshop` currently live in the *workspace* repo at
`D:\Claude\tools\skills\` (uncommitted/local), while packaged Legion skills live in the
*legion* repo at `legion/skills/` — the Orthic-Labs/legion `main` shows only the latter.
Before execution, record the exact working tree + commit baseline for every file this plan
touches so no agent patches the wrong copy, and decide where Canon's canonical home is
(packaged Legion skill vs workspace skill).

## Part C — Architect

1. **Add Phase 5.5 — Reference Canon Gate** (between risk and candidates). For greenfield,
   material subsystem redesign, cross-platform surfaces, "best possible shape" requests, or any
   decision where mature comparable OSS exists: candidate generation is blocked until a fresh
   Canon exists or a bounded search proves no useful corpus exists. "Fresh" is defined by the
   Canon receipt fingerprint (Part B item 10) — unchanged fingerprint = fresh, no rerun;
   material change invalidates only affected scopes. Not applicable to trivial work.
2. **Feed Phase 6.** `doctrine/architecture/workflow/06-candidates.md` currently reads
   `["drivers","risk","current state"]`; add Blueprint current-state and Canon reference
   evidence as inputs; candidates become build/buy/adopt/port/compose/greenfield.
3. **Doctrine additions:** canon-first gate (product-scoped architecture without an atom canon
   starts by creating one) and donor-port doctrine (find the best OSS implementation before
   designing from scratch — aligns with MINIMIZE: NOT_BUILD → REUSE before MIN_CUSTOM).
4. **Fix the eval bug.** `evals/evals.json` → `ad-best-shape-prior-art-gate` expected behavior
   must require discovering/inspecting prior art, not merely "uses current evidence." Add a
   negative eval proving small work does *not* trigger the gate.
5. **Rename** doctrine template `canon-map.md` → `ownership-map.md` (collision with `/canon`).

## Part D — Dispatch (keep separate)

1. Dispatch consumes Canon's reuse + license disposition; it never independently decides
   "source exists → port it." Amend `skills/dispatch/SKILL.md` step 3: port-first applies only
   under `COPY_ALLOWED`; `REFERENCE_ONLY` sources permit behavioral reimplementation only.
2. No structural changes — waves/lanes/one-owner-per-file/integration-owner mechanics stay.

## Part E — Designer (plug the draft exit)

Two independent axes replace the current draft/ship conflation: **mode** (artifact fate) and
**divergence tier** (required exploration). The current contradiction — parametric contract
demands `k ≥ 3` while draft mode legally skips the exploration machinery — is what let agents
optimize for minimum effort.

1. **Divergence tiers (work-driven, not mode-driven):**

   | Tier | Work | Required exploration |
   |---|---|---|
   | T0 — Corrective | resize, alignment, exact spec fix, mechanical adaptation | no concept divergence; render + inspect still mandatory |
   | T1 — Local | component polish, small visual improvement | ≥3 cheap parameter/direction alternatives, not three complete builds |
   | T2 — Material | screen/page redesign, significant new surface | ≥3 genuinely divergent concepts + critic + context simulation + rendered exemplar |
   | T3 — System/Identity | design system, product identity, major launch surface | ≥3 full directions across multiple axes + reference DNA + novelty/familiarity controls + extensive states + critic + regression record |

2. **Mode is orthogonal:** `DRAFT` = exploratory/non-production artifact; `SHIP` = intended to
   alter or become the product. A real product redesign never becomes draft because the prompt
   said "show me something" — repo-touching work defaults to ship; draft is explicit opt-in and
   never selectable because it's cheaper. Tier is set by the work, in either mode.
3. **Parametric contract onto the hot path.** Compact mandatory version (parameter vector →
   tier-required divergence → critic → penalize default region → record winning vector) moves
   from `references/manual.md` §66 into `SKILL.md`.
4. **Two critics, not one.** Pre-convergence critic (compares directions, helps select) is a
   Legion-routed critic work unit — Designer emits the requirement, Legion schedules it, which
   also resolves `CHILD_AGENTS_MAX: 0`. Oracle stays completion-only; it is never a generic
   second-opinion agent.
5. **Absorb from the design-router doc:** reference DNA with `transfer`/`do_not_transfer`,
   familiarity floor + novelty budget, context simulation (feed/device/print-distance), and
   revision regression tracking (every fix records what it damaged).
6. **Evidence-based terminal + evals** per the adoption doctrine: terminal emits mode, tier,
   winning vector, divergence proof, critic reference, rendered inspection; evals assert
   tier selection, vector existence, genuine divergence, separate critic — the current suite
   checks routing and screenshots only.
7. **Mode/tier ownership:** `Legion freezes intent/constraints → Designer deterministically
   classifies mode + tier → emits DesignPlan receipt → Legion freezes that receipt into
   downstream packets`. Tier is Designer method (skill owns HOW); user intent can force draft
   ("rough concepts only") and production fate can force ship — but an executor can never
   downgrade a tier because it is cheaper.
8. **Rationale→artifact verification (T2/T3 terminal).** A design claim ("the CTA is visually
   dominant") is not evidence: `design claim → implementation locator → rendered evidence →
   verified finding`. The terminal contract requires locating the implementation and rendered
   region that demonstrates each material rationale claim.
9. **Bounded stopping.** Designer stops when hard gates pass, no material major finding
   remains, and the next revision has low expected net gain; each tier supplies a bounded
   default critique budget (roughly T0 0–1, T1 1–2, T2 2–3, T3 3–4 cycles; hard failures
   always trigger correction). Directly targets the observed rework-loop failure mode.

## Part F — Legion routing

1. Add automatic Canon dependency for qualifying architecture work (the Phase 5.5 triggers), so
   Legion inserts Canon before Architect invents solutions. Canon is a capability in the routing
   tree, not a new orchestration authority; Legion remains the only lead.
2. Do **not** resurrect `/blueprint` as a skill; repo truth stays Membrane's, reached through
   the packet adapter (`legion/src/adapters/blueprint-packet.mjs`, intact).

## Part G — Writing (precedence + semantic invariants)

Verified 2026-08-30: no existing evidence taxonomy in `legion/skills/writing` (the claimed
`SOURCE_LOCKED/RESEARCH_BACKED/COMMON_KNOWLEDGE` classification does not exist anywhere in
Legion) — both axes below are new work.

1. **Two orthogonal axes**, not five execution modes:
   `Operation: TRANSFORM | DRAFT | CO_WRITE | HIGH_STAKES` × `Evidence: SOURCE_LOCKED |
   RESEARCH_BACKED | COMMON_KNOWLEDGE`. No DELEGATED mode — delegation belongs to Legion;
   Writing declares `RESEARCH_REQUIRED` and Legion routes `/research`. Specialists never
   grow their own orchestration vocabulary.
2. **Precedence ladder** (deterministic editor-conflict resolution): locked facts / source
   fidelity → locked meaning, claim direction & certainty → explicit task requirements →
   channel/genre → audience → voice → structure → sentence/line craft → anti-slop
   preferences. ("Locked facts," not "truth" — Writing also handles fiction, transformations,
   and source-bound material.)
3. **Semantic checkpoint with concrete invariants:** any structural or stylistic pass that
   mutates names, numbers, dates, quotes, attribution, negation, causal direction, scope,
   degree of certainty, required claims, or forbidden claims without explicit authorization
   fails. Check after substantive rewrite AND after voice/line/anti-slop passes.
4. Anti-slop stays a late diagnostic, never the theory of writing.

## Part H — Research (diff runtime, then patch only real gaps)

Contract/doctrine in the skill root is largely the desired shape; runtime is partially
verified: `src/lib/research-core/retraction.py` (fresh DOI retraction via OpenAlex/Crossref),
`failure_taxonomy.py`, and staged `manifest.py` (`citecheck`/`retraction`/`patch`/`ship`)
exist; literal `ResearchBrief`/`stop_reason` constructs do not.

1. Diff the runtime (`legion research --help`, route schema, research-core) against the
   canonical doc for: atomic request-coverage denominator, independence clustering
   (syndication / same-primary-source ≠ independent), contradiction/gap records with
   dispositions, stop-reason vocabulary.
2. Patch only proven gaps; add eval coverage for mechanisms that exist but are untested.
3. Benchmark/new-evidence protocol lands as a conditional reference for engineering
   questions — never mandatory ceremony per request.

## Part I — SEO (bounded track, last unless business-critical)

1. Control catalogue from the master checklist with provenance (source section, digest,
   review date); verbatim retention only if the material is our own — preserve controls +
   provenance otherwise.
2. Status vocabulary: `PASS | PARTIAL | FAIL | N/A | NOT_TESTABLE | NOT_CHECKED` —
   `NOT_CHECKED` distinguishes sampled/interrupted coverage from fundamentally untestable;
   provider absence never yields PASS or N/A. Coverage declaration per module.
3. Page dispositions (`KEEP/REFRESH/EXPAND/REPOSITION/CONSOLIDATE/SPLIT/REDIRECT/NOINDEX/
   DELETE`) + diagnose-before-write.
4. GSC v2 fixes (dimensionless totals, honest row-completeness) only after inspecting the
   actual scripts — don't turn a document's proposed fix into an assumed bug.
5. Defer: checklist compiler (curate ~30–50 controls manually first) and DataForSEO adapter
   (paid; when a real project needs market data).

## Absorption checklist (content, not architecture — final)

The architecture is frozen; specialist implementations are not content-frozen. When a part
below is implemented, absorb its listed mechanisms through the adoption lifecycle —
`implement skill → absorb mechanism → invariant on hot path → detail in reference → eval →
runtime evidence` — without reopening routing, ownership, or adding subsystems. After this
list, the five source documents are considered mined; further combing recreates the
cathedral problem.

**Cross-cutting (Designer + Writing, i.e. wherever a skill carries heuristic
creative/editorial rules — NOT epistemic invariants like "a search hit is not evidence"):**
classify every such rule as `HARD INVARIANT | CONTEXTUAL HEURISTIC | DEFEASIBLE
ANTI-DEFAULT`. Anti-defaults ("never Inter", "never center") are never universal law —
otherwise anti-slop becomes the next slop.

**Part E — Designer** (items 8–9 are already in Part E's contract):
- design thesis required (no "premium/clean/modern" adjective soup); subject-world grounding;
  signature move (≤1 memorable device per direction);
- preserve/introduce/remove accounting on redesigns — a local redesign never silently becomes
  system-wide;
- pairwise criterion-by-criterion selection over scalar scores; judge disagreement stays
  visible, never averaged;
- three evaluation classes kept distinct: hard gates (binary, never averaged away) vs
  qualitative critique vs outcome evidence; Q/C/O separation (estimated quality ≠ evidence
  confidence ≠ observed outcomes);
- **conditional message strategy** for marketing surfaces (landing/ads/launch/social): freeze
  primary claim, support, proof, objections, desired action, compress/remove permissions;
  co-compose verbal + visual hierarchy. Not required for product screens.

**Part G — Writing:**
- substance diagnostics on the hot path (substitution, negation, so-what, delete,
  information-gain);
- functional outline (every section has a job) + information budget;
- human-origin packet with withhold-prose option for high-authorship work;
  divergence-before-prose (theses/angles/structures); genre playbook shape (objective /
  generative moves / rubric / failure modes);
- **bounded revision control**: each finding carries severity, confidence, expected gain,
  semantic risk; revise in bounded cycles and stop when blockers/majors are gone or the next
  revision has insufficient expected value — prevents critic→rewrite→homogenization;
- extend the existing freeze with `desired_reader_change` + `success_criteria` (and
  `immutable_facts`/`prohibited_claims` if not already covered by the semantic invariants) —
  do NOT implement the cathedral Writing Contract.

**Part H — Research:**
- expected-decision-value stopping (continue only when more evidence could reverse the
  conclusion, materially change confidence/recommendation, reveal a safety/legal issue, or
  close a load-bearing unknown); assurance × scale matrix as reference;
- **conditional operationalization**: compile adjectives into observable criteria before
  retrieval when the question is comparative/performance-shaped ("fast" → cold-start latency
  → p50/p95/p99 → hardware → workload); never on simple lookups;
- **epistemic-role typing**: `OBSERVATION | INFERENCE | MECHANISM | NORMATIVE_JUDGMENT |
  RECOMMENDATION` — recommendations never masquerade as observations (distinct from
  confidence);
- **reconcile before more search**: on contradiction, first test whether time, version,
  jurisdiction, population, workload, metric, method, scope, or primary-vs-secondary
  reporting explains it; only unresolved genuine conflict remains a contradiction — agents
  must not resolve disagreement with another search wave;
- **generalized evidence-gap disposition**: Research may conclude `NEW_EVIDENCE_REQUIRED
  (CONTROLLED_BENCHMARK | EMPIRICAL_STUDY | REPO_MINING | SIMULATION | REPLICATION |
  MONITOR | HUMAN_GATE | PRESERVE_UNRESOLVED)` — it emits the need; Legion routes execution.

**Part I — SEO** (fidelity tiers stay SEO-only; Research keeps assurance×scale instead):
- evidence fidelity tiers 0–4 (static-local → experimental; lower never described as
  equivalent to higher); `OBSERVED/DERIVED/ESTIMATED/HYPOTHESIS/RECOMMENDATION` labels;
- **Evidence → Finding → Recommendation → Action separation**: a finding records
  observed/expected state and never equals a fix; a recommendation references findings and
  carries a falsifier, validation method, leading/lagging measurement, and rollback; an
  action exists only when execution is authorized (baseline, receipt, verification) —
  current `findings.json` collapses finding/fix and must be split;
- **baseline → mutation → outcome verification**: successful process/API response ≠
  successful SEO outcome; deployment, crawling, indexing, rankings, citations, and leads are
  separate states — capture a baseline before mutation and verify actual post-change state
  (full drift tooling deferred).

## Order of execution

Severity-ordered, not ROI-ordered:

1. **A** — Blueprint runtime repair (quick; unblocks repository truth for everything below).
2. **B + C + F** — Canon skill, Architect gate + eval fix, Legion routing: the missing
   orchestration stage; until fixed the system can skip the entire prior-art/atom/bakeoff
   process.
3. **D** — Dispatch reuse/license consumption (small, rides on B).
4. **E** — Designer hot-path + divergence tiers (failure already observed in production).
5. **G** — Writing precedence + invariants (small, bounded, lands correctly).
6. **H** — Research runtime diff, patch proven gaps only.
7. **I** — SEO bounded track.

Oracle completion validation over the doctrine edits; `manage.py sync` + `check` in the same
turn for any `docs/agent-rules/` change; refresh `skills/manifests/*.json` for packaged
Legion skill edits.
