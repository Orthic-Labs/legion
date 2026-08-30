# Foundation protocol (creation & comparison)

Absorbs the Atom protocol (Atom Stage 1/2 → Foundation Stage 2/3) & retired CompShop (`INVENTORY`/`CONSOLIDATE`/`RECONCILE` map onto Stage 3's independent-pass/consolidate/reconcile steps; `compshop` remains a deprecated alias for `/foundation compare`).

## Stage 0 — Scope plan

Partition the product into comparison surfaces using `Product → Scope → Domain → Atom` per the taxonomy rules in `model.md`. Record requested stages; platforms & shared/platform-specific split; output directory; & comparison criteria supplied by the user.

Default Stage 3 criteria when the user gives none: correctness, native UX, local-first privacy, latency, recovery visibility, accessibility, maintainability, & testability. Popularity is never evidence.

Do not mutate product repositories during Foundation research.

## Stage 1 — Corpus discovery

Find the strongest applicable OSS repositories per scope. Foundation never calls skills itself: emit `CORPUS_DISCOVERY_REQUIRED(scope, criteria)`; Legion routes Research; Research returns frozen corpus evidence; Foundation resumes.

Freeze the corpus on **saturation evidence**, not quotas: applicable production implementation, inspectable source, meaningful mechanism diversity, diminishing unique-atom/mechanism yield — with a recorded stop reason. Overlap across scopes is fine; no fixed repos-per-platform quota. Record repository roots, targets, origins, & exact commits.

### Applicability map

Before source inspection, map each repository target to supported platforms. Platform-incompatible target is `N/A`. Platform-compatible target must be inspected for every applicable atom & reported as `Observed`, `Unclear`, or `Not found`. `Not found` means a scoped production-source search found no mechanism; it never means search was skipped.

Persist applicability in a run-local JSON manifest:

```json
{
  "repo_roots": {"Repository name": "/absolute/source/root"},
  "scope_repos": {"Scope label": ["Repository name"]}
}
```

Use exact repository names from this manifest in every mechanism/evidence cell.

## Independent passes

Use two independent passes when the user requests dual review or when a cross-repository canon materially affects product architecture. Each pass receives the same immutable packet: raw user scope; frozen corpus/applicability map; stage contract; unique output path; explicit ban on sibling/prior output.

Stage 2 may read source only. Stage 3 may additionally read the reconciled canon as immutable taxonomy. Neither pass reads README, docs, root Markdown, marketing, web pages, issues, benchmark claims, prior inventories, expected taxonomies, sibling outputs, or prior research reports. Independent passes create recall; each is imperfect. Run one adversarial self-review per pass — check omissions, unsupported claims, wrong absences, broad rows, copied cells, category leakage, missing repos, malformed tables — fix defects in place, then stop; never demand exhaustiveness & create no separate review artifact.

### Batching

Partition work by platform/domain, normally no more than 25 atoms per batch. After each batch:

1. verify every cited path exists;
2. open cited symbol & confirm atom semantics;
3. trace at least one production caller/consumer;
4. confirm platform target;
5. remove build/cache/generated/test-only contamination;
6. detect copied or repeated cells;
7. downgrade unsupported `Observed`/winner claims.

Only then start the next batch. Merge validated batches into one report after all batches pass.

## Evidence tuple

Every `Observed` mechanism must state repository + platform target; production file + symbol; live caller/consumer; concrete mechanism; relevant state/persistence/fallback; & focused test or safeguard when present.

Do not infer recovery, privacy, persistence, confirmation, or platform support from filenames. Tests prove only the asserted contract & require a corresponding production path.

Forbidden evidence includes `.cache`, `.right-release`, `.fingerprint`, `node_modules`, compiled `target`/`build` output, `DerivedData`, backup exports, agent artifacts, generated reports, fixtures, & unrelated experiments.

## Stage 2 — atomic canon

An atom passes the split test in `model.md`. Categories group atoms; they are not atoms.

Each independent inventory uses:

| Platform | Domain | Atom | Definition / boundary | Source evidence |
|---|---|---|---|---|

Discover the semantic union from operative source; merge synonyms; split behavior when the user/platform contract differs; preserve single-repository atoms; avoid implementation technique in atom names unless the technique is the platform contract; cite terse production evidence; never rank or perform gap analysis during inventory.

Consolidate independent inventories without reopening source, then reconcile disputes against the smallest source surface. Shared atoms list once, then platform-only contracts. Shared means the product vocabulary applies to all targets; it does not claim current parity.

Final canon uses:

| Domain | Atom | Boundary |
|---|---|---|

Include the corpus manifest & reconciliation notes. Assign stable atom keys & record lineage when the canon is persistent (see `model.md`); otherwise add IDs only when the user requests them.

## Stage 3 — implementation comparison (`/foundation compare`)

Stage 3 reads the final canon as an immutable row set; the canon is immutable during comparison. Each independent report contains every canon atom exactly once:

| Scope | Domain | Atom | Repository mechanisms | Best observed | Best combined | Rationale / tradeoffs | Source evidence |
|---|---|---|---|---|---|---|---|

For each applicable repository cell: `Observed` only when the evidence tuple passes; `Unclear` when relevant source exists but operative behavior/consumer cannot be proven; `Not found` only after scoped source search.

### Winner threshold

Use `Best observed` only when one or more mechanisms are proven & the comparison states why they outperform alternatives under fixed criteria. If evidence is insufficient, write `No proven winner`. Stars, file count, apparent complexity, filename specificity, test presence alone, or source-match frequency never determine a winner.

### Combined-pattern threshold

A combined recommendation must be an executable design, not "combine strongest parts": preferred primary path; eligibility/readiness gate; ordered fallback; state transitions; confirmation/evidence boundary; recovery/user-visible failure; privacy/security constraint; & tests needed to prove the contract. Include only parts justified by observed source or explicit engineering reasoning. Label inference.

### Consolidate

Read completed reports, not source. Align by exact canon tuple `(scope, domain, atom)`. Preserve both mechanisms & minority findings. The dirty list contains only contradictory operative mechanisms; a different winner with material product consequence; an unsupported high-impact claim; platform leakage; semantic mismatch between evidence & atom; a generic combined recommendation; a missing applicable repository; or scope/row mismatch. Structural wording differences are not dirty.

### Reconcile

For each dirty row inspect the smallest relevant production paths from both claims. Resolve by merge, split, correction, qualification, or `No proven winner` — never by vote. Final artifact:

| Scope | Domain | Atom | Best observed | Recommended implementation | Why / tradeoffs | Source evidence | Confidence |
|---|---|---|---|---|---|---|---|

Full per-repository cells remain in raw reports. Confidence is High when operative mechanism + consumer + safeguard/test are proven; Medium when mechanism & consumer are proven but failure evidence is incomplete; Low when source support is partial & the recommendation includes inference.

## Stage 4 — reuse & license disposition

Populate the license disposition ledger in `model.md`: observed license/SPDX identity, evidence location, obligations, then the derived permitted reuse actions under project policy, using the extended Action vocabulary (`ADOPT`, `DIRECT_PORT`, `TRANSLATE_PORT`, `BEHAVIORAL_REIMPLEMENT`, `COMPOSE`, `GREENFIELD`). Dispatch consumes the derived decision only.

## Quality gates

Before any pass says complete: exact canon row count; no duplicate tuple; all applicable repos explicit; all paths exist inside the intended source root; no forbidden evidence; no platform leakage; no unrelated keyword-only match; no test-only winner; no copied generic cells; no unsupported winner; atom-specific combined recommendations; valid Markdown.

Run the validator with the corpus manifest so it verifies expected repository names & cited file existence:

```bash
python3 scripts/validate_atom_report.py REPORT.md --mode stage2 --expected-rows N --manifest corpus.json
```

The validator removes the atom label from recommendations before high-risk semantic-signature checks; quoting or prefixing the atom name cannot satisfy the gate. Extend `SEMANTIC_SIGNATURES` when the canon adds a high-risk atom whose wrong category template could still read plausibly. Then adversarially inspect semantic samples from every platform/domain. Structural PASS with semantic failure is failure.

## Completion & receipt

Report: final artifact path; independent report paths; corpus size & commits; row counts; `requested / evaluated / unresolved (with reason) / excluded`; dirty rows resolved/unresolved; validator result; & independent completion-validation result. Never claim completion while any semantic gate fails; never make a global-completeness claim.

Emit a Foundation receipt per `model.md`. Structured export beyond these artifacts is post-research & request-only: never build state/backfill systems, extractors, WALs, rankings, or certification gates as a side effect.
