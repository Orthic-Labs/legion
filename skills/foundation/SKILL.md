---
name: foundation
description: "Create, audit, normalize, reconcile, or compare a product's atomic capability foundation. Use for atom inventories, cross-repository implementation bakeoffs, feature ledgers, closure counts, parent-child hierarchies, evidence rows, qualification gates, donor dispositions, or cross-canon standardization. `canon` & `compshop` are retired aliases; `/foundation compare` replaces CompShop."
kind: capability
capabilityClass: domain
discoverability: public
domain: engineering
operations:
  - analyze
  - evaluate
  - produce
effects:
  - source-read
  - artifact-write
hostRequirements: []
metadata:
  legion:
    provenance: legion-authored
    licenseState: licensed
    rightsReceipt: LICENSE
    publish: true
    aliases:
      - canon
      - compshop
---

# Foundation

Foundation creates **and** maintains evidence-backed atomic product canons, then optionally compares implementations per atom across a frozen reference corpus.

Read [references/model.md](references/model.md) completely before every run. Read [references/protocol.md](references/protocol.md) before any creation or comparison stage.

## Modes

Maintenance (existing canons):

- `AUDIT`: classify existing rows & test whether totals are reproducible.
- `NORMALIZE`: preserve IDs/history while migrating into explicit hierarchy, state, & proof ledgers; apply the atom split test to drifted canons.
- `RECONCILE`: challenge current state against live consumers plus exact-state evidence.

Creation & comparison (protocol stages; run only stages the user requests):

- `Stage 0 — Scope plan`: partition the product into comparison surfaces using `Product → Scope → Domain → Atom`.
- `Stage 1 — Corpus discovery`: emit `CORPUS_DISCOVERY_REQUIRED`; Legion routes Research; freeze exact commits on saturation evidence.
- `Stage 2 — Atomic canon`: two independent source-only passes discover the semantic union of atoms; consolidate; reconcile against source.
- `Stage 3 — Implementation comparison` (`/foundation compare`; absorbs retired CompShop): compare every canonical atom across every applicable repository, select best proven mechanism, synthesize combined pattern only when justified, reconcile dirty rows against source.
- `Stage 4 — Reuse & license disposition`: record license facts, derive obligations & permitted reuse actions under project policy.

Never begin implementation comparison before the foundation is reconciled. Foundation never calls other skills itself: corpus search is Legion-mediated (`CORPUS_DISCOVERY_REQUIRED → Research → frozen corpus evidence → Foundation resumes`).

## Counting & closure

One countable atom is one independently observable behavior with one owner & one closure decision. Count only committed `CAPABILITY` rows. Keep groups, implementations, qualifications, evidence, references, exclusions, backlog, & exploratory scope outside capability totals.

For every maintenance mode:

1. Enumerate every table, prose register, implicit row, backlog, & exclusion.
2. Classify each row; retain ambiguity as `UNKNOWN`.
3. Map explicit parents & qualification targets; flag missing IDs, cycles, overlap, & double counting.
4. Separate scope, strategy/donor, implementation, verification, qualification, delivery, & evidence.
5. Derive closure only from delivered implementation, fresh required qualification, required delivery boundary, & no contradictory blocker.
6. Trace sampled claims through requirement → consumer → acceptance → revision-bound evidence → delivery.

Normalization first creates an old-row migration map. Never rename, delete, merge, promote, or upgrade status implicitly; preserve stable atom keys & merge/split/alias lineage so historical bakeoff/dispatch references never silently break. Reconciliation inspects the smallest source surface able to disprove a claim.

## Proof gate (creation & comparison)

Mark a repository/atom pair `Observed` only when all are true: exact production path exists; cited symbol semantically performs the atom; live production caller or consumer is identified; target platform matches the row; claimed state, fallback, persistence, privacy, or test behavior is directly evidenced. Otherwise use `Unclear` or `Not found`. Never force a match to satisfy coverage.

Only operative source proves claims. Never read README, docs, marketing, web pages, issues, benchmark claims, or prior research reports during inspection passes. Preserve unique & minority findings; never majority-vote facts. Run one adversarial self-review per pass, fix defects, then stop — never demand exhaustiveness.

Run `scripts/validate_atom_report.py` against every inventory, comparison, & final report. Automated PASS does not replace semantic review.

## Completion

"Complete" always means complete relative to the frozen `Scope × Corpus × Applicability Map`: report `requested / evaluated / unresolved (with reason) / excluded`, never a global claim. Emit a Foundation receipt per the protocol; a material fingerprint change invalidates only affected scopes.

Maintenance modes return:

```text
Foundation: <name>
Count view: CAPABILITY
Capabilities: <closed>/<total> closed; <open> open
Non-counted: <groups> groups; <implementations> implementations; <qualifications> qualifications; <references/exclusions> decisions
Unclassified: <count>
Verdict: PASS|BLOCK
```

For multi-canon work, repeat this block per canon, then list cross-canon ownership overlaps & unresolved semantic duplicates.

Installed/device/release/soak/capture acceptance is qualification, never capability. Donor/action/phase is metadata, never lifecycle state. If one honest denominator is unavailable, report `not computable`. Never let a producer self-certify closure. Architect, not Foundation, decides which atoms the product owns.
