# Foundation model

Use separate ledgers so hierarchy, work, & proof cannot masquerade as peer features.

## Capability ledger — only counted table

| Field | Values / rule |
|---|---|
| `ID` | Stable, unique, never recycled |
| `Parent` | Optional `GROUP` ID only |
| `Owner` | Exactly one product/runtime surface |
| `Scope` | `COMMITTED`, `EXPLORATORY`, `BACKLOG`, `EXCLUDED`; only committed capabilities enter committed-scope progress |
| `Observable behavior` | User- or operator-observable outcome; no donor, file, test, or implementation wording |
| `Implementation` | `MISSING`, `PARTIAL`, `DELIVERED`, `UNKNOWN` |
| `Verification` | `PENDING`, `FOCUSED_PASS`, `FAIL`, `STALE`, `UNKNOWN`; distinct from runtime/device/release qualification |
| `Qualification` | `NOT_REQUIRED`, `PENDING`, `PASS`, `FAIL`, `STALE`, `UNKNOWN` |
| `Delivery` | `LOCAL`, `COMMITTED`, `PUSHED`, `RELEASED`, `UNKNOWN`; compare with canon's declared required boundary |
| `Action` | Planning metadata such as `RETAIN`, `REPAIR_WIRE`, `ABSORB_REFERENCE`, `DIRECT_PORT`, `ADAPT`, `ORIGINAL` |
| `Evidence` | Acceptance IDs plus exact revision/receipt; never a bare path or aggregate suite total |

`Closed` is derived from implementation + qualification + delivery. Do not store a freely editable closed flag.

## Group ledger — not counted

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|

A group may contain groups or capabilities. If a legacy parent is itself independently observable, retain it as a capability & classify its supposed children as implementation/qualification records unless they prove distinct behavior. Never count both a bundle & its decomposed behaviors.

## Implementation register — not counted

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|

Use this for adapters, connector projections, donor ports, modules, wiring lanes, & technical subtasks. Implementation can target several capabilities but cannot close them by itself.

## Qualification ledger — not counted

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|

Examples: installed `/app-control`, physical-device behavior, performance soak, screen-reader run, signed-install launch, security probe. A qualification may target multiple capabilities. Evidence belongs here, not in feature totals.

## Decision registers — not counted

- `REFERENCE`: donor choices, rejected alternatives, reuse rationale, pins.
- `EXCLUSION`: explicit non-goals with decision authority.
- `BACKLOG`: discovered but unpromoted candidates.

## Required invariants

1. Every ID is unique within its kind; aliases are explicit.
2. Every countable row is `CAPABILITY`.
3. Every capability has one owner & one observable outcome.
4. Every counted capability has `COMMITTED` scope.
5. Parent links are acyclic & target `GROUP` only.
6. Every qualification target resolves to a capability.
7. Every implementation target resolves to a capability.
8. No evidence row appears in capability totals.
9. No group rollup is summed with descendants.
10. No current `PASS` evidence predates a material change to its target.
11. Summary totals are derived from ledgers, never maintained independently in prose.

## Preservation-first migration

1. Freeze source revision & enumerate legacy rows.
2. Produce migration map with legacy location, old ID, new kind, target/parent, & ambiguity.
3. Reclassify without renaming IDs.
4. Preserve original prose in history/reference notes when moving it.
5. Compute normalized totals only after all rows are classified.
6. Compare old & new inventory unions; any missing row blocks migration.
7. Reconcile closure separately after normalization.

## Taxonomy (creation)

Fixed hierarchy: `Product → Scope → Domain → Atom`. No sub-atoms. A **Scope** exists only when one of these materially changes: reference-repo applicability, runtime/deployment boundary, platform-native contract, state/data authority, independent lifecycle. Language alone never splits the taxonomy.

**Atom split test:** an atom is the smallest independently meaningful product/reliability contract *for which another implementation could reasonably be the better implementation*. Different possible winners → split; necessarily shared state machine/caller/failure semantics → keep together. Standardize the criterion, not the count.

**Provenance classes** map onto existing Scope/REFERENCE/EXCLUSION registers: `USER_REQUIRED`, `CURRENT_PRODUCT`, `REFERENCE_CANDIDATE`, `EXCLUDED`.

## Extended Action vocabulary

In addition to planning metadata (`RETAIN`, `REPAIR_WIRE`, `ABSORB_REFERENCE`, `ORIGINAL`), reuse-disposition actions: `ADOPT`, `DIRECT_PORT`, `TRANSLATE_PORT`, `BEHAVIORAL_REIMPLEMENT`, `COMPOSE`, `GREENFIELD`. Action never changes lifecycle state.

## License disposition ledger — not counted

| Atom/mechanism | Repository | Observed license/SPDX | Evidence location | Obligations | Permitted reuse actions |
|---|---|---|---|---|---|

License facts first, policy second: store observed license identity, evidence location, & obligations; derive permitted actions under project reuse policy (`License evidence → obligations → project policy → permitted reuse actions`). `COPY_ALLOWED / DEPENDENCY_ALLOWED / REFERENCE_ONLY` is the *derived* execution policy, never the license model — MIT/Apache/MPL/LGPL/GPL/AGPL do not collapse into one binary, & a translated port may still be derivative. Dispatch consumes the derived decision only; it never interprets licenses.

## Atom identity & lineage

Every persistent canon keeps stable atom keys plus merge/split/alias lineage across NORMALIZE & RECONCILE. Renaming or splitting an atom without lineage is a defect: it silently breaks historical bakeoff & dispatch references.

## Foundation receipt

A Foundation receipt fingerprints: product/scope; relevant target commit for existing software; scope-affecting requirements/ASRs; platform/runtime set; corpus repos + exact commits; exclusions; & Foundation protocol/schema version. A material fingerprint change invalidates only affected scopes. Orchestration state is explicit: `ARCHITECT → FOUNDATION_REQUIRED(scope, reason) → LEGION → FOUNDATION → FOUNDATION_RECEIPT → ARCHITECT_RESUME`.
