---
name: compshop
description: "Compare repositories semantically from source code. Use for independent Inventory passes that produce one function-first Markdown matrix, Consolidate passes that combine multiple Inventory reports, or Reconcile passes that resolve conflicts against source."
---

# CompShop

Use one stage:

1. `INVENTORY` — inspect every repository independently; write one Markdown matrix.
2. `CONSOLIDATE` — combine completed Inventory reports.
3. `RECONCILE` — resolve Consolidate conflicts against source.

## Doctrine

- Independent Inventories create recall; each is imperfect.
- Only operative source proves claims; preserve uncertainty.
- Inventory never reads other reports. Consolidate starts from reports. Reconcile alone returns to source.
- Preserve every material finding, including unique/minority findings; never majority-vote facts.
- Run one adversarial self-review, fix defects, then stop; never demand exhaustiveness.
- `Stage 1 complete` means all repos represented, matrix sound, & self-review finished—not exhaustive recall.

## Inventory

Inspect in-scope implementation only. Never read README, docs, root Markdown, prior inventories, benchmarks, expected taxonomies, sibling outputs, or web sources.

Read entry points, registries, configuration, persistence, parsing/search, UI, hooks, tests, security, recovery, performance, packaging, & integrations. Search only navigates. Workers may inspect disjoint scope; one coordinator owns report.

Discover semantic union. Rows are concrete functions, mechanisms, workflows, UI/UX, options, or limits; columns are every repo. Each cell answers its row with mechanism detail, `N/A`, `Not found`, or `Unclear`. Merge equivalents, split varying behavior, preserve single-repo capabilities, & use broad categories only as grouping. Never copy summaries between unrelated rows.

Write one `.md`. Adversarially check omissions, unsupported claims, wrong absences, broad rows, copied cells, category leakage, missing repos, & malformed tables. Correct it in place; create no review artifact.

Return only:

```text
Stage 1 complete: /absolute/path/inventory.md
Repositories: <count>
Concrete rows: <count>
Sections: <count>
```

## Consolidate

Read every Inventory; do not reread repos. Enumerate all rows, merge equivalents, combine detail, split different behavior, & preserve unique findings. Every output row represents every repo.

Write `consolidated.md` plus `dirty.md`. Dirty holds only contradictions, material merge/split ambiguity, unsupported high-impact claims, or scope mismatch—not paraphrases/minority findings. State question, claims, repos, & references.

## Reconcile

For each dirty item, inspect smallest relevant implementation surface; merge, split, correct, qualify, preserve unresolved, or remove noise. Patch consolidated matrix & return one final `.md`. Do not reread README/docs or repeat full Inventory.

## Never

Structured export is post-research & request-only. Never build IDs, ontologies, state/backfill systems, extractors, validators, receipts, WALs, rankings, or certification gates.
