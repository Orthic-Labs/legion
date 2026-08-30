# Legion Foundation independent source-inventory packet

## Raw user scope

> I want you to use 2 sol subagents to independently do new foundation stage 1 on those repos, 2 separate docs, no cross contamination. once you're done processing, add it into canon as atoms as well as into pending, as needed
>
> and then 2 subagents to do the same for legion with repos in `\\192.168.1.7\d\claude\repos\legion`
>
> The goal is to capture atoms acros those repos that we've missed, so that we can fold in as necessary

## Contract

- Product: Legion.
- Requested research: Foundation Stage 1 corpus freeze + Stage 2 independent atomic inventory needed to discover missed atoms. Do not perform implementation comparison, ranking, reuse, license disposition, or target-repository mutation.
- Frozen corpus/applicability map: `docs/foundation/2026-08-31/legion-corpus.json`. Every listed repository is in scope at its recorded commit. Do not fetch, pull, switch, or alter any repository.
- Taxonomy: `Product → Scope → Domain → Atom`; no sub-atoms. Apply split test from `D:/Claude/tools/skills/foundation/references/model.md`.
- Output: exact allowlisted report path from authority dispatch packet. Edit only that path.
- Each independent pass is blind. Do not read sibling output, prior Foundation/Atom reports, `D:/Claude/legion/docs/canon/**`, `D:/Claude/legion/docs/pending/**`, expected taxonomies, or any other inventory.
- Source restriction: read operative production source only. Do not read README files, docs, root Markdown, marketing, web pages, issues, benchmark claims, tests as sole proof, generated/build/cache output, fixtures, backups, or agent artifacts. Package/config files may establish target/platform, never behavior alone.
- Platform/applicability: map every corpus repository to actual supported runtime/platform from operative source. Mark unresolved platform or non-applicability explicitly; never imply `Not found` from skipped search.
- Evidence: each observed row states exact repository name, target/platform, production file + semantic symbol, live caller/consumer, concrete behavior, state/persistence/fallback where relevant, & focused safeguard/test only when paired with production path.
- Inventory table header must be exactly `| Platform | Domain | Atom | Definition / boundary | Source evidence |`.
- Atom names describe independently observable behavior, not donor/file/test/implementation technique unless technique is platform contract. Merge synonyms, retain single-repository atoms, & do no gap analysis or ranking.
- Batch by domain/platform, normally ≤25 atoms. After each batch verify paths, symbols, consumer, target, contamination, copied cells, & support level.
- Run one adversarial self-review in place: omissions, unsupported claims, wrong absences, broad rows, copied cells, category leakage, missing repos, malformed tables. Fix in place, then stop. Do not create a review artifact.
- Worker runs no validator, tests, builds, generators, installs, commits, pushes, or merges. Integration owner runs checks.

## Required report sections

1. Frozen scope/corpus table with all 18 exact commits, platform/applicability disposition, & saturation stop reason.
2. Atomic inventory table using required header.
3. Repository coverage ledger: every manifest repository marked `evaluated`, `unresolved` with reason, or `excluded` with reason.
4. Ambiguities/minority findings retained for later reconciliation.
5. Requested/evaluated/unresolved/excluded totals.
6. Foundation receipt fingerprinting product/scope, corpus manifest digest, commits, runtime/platform set, exclusions, Foundation protocol/schema version, & report material digest placeholder for integration owner.

## Criteria

Correctness, native/runtime fit, local-first privacy, latency, recovery visibility, accessibility where applicable, maintainability, & testability. Popularity is never evidence.
