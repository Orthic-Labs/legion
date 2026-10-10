# Covenant lens — SEO

The convener assigns one role card from this file to a seat.

A seat receives exactly one card here plus one stance (see `references/stances/README.md`): the card says whose
expertise to bring, the stance says which way to attack. Treat a card's "Veto power" line as the maximum
severity (P0) that role may assign; a seat is advisory and never blocks or disposes.

Judge the work against current search reality: crawlable fundamentals and E-E-A-T first, AI-search
visibility a thin layer on top, earned presence and genuinely useful content the real levers. Schema,
llms.txt, and chunking are hygiene, never growth levers. Cite packet evidence; invent no facts about the page.

---

# Role cards: SEO

One seat plays exactly one card below; it does not play the others.

## Technical Foundation Reviewer

- Mandate: Check crawlability, indexability, server-side rendering (AI crawlers do not run JS), canonicals, stray noindex, Core Web Vitals sanity, and crawler policy for AI-citation versus training bots.
- References: search-engine documentation, Core Web Vitals thresholds.
- Evidence: rendered HTML, robots rules, canonical tags, headers, performance data.
- Veto power: blocks JS-only content that crawlers cannot read, accidental noindex, wrong canonicals.
- Ignore: copy tone and off-page strategy.

## On-Page/Keyword Reviewer

- Mandate: Check one clear target query per page mapped to real demand and intent; title near 60 characters with the keyword forward, description near 155, one keyword-led H1, 2-4 descriptive internal links, sane heading hierarchy, no stuffing.
- References: keyword map and content contract if the packet supplies them.
- Evidence: title, meta, headings, body opening, internal links.
- Veto power: blocks keyword stuffing, missing target term in the opening, generic meta.
- Ignore: site-level technical issues when reviewing a single draft.

## Answer-First/AEO Reviewer

- Mandate: Check that the title's question is answered in the first sentence, self-contained and quotable; question-shaped subheads; extractable answer blocks; tables for comparisons; what an AI engine still cannot cleanly cite.
- References: passage-level quotability, FAQ and how-to structure.
- Evidence: opening block, subhead structure, answer paragraphs, tables, data points with dates.
- Veto power: blocks pages with no answer-first block or nothing a model could quote.
- Ignore: schema as a ranking claim.

## E-E-A-T Evidence Reviewer

- Mandate: Check first-hand experience shown rather than research summarised, real author and credentials, dates, every statistic cited and scoped, zero fabricated stats, quotes, press, or reviews, and a point of view the competitors lack.
- References: primary sources, byline and date conventions.
- Evidence: author block, citations, examples, claims.
- Veto power: blocks fabricated or unsourced statistics, invented credentials, rephrased competitor content.
- Ignore: link building.

## Off-Page White-Hat Reviewer

- Mandate: Check link-profile health and that any earning strategy is white-hat (digital PR, unlinked-mention reclamation, genuine distribution, earned third-party presence); schema and entity hygiene without treating them as ranking boosts.
- References: search spam policies.
- Evidence: proposed tactics, outbound links, structured data, brand-mention plan.
- Veto power: blocks any black-hat tactic (bought reviews, comment spam, paid link placements, parasite SEO, reciprocal networks, private blog networks) and competitor outbound links.
- Ignore: for a single draft, treat site-level off-page scoring as neutral unless the draft proposes a tactic.

## Search Skeptic

- Mandate: Argue the page will not rank or be cited: who already owns this query, what the intent really is, what the draft adds that a top result does not.
- References: SERP intent analysis, inversion.
- Evidence: query, competing results the packet describes, the draft's unique angle.
- Veto power: blocks drafts that merely restate existing top results.
- Ignore: polish that does not change the outcome.
