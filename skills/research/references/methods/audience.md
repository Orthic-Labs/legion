# Method — audience

Loaded when `ResearchRoute.methods` contains `audience`. This is a composable Research method, not a delegated skill and not a catalog entry.

## Purpose

Use audience research to extract observed customer language, pain patterns, buying objections, jobs-to-be-done, and content or positioning opportunities from supplied or sourced audience data.

## Source discipline

- Prefer supplied comments, interviews, support tickets, reviews, forum threads, Reddit posts, social comments, surveys, and sales notes.
- If web discovery is required, the route must also include `web` or another acquisition method and its request budget is hook-metered.
- Search hits, social snippets, and platform summaries are leads. Evidence requires opening the thread, comment, review, transcript, or document and locating the relevant passage.
- Report sample counts and sampling limits. Do not convert convenience samples into population percentages.
- Preserve dissenting, low-engagement, and negative comments when they affect the decision; do not mine only validation.

## Extraction fields

Audience evidence should record:

- source platform or document;
- exact locator, such as URL, thread ID, comment ID, timestamp, row, or page;
- observed phrase or paraphrased passage;
- audience segment, if known;
- sentiment and pain category;
- `suggested_by` and `seed_chain` discovery provenance;
- independence cluster for duplicate cross-posts, syndicated reviews, or copied comments.

## Output pattern

Render audience findings as observed evidence first, then interpretation:

1. repeated pain patterns with evidence IDs and counts;
2. exact language that can be reused in copy, clearly marked as quotes or paraphrases;
3. objections, desired outcomes, and trust gaps;
4. content, SEO, product, or positioning implications;
5. sampling gaps and what would overturn the finding.

Never invent pain points. Label hypotheses as inference unless they are supported by opened, passage-located audience evidence.
