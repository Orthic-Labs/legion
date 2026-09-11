# GEO / AI Search Analysis

Read `ai-search-2026.md` first. It owns current Google/Bing report semantics, crawler-purpose corrections and official-source freshness. This file supplies the deeper page/site analysis method.

## Position

GEO is search optimization applied to generative retrieval/citation surfaces, not a license to invent separate ranking factors. Diagnose normal crawl/index/quality foundations first, then evaluate information gain, answerability, factual extractability, entity consistency, corroboration and measured generative visibility.

## 1. Eligibility and access

Check only the controls relevant to the claimed surface:

- normal Google Search/AI Overview/AI Mode eligibility -> Googlebot/indexability/snippet controls;
- ChatGPT Search -> OAI-SearchBot, not GPTBot;
- Claude search -> Claude-SearchBot, not ClaudeBot;
- Bing/Copilot -> Bing indexability and Bing Webmaster evidence;
- Perplexity and other systems -> current vendor documentation.

Report model-training policy separately from search/citation policy. Inspect CDN/WAF/server-log evidence where authorized; a permissive robots.txt does not prove the crawler can reach the site.

## 2. Information gain / citation worthiness

For each important asset ask: **why would an answer system cite this page instead of interchangeable pages covering the same topic?**

Strong candidates include:

- original research or first-party statistics;
- transparent methodology, benchmarks or tests;
- primary product/documentation facts;
- original examples, datasets, tools or calculators;
- expert observations with identity and evidence;
- transparent comparisons with explicit criteria;
- maintained factual resources.

Generic summaries, keyword-expanded paraphrases and synthetic FAQ volume do not satisfy this gate.

## 3. Factual extractability

Important claims should be independently understandable when retrieved as passages. Check:

- explicit entity/product names rather than ambiguous pronouns;
- direct answer near the relevant question;
- source adjacent to factual claims;
- publication/update dates for time-sensitive material;
- methodology/sample size/geography/units/currency where applicable;
- limitations and caveats;
- clear table headings and definitions;
- consistent product/specification terminology.

Do not optimize toward arbitrary passage-length formulas. Extractability is semantic clarity plus evidence, not a magic word count.

## 4. AEO question coverage

Build the question inventory from owned queries first, then PAA/related/autocomplete/Bing/customer/support/sales/community evidence. Map every important question to an intended page and classify:

`answered | weak_answer | wrong_page | duplicate_ownership | missing | not_worth_targeting`

For answerable questions prefer direct answer -> evidence -> explanation -> related questions. Do not create FAQ schema merely because Q&A copy exists; validate current structured-data eligibility separately.

## 5. Entity and corroboration

Build a source-linked graph for material facts:

`Organization -> Product -> Person -> Topic -> Claim -> First-party source -> Independent corroboration -> Page`

Check consistency across the site and legitimate external sources. Detect stale claims after product/pricing/policy changes. Never manufacture reviews, mentions, directory entries or community discussion.

## 6. Measured visibility

Keep each surface separate:

### Google

Use Search Console Generative AI Performance when available. Track generative impressions by documented dimensions and period. This is visibility evidence, not citation/ranking/click evidence.

### Bing

Use Bing Webmaster Tools AI Performance when available. Track citations, cited pages, grounding queries, page-query mappings, trends and documented preview dimensions such as intents/topics/citation share. Preserve sampling/aggregation caveats.

### Other answer engines

Use controlled prompt sampling or legitimate provider evidence. Freeze prompt bank, engine/surface, locale/account state, repetition and observation time. Record brand mention, citation URL, competitors and claim accuracy. Treat this as observational sampling, never exhaustive market share.

### Outcomes

Track identifiable AI referrals and qualified events separately. A citation or impression is not a visit; a visit is not a conversion.

## 7. Controlled prompt bank

Cover a stable set of:

- category discovery;
- brand/entity questions;
- comparisons/alternatives;
- informational/how-to questions;
- multi-constraint/fan-out research tasks.

Repeat periodically rather than changing the benchmark every run. Report volatility.

## 8. `llms.txt`

Presence may be audited or generated for interoperability. Do not assign Google ranking/citation weight to it. Absence is not a Google SEO failure. Keep `llms.txt` guidance subordinate to current official consumer documentation.

## 9. Output

Return evidence-linked findings across:

`eligibility | information_gain | extractability | answer_coverage | entity_consistency | corroboration | google_generative | bing_ai | sampled_engines | referral_outcomes`

For every finding include source/scope/date, observed condition, confidence, limitation and next action. Feed actionable candidates to `operations.md` for prioritization rather than producing a separate GEO backlog.

## 10. Anti-patterns

Do not:

- claim `Google-Extended` controls AI Overview/AI Mode inclusion;
- claim GPTBot access proves ChatGPT Search citability;
- treat `llms.txt` as a Google ranking lever;
- promise citations from schema, FAQ formatting or passage length;
- turn third-party correlation studies into ranking factors;
- publish generic AI-written pages to create topical volume;
- merge Google impressions, Bing citations and prompt samples into one score;
- infer zero visibility from an unavailable first-party report.