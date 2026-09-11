# Page Engine — evidence-driven single-page analysis

Use for one URL or one page-family representative. This reference does not award a universal page score and does not use keyword-density, fixed word-count, or fixed title/meta-length targets as ranking rules.

## Required context

Freeze:

`URL | page family | market | language | device | intended query/topic | business purpose | date window | repository/template if known`

If intended query/topic is unknown, infer only as a hypothesis and label it.

## Evidence order

1. **Eligibility** — status, redirects, robots/X-Robots, canonical, index evidence, renderability.
2. **Ownership** — intended query/topic, GSC observed queries, intended vs observed page, cannibalization/switching.
3. **SERP fit** — current result-set page types/features when evidence is available; use `search-experience.md`.
4. **Page family/template** — route/template/component and sibling behavior where repository evidence exists.
5. **Content/information gain** — task completion, originality, factual support, entity clarity, freshness appropriate to the topic.
6. **Search appearance** — title/snippet inputs, headings, visible dates, images/video, structured data eligibility.
7. **Internal graph** — inlinks/outlinks, anchors, orphan/depth/context and parent-child role.
8. **Performance/UX** — field CWV first where available; lab/browser evidence as a different tier.
9. **AEO/GEO** — question coverage, factual extractability, sources, information gain and measured generative visibility where available.
10. **Business outcome** — qualified organic sessions/conversions where instrumented.

## Titles and descriptions

Evaluate descriptiveness, uniqueness, intent fit, entity clarity, spam risk and observed search appearance. Pixel/character ranges are diagnostics for likely truncation or templating, not ranking requirements. Google may rewrite title links/snippets. Do not force a keyword to the front or manufacture a CTA solely to satisfy a template.

## Content depth

There is no canonical minimum word count or keyword density. Judge sufficiency against the user task, page type, SERP/competitor evidence, unique information and business purpose. A concise tool/product/reference page can be complete; a long generic article can be thin.

Flag:
- missing answer/task-critical information;
- unsupported or stale claims;
- commodity summary with no information gain;
- templated boilerplate overwhelming unique content;
- page-type/intent mismatch;
- duplicate/near-duplicate target where ownership evidence supports it.

Do not flag merely because a page misses an arbitrary word threshold.

## Structured data

Validate only markup supported by visible page content and current platform eligibility. Schema improves machine understanding/eligibility; it does not prove a rich result, ranking lift or AI citation. Current platform restrictions/deprecations override old recipes.

## Images/media

Evaluate relevance, accessible text alternatives, intrinsic dimensions/CLS, delivery size/format, lazy loading where appropriate, surrounding context, previews/licensing and media-specific search eligibility. Decorative images may correctly use empty alt text.

## Page verdict

Every material page review ends with one primary lifecycle disposition:

`KEEP | REFRESH | EXPAND | REPOSITION | CONSOLIDATE | SPLIT | REDIRECT | NOINDEX | DELETE | INVESTIGATE | WAIT`

The verdict must record:

`evidence | mechanism | business value | confidence | downside | dependencies | validation method`

Low traffic alone cannot justify deletion or redirect.

## Information-gain gate

Before `EXPAND`, `SPLIT`, or creating a replacement page, state what useful information/task capability will exist afterward that is absent from the current page and competitive result set. If the answer is only more words, keyword variants, synthetic FAQs or rephrasing, prefer `KEEP`, `WAIT`, consolidation, or acquiring better evidence/data.

## Output

Return:

1. frozen scope and evidence coverage;
2. eligibility/ownership/SERP-fit findings;
3. page-family and content findings;
4. AEO/GEO/business evidence when applicable;
5. one lifecycle verdict;
6. one primary next action or `WAIT`;
7. exact validation method and missing evidence.

Use canonical `Pass | Partial | Fail | N/A | Not testable` control states. Never convert unavailable GSC, CWV, SERP, analytics or generative data into a pass.