# SEO quality gates

These are **risk and evidence gates**, not universal ranking formulas. Do not turn character counts, word counts, link counts, content age, or keyword density into pass/fail ranking rules without page-type and live evidence.

## Universal hard gates

A page/control cannot be clean when any applicable gate is unresolved:

- crawl/index intent conflicts with robots, X-Robots, canonical, redirect or status evidence;
- important main content fails to render reliably;
- serious security/spam-policy/private-data exposure exists;
- migration/domain redirect controls are materially broken;
- primary analytics/conversions required for the claim are known broken;
- a binding browser/agent action lacks exact authority;
- a finding relies on missing evidence but is reported as Pass.

Critical gates remain visible outside any optional score.

## Content sufficiency

Judge content by **task completion, originality/information gain, factual support, page purpose, market/language, and current result-set expectations**.

Do not enforce canonical minimum word counts. Use length only as a diagnostic signal when it helps explain a concrete deficiency. Examples:

- a short calculator/tool page can provide high standalone value;
- a long article can still be thin if it merely restates commodity information;
- product/category/location pages require unique useful facts appropriate to their entities, not a percentage-of-words quota.

For scaled/programmatic pages, require a real reason each URL should exist independently. Detect mass template substitution, overlapping intent, insufficient entity/data differentiation, index bloat and maintenance risk. Progressive rollout and sampling may be recommended based on risk, not arbitrary page-count folklore.

## Location/programmatic pages

Hard stop when evidence indicates doorway/scaled-content abuse risk, such as:

- substantially interchangeable pages whose only meaningful change is a location/keyword token;
- pages funnelling users to the same destination without independent value;
- fabricated local presence, testimonials, staff, reviews or facts;
- no standalone user task or entity-specific information;
- page volume exceeds the organization's ability to keep factual claims current.

The number of pages alone is not the violation. Record affected count/reach as impact evidence.

## Titles and snippets

Evaluate:

- descriptive accuracy and visible-page consistency;
- uniqueness where distinct pages need distinct search representation;
- entity/intent clarity;
- boilerplate/template risk;
- spam/repetition;
- observed title-link/snippet behavior when Search Console/SERP evidence exists.

Character/pixel length can predict truncation and is useful diagnostically, but there is no universal minimum/maximum ranking gate. Google may generate/rewrite title links and snippets.

## Internal links

Evaluate graph function, not quota:

- important pages have discoverable contextual paths;
- orphan/deep pages are intentional or fixed;
- anchors describe destination purpose without manipulation;
- parent/child, hub/spoke and sibling links match information architecture;
- template links do not create crawl traps or sitewide irrelevant repetition.

Do not require a fixed number of links per thousand words or page type.

## Images/media

Non-decorative images need useful accessible alternatives where appropriate; decorative images may correctly use `alt=""`. Evaluate intrinsic dimensions/CLS, delivery, format/compression, relevance/context, preview controls, rights/licensing and search/media eligibility. Do not fail an image merely for exceeding a universal byte or alt-text character threshold without context.

## Freshness

Freshness is query- and fact-dependent. Update when facts/product states/regulations/prices/availability/source evidence change, when the search task rewards recency, or when performance/ownership evidence indicates decay. Never rewrite evergreen material solely because an arbitrary number of months elapsed.

## Structured data

Markup must match visible content and current platform eligibility. Unsupported/deprecated rich-result expectations are removed, not retained as historical recipes. Structured data is evidence/eligibility support, never proof of ranking or citation lift.

## AI/AEO/GEO quality

Require eligibility/access, information gain, factual extractability, source clarity, entity consistency/corroboration, answer coverage and measured visibility kept as separate dimensions. No fixed passage length, FAQ count, heading formula, `llms.txt`, crawler-training permission or third-party correlation is a universal AI-search ranking gate.

## Control states

Every applicable check ends in exactly one:

`Pass | Partial | Fail | N/A | Not testable`

- `Partial` names tested and untested scope.
- `N/A` requires rationale.
- `Not testable` remains in the evidence-coverage denominator.
- Missing data never becomes Pass.
