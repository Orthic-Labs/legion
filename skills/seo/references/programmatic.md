# Programmatic SEO — scaled-page control pack

Use for data/template-generated page families, facets, directories, integrations, locations, products, inventories and other pages created at scale.

The governing question is not “how many words/pages?” It is: **does each indexable URL represent a distinct user task/entity/state with standalone value, stable factual inputs, intentional query ownership and maintainable lifecycle controls?**

## Freeze scope

Record:

`page family | generation source | record count | intended indexable count | markets/languages | canonical pattern | lifecycle | owner | business purpose | query/topic ownership | data freshness | rollout state`

## Data-source evidence

Inspect structured source quality:

- unique identifiers and stable keys;
- required fields and null/missing-value behavior;
- data freshness and source-of-truth ownership;
- duplicates/near-duplicates and conflicting records;
- entity relationships;
- update/delete/discontinued lifecycle;
- provenance for externally sourced facts.

A numeric overlap ratio may be used diagnostically, but there is no universal percentage at which a page becomes “safe.” Examine whether differences are useful to the user rather than token-level uniqueness.

## Template and page-family controls

Check:

- generated title/H1/body/schema/meta/canonical behavior;
- fallback behavior when data is missing;
- client/render parity;
- route/slug stability;
- template boilerplate vs entity/task-specific information;
- visible content vs structured-data/feed consistency;
- internal-link generation;
- duplicate/near-duplicate target detection;
- pagination/facet/filter state;
- empty/no-result states;
- experiment/personalisation/access-state effects.

Reject “mad-libs” pages where meaningful content is unchanged except for a city, category, product or keyword token and no independent task/value exists.

## Information-gain gate

For every indexable page family, state what information/task capability exists because that URL exists. Examples of legitimate differentiation can include real inventory, compatibility, setup instructions, local availability, distinct specs, prices, policies, original data, user-generated evidence or entity-specific analysis.

If differentiation is only wording variation, synthetic FAQs or search-keyword substitution, prefer consolidation, non-indexable states or a stronger data/product asset.

## Query ownership

Before expansion:

- map existing pages and first-party queries;
- identify intended owner per query/topic/entity;
- use SERP-overlap evidence where useful;
- test parent/child inversion and switching;
- avoid creating a new URL when an existing page already owns the task adequately.

## Crawl/index controls

For each generated URL class determine whether it should be:

`indexable canonical | indexable self-canonical | noindex | canonical-to-parent/variant | redirect | 404/410 | non-crawlable application state`

Do not blanket-canonical pagination/facets/products to page 1 or a parent merely because they share a template. Canonicals must represent genuinely duplicate/substitute content. Pagination and filtered states need evidence-specific treatment.

Sitemaps include only canonical indexable URLs intended for search. `<lastmod>` reflects meaningful source/content change, not build time.

## Facets and crawl traps

Inventory filter/sort/search/calendar combinations and measure:

- finite vs combinatorial URL space;
- internal-link discoverability;
- robots/canonical/noindex behavior;
- duplicate demand;
- server/render cost;
- query-parameter normalization;
- crawl evidence where logs/GSC are available.

Solve with information architecture and URL-state policy rather than indiscriminate blocking that hides diagnostic evidence.

## Scaled-content/spam-policy gate

Escalate when evidence indicates content exists primarily to manipulate rankings rather than help users, including:

- mass pages with no standalone value;
- third-party/parasite sections exploiting host reputation;
- deceptive redirects or doorway funnels;
- fabricated local/entity/customer information;
- automated content where human/organizational controls cannot maintain factual integrity;
- expired inventory kept indexable without a lifecycle reason.

Use current official search-spam policy sources before making a policy claim. A page count, AI authorship, shared-template percentage or word count alone is not proof of violation.

## Rollout

Use risk-based rollout:

1. validate a representative sample across important templates/states;
2. establish index/query/business baselines;
3. publish a bounded cohort when feasible;
4. verify technical deployment;
5. observe crawling/indexing/ownership/outcomes separately;
6. expand only when evidence supports it.

Batch size and observation window depend on site authority, crawl behavior, risk, page family and business urgency; do not use universal 50/100/500-page thresholds.

## Internal-link automation

Links should reflect relationships and user journeys, not quotas. Check hub/parent/child/sibling/related-entity graph, anchor clarity, orphan/depth, template repetition and crawl-trap amplification. Fixed links-per-1000-words targets are not canonical controls.

## Lifecycle

Define behavior for:

`new | active | temporarily unavailable | out of stock | discontinued | merged | renamed | deleted | market-disabled`

Preserve useful historical/alternative paths where they serve users. Use redirects only when a true replacement exists; otherwise return the correct terminal state.

## Output

Report:

- page-family inventory and source provenance;
- applicable controls with `Pass | Partial | Fail | N/A | Not testable`;
- query ownership/cannibalization evidence;
- information-gain verdict;
- index/canonical/facet/lifecycle policy;
- affected URL count/reach;
- critical gates and missing evidence;
- one bounded rollout/remediation action or `WAIT`;
- validation and rollback method.

No universal programmatic SEO score is canonical. Optional reporting profiles must publish their formula, applicability, evidence coverage and critical gates.