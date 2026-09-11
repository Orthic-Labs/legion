# Topic Architecture / SERP-Overlap Clustering

Absorbed conceptually from AgriciDaniel/claude-seo v2.3.1 `seo-cluster`, adapted to Legion's evidence and capability boundaries.

Use for keyword grouping, pillar/spoke planning, topic architecture and cannibalization prevention.

## Principle

Do not cluster only by lexical/embedding similarity. When evidence budget permits, use **SERP overlap** as behavioral evidence that search engines currently treat two queries as satisfiable by the same or closely related result sets.

## Inputs

Build the query universe in this order:

1. owned GSC/Bing queries;
2. existing rank history/query ownership;
3. seed/category terms and customer language;
4. provider keyword enrichment;
5. PAA/related/autocomplete/question expansion;
6. live SERP evidence for candidate boundaries.

Do not begin with a huge external keyword dump when first-party demand already exists.

## SERP-overlap method

For candidate query pairs, compare a normalized top-organic-result set in the same market/time context. Record overlap count/ratio and the actual shared URLs. Use overlap as evidence, not a universal fixed threshold.

A useful starting interpretation for top-10 sets is:

- very high overlap -> likely one target page / merge candidate;
- medium overlap -> same topic family with strong internal-link relationship;
- low overlap -> adjacent but distinct pages;
- near-zero -> separate intent/topic.

Calibrate thresholds by SERP volatility, market and sample quality. Do not blindly inherit upstream's 7/4/2 cutoffs as platform truth.

## Cluster output

Produce:

- pillar/hub candidate and why;
- spoke/query groups;
- primary intent and expected page type for each target;
- existing target URL or demonstrated page gap;
- query ownership conflicts;
- mandatory and optional internal-link edges;
- evidence for merge/split decisions;
- information-gain requirement for every proposed new page.

New pages require more than keyword uniqueness. Before creation, prove distinct user intent or distinct information value and check the existing page family.

## Internal-link graph

Every planned page should have a route from a meaningful hub and intentional contextual links to related pages. Avoid mechanical exact-match anchor repetition and arbitrary link-density quotas. Use descriptive anchors that make destination purpose clear.

## Execution boundary

This reference produces search architecture and content briefs only. Writing owns prose creation; Designer owns visual/interaction changes; Legion coordinates multi-capability work. SEO does not invoke those skills itself.

## Measurement

After deployment, measure cluster/query ownership stability, indexation, impressions/clicks, qualified outcomes and AI citation/visibility where relevant. Do not treat completion of a planned cluster as evidence of search success.