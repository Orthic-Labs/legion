# Search Experience / SERP-Fit Diagnosis

Absorbed conceptually from AgriciDaniel/claude-seo v2.3.1 `seo-sxo`, adapted to Legion ownership and evidence contracts. Do not import its separate-agent orchestration or opaque score as authority.

Use when a technically healthy page does not rank, the user asks about intent/page-type mismatch, or a page redesign/reposition is being considered.

## Principle

Technical correctness is necessary but does not establish that a page is the right result type for a query. Read the live SERP backwards to infer the result formats Google currently rewards, then compare the target page.

## Method

1. Freeze target URL, query, country/language, device where relevant, and collection time.
2. Acquire target page through the normal safe/render-aware evidence path.
3. Collect a bounded live SERP sample or provider result. Preserve source and limitations.
4. Classify organic results using one taxonomy: product, category, service, landing, comparison, list, guide, how-to, definition/reference, tool/calculator, forum/community, video/media, local, other.
5. Record SERP features: AI Overview, featured snippet, PAA, local, shopping/products, images, videos, discussions, news and other material features.
6. Determine page-type consensus. Strong consensus is evidence of format expectation; fragmented results are evidence of uncertainty/opportunity, not permission to guess.
7. Compare target against dominant intent, page type, answer format, depth, media/interactivity, trust/proof and freshness expectations.
8. Derive user needs only from observed SERP/query/customer evidence. Label inferred personas/user stories as hypotheses.
9. End with a structural verdict before copy recommendations.

## Structural verdicts

`ALIGNED | REPOSITION | SPLIT | CONSOLIDATE | CREATE_DIFFERENT_PAGE_TYPE | INVESTIGATE`

Examples:

- informational article against a strongly commercial product/category SERP -> consider a commercial page rather than endlessly rewriting the article;
- generic landing page against tool/calculator SERP -> investigate whether an interactive utility is the missing value;
- broad page outranking a specific child for the child's intent -> diagnose ownership/internal-link/canonical structure before copy.

Do not assert that a mismatched type can "never" rank. SERPs change and mixed-intent queries exist.

## Evidence output

Record:

```json
{
  "query": "...",
  "market": "...",
  "observed_at": "...",
  "target_page_type": "...",
  "serp_sample_size": 10,
  "dominant_page_type": "...",
  "consensus": "strong|mixed|fragmented",
  "features": [],
  "fit": "aligned|mismatch|uncertain",
  "evidence": [],
  "limitations": []
}
```

Feed this evidence into page lifecycle and `seo next`; do not create a separate SXO authority or universal score.