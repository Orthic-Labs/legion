# SEO Operations — Observe, Decide, Improve, Learn

Use this reference for recurring SEO/AEO/GEO operation, prioritization, decay review, intervention measurement, and `what should we do next?` requests.

## Operating objective

Maximize qualified organic and AI-search visibility per unit of effort without manufacturing work.

Canonical loop:

`Observe -> Diagnose -> Decide -> Execute -> Verify -> Measure -> Learn -> Repeat`

A full audit is one input to this loop, not the loop itself.

## State contract

Keep these objects distinct:

- **Evidence** — source, scope, collection time, freshness, completeness, raw locator, limitations.
- **Finding** — observed condition supported by evidence; status `pass|partial|fail|na|not_testable` where a control applies.
- **Recommendation** — proposed intervention with expected mechanism, confidence, impact, effort, downside, dependencies.
- **Action** — authorized mutation with target, exact change, deployment/revision identity, rollback and verification.
- **Outcome** — later observation against the frozen baseline and evaluation condition. Outcome is not automatically causal.

Never turn missing credentials, unavailable reports, sampling, or failed collection into a clean result.

## Baseline before intervention

For owned sites, collect the best available subset:

1. Google Search Console search performance with explicit date range, dimensions, aggregation/completeness notes.
2. Google Search Generative AI report export when available; keep separate from ordinary Search Analytics unless Google documents an API mapping.
3. Bing Webmaster traditional search/crawl/index evidence and Bing AI Performance export when available.
4. GA4 or business events where authorized and useful.
5. Crawl/indexability/render state, sitemap, canonical/redirect graph, CWV.
6. Page-family, query-ownership and internal-link graph for affected pages.
7. Backlink/mention/provider data only as labelled external evidence.

## `seo next` decision method

Build candidates from evidence, not generic SEO checklists. Eligible candidate classes include:

- critical crawl/index/render defect;
- query ownership/cannibalization repair;
- wrong page type or intent mismatch;
- high-value position/CTR opportunity;
- decay or stale factual claim;
- missing answer/question coverage;
- weak generative citation/extractability on a commercially important topic;
- authority/corroboration gap;
- missing page where demand and information gain are demonstrated;
- `wait` / `retain` / `investigate`.

Decision order:

1. **Eligibility/blockers** — authority, reversibility, evidence sufficiency, dependencies, critical defects.
2. **Business value** — qualified demand, page/topic value, downstream conversion relevance.
3. **Opportunity evidence** — first-party visibility, SERP/AI-surface evidence, query ownership, citation data.
4. **Mechanism** — explain why the intervention could change the measured outcome.
5. **Confidence** — strength and independence of evidence.
6. **Effort/downside** — engineering/editorial cost, regression risk, cannibalization, brand/legal risk.
7. **Learning value** — whether the action produces useful evidence for later decisions.

Return exactly one **primary action** unless multiple P0/P1 defects must be handled together. Record why it beat the alternatives. `wait` is valid when evidence is immature or expected value is negative.

Do not use an opaque universal opportunity score. A compact comparison table is acceptable, but preserve the underlying dimensions.

## Page lifecycle

Every material page review ends with one primary disposition:

`KEEP | REFRESH | EXPAND | REPOSITION | CONSOLIDATE | SPLIT | REDIRECT | NOINDEX | DELETE | INVESTIGATE | WAIT`

Low traffic alone never authorizes deletion. Consider business purpose, inbound/internal authority, customer/documentation utility, page-family role, seasonality and observation window.

## Intervention record

Before a consequential SEO change, freeze:

```yaml
intervention:
  id: seo-int-...
  target: https://example.com/page
  query_or_topic: ...
  hypothesis: ...
  baseline:
    window: ...
    evidence: [...]
  action: ...
  primary_metric: ...
  guardrails: [...]
  deployment_identity: pending
  evaluation:
    earliest_date: ...
    maturity_condition: ...
  status: proposed
```

After execution, record deployment identity and technical verification. Later record outcome as `improved|declined|mixed|inconclusive|not_measurable`, plus confounders. Before/after movement is observational unless experimental design supports causality.

Do not repeatedly edit a page while its experiment is still maturing unless correcting a material defect; doing so destroys attribution.

## Recurring cadence

### Daily — health/drift

Cheap, deterministic checks only: uptime/status, robots/noindex/canonical accidents, sitemap/redirect drift, major crawl/index failures, important-page changes, severe GSC/Bing anomalies where available. Notify only on meaningful change.

### Weekly — operator run

Refresh first-party search/AI visibility evidence, decay/CTR/query-ownership candidates, Bing AI citations/grounding-query trends, Google generative impressions where available, material crawl drift and intervention outcomes. Run `seo next` and return one primary action plus P0/P1 exceptions.

### Monthly — growth review

Review topic/query coverage, page lifecycle, AEO question inventory, AI prompt benchmark, authority/corroboration, conversion outcomes, content gaps and completed interventions. Produce a bounded monthly roadmap.

### Quarterly — deep audit

Run the applicable control catalogue across technical, content, entity/schema, authority, AEO/GEO, local/international/ecommerce and measurement/governance lenses. Declare coverage and critical gates explicitly.

### On deploy/change — release gate

Re-crawl changed URLs/templates and verify rendered/static metadata, schema, links, redirects, canonical/indexability and rollback evidence. Deployment verification does not prove ranking/citation improvement.

## Weekly operator brief

Keep routine output short:

```text
SEARCH VISIBILITY — <period>
Traditional search: <material movement + evidence scope>
Google generative: <movement/unavailable>
Bing AI: <citations/pages/grounding-query movement or unavailable>
Qualified outcomes: <movement/unavailable>

PRIMARY ACTION
<one action or WAIT>
Why now: ...
Evidence: ...
Expected mechanism: ...
Confidence: ...
Effort/downside: ...
Evaluation condition: ...

WATCH
<one or two items not yet actionable>

PREVIOUS INTERVENTIONS
<technical verification + mature/immature/inconclusive outcome>

CRITICAL ISSUES
<only P0/P1>
```

## Doctrine drift

Weekly or before high-impact advice, verify unstable claims against current official Google/Bing/platform documentation. Record `checked_at`, source URL/title, affected rule and whether Legion guidance changed. Do not silently preserve stale platform doctrine.