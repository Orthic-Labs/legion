# OpenSEO absorption — Legion-native contract

Source family: `every-app/open-seo`. This reference captures useful OpenSEO behaviors without importing its SaaS shell, database, billing/team model, Cloudflare assumptions, or mandatory DataForSEO coupling.

## What Legion absorbs

### Project context

Search work needs durable project context shared across runs, not rediscovery on every invocation. The project context must be source-bound and may include:

- goals and business/search outcomes;
- positioning and audience;
- competitors;
- key pages/page families;
- default market: country + language;
- writing/content constraints;
- provider/property mappings;
- baselines and intervention history.

Store non-secret project state under `<project>/.legion/seo/`; keep credentials/secrets outside the repository under user configuration or provider-native secure storage.

Recommended portable layout:

```text
.legion/seo/
  site.yaml
  strategy/
  baselines/
  gsc/
  ga4/
  bing/
  ai-visibility/
  crawls/
  keywords/
  rank-tracking/
  competitors/
  backlinks/
  briefs/
  interventions/
  reports/
```

Do not require every directory. Create/use only state justified by the workflow.

### Data-plane coverage

OpenSEO's useful product lesson is the coherent data plane across keyword research, rank tracking, competitor intelligence, backlinks, site audit, Search Console/Analytics and AI visibility. Legion already owns methods for these areas; preserve them as one evidence graph rather than isolated reports.

For each observation preserve:

`provider | project/site | market | collected_at | period | dimensions | raw locator | completeness | cost | limitations`

Provider estimates must never overwrite first-party observations. Equivalent facts from multiple providers may coexist with provenance.

### Rank tracking

Rank tracking is longitudinal evidence, not a one-off SERP lookup. A tracked keyword needs:

`keyword | market | device | intended page | observed URL | organic position | SERP features | collected_at | provider`

Track organic position explicitly. Detect URL ownership changes/cannibalization separately from rank movement. Deeper SERP retrieval is on-demand when the decision requires it; do not pay for depth by default.

### Project defaults

Country and language defaults belong to project context and should flow into keyword research, SERP work, rank tracking and compatible provider calls. Never silently fall back to US/en when the project has an explicit market.

### Cost visibility

Paid-provider requests need visible cost semantics before expensive/bulk work. Prefer bulk endpoints, cache within the evidence window, and record provider cost/estimate with the evidence. DataForSEO is optional: owned-site first-party lanes must continue to function without it.

### MCP / agent access

OpenSEO demonstrates the value of exposing the same project/search evidence to agents through a stable tool surface. Legion should expose normalized evidence/state through its host/runtime contracts rather than coupling SEO to one agent client or importing OpenSEO's MCP server wholesale.

### Adversarial fixtures

OpenSEO's `badseo` corpus is a useful testing pattern. Legion deterministic SEO checks should have local fixtures for known failures and regressions: broken/cyclic redirects, bad canonicals, robots/noindex conflicts, duplicate/templated metadata, malformed schema, sitemap drift, render gaps, hreflang errors, orphan pages and crawler-purpose mistakes. A check is not complete merely because its prose exists; it should have a fixture/test when deterministic.

## Current OpenSEO additions reviewed in 2026-09

OpenSEO v0.1.6 added shared project context across its assistant/MCP, Google Analytics organic traffic, and opt-in Lighthouse for agent audits. v0.1.7 added deeper SERP retrieval on demand and repaired Search Console Discover/Google News MCP reports. Legion should absorb the underlying behaviors:

- shared durable project context;
- GA4 organic/business outcome evidence;
- Lighthouse only when useful rather than mandatory on every lightweight run;
- on-demand SERP depth;
- Search Console surface/type fidelity, including Discover/Google News where requested and supported.

These are behaviors, not reasons to adopt OpenSEO's application architecture.

## Explicit non-absorptions

Do not import as Legion core:

- hosted SaaS/dashboard shell;
- database/team/billing/account model;
- Cloudflare deployment assumptions;
- mandatory DataForSEO dependency;
- provider markup/margin model;
- OpenSEO-specific assistant/MCP topology.

Legion's SEO capability remains provider-agnostic and evidence-first.