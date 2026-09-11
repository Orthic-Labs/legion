---
name: seo
description: "Operate SEO, AEO, GEO and AI-search visibility: diagnose, prioritize, improve, verify and measure crawl/indexation, query ownership, SERP fit, content, entities, citations, Google generative visibility, Bing AI citations, CWV, schema, links, local/international/ecommerce search, and traffic or visibility changes."
kind: capability
capabilityClass: domain
discoverability: public
domain: commercial
operations:
  - analyze
  - diagnose
  - decide
  - produce
effects:
  - source-read
  - artifact-write
  - process-exec
  - network-request
hostRequirements:
  - python-runtime
---

# SEO

PRIMARY_DELIVERABLE: Evidence-backed search-visibility decision, finding set, or bounded change.
SPECIALIST_REFS_MAX: 2
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen scope has explicit evidence coverage, one primary next action or justified no-action, and verification/outcome state where applicable.

Freeze domain, market, language, page/query set, dates, repository, access, business goal, irreversible effects, and evidence budget. When durable project context exists, load it rather than rediscovering goals/market/competitors/key pages every run; `references/openseo-absorption.md` defines the portable project-state contract.

SEO owns search diagnosis and search-specific methods. Legion owns orchestration across capabilities; this skill does not spawn agents or invoke other skills. Writing owns prose, Marketing owns broader commercial strategy, Designer owns presentation/UX work, and authorized execution follows Legion's normal effect/verification lifecycle.

## Route

- Project setup, provider/capability doctor, market defaults, cache/cost preflight: `references/openseo-absorption.md`; use `scripts/seo_project.py` and `scripts/provider_registry.py`.
- Full audit, coverage, scorecard, or unfamiliar request: `references/manual.md` + `references/quality-gates.md`; use `scripts/coverage.py` for control coverage and `scripts/seo_closure.py` for repository implementation closure.
- Recurring operation, prioritization, "what next", decay, monitoring, release verification, intervention review: `references/operations.md`; use `scripts/search_ops.py` for durable state.
- Policy, bot-policy, logs/crawl efficiency, agent readiness, search appearance/Discover, media/documents, publisher, access states, migration, analytics, forecast/experiment, monitor/release-gate/incident, feeds: `references/workflow-packs.md`.
- GEO/AEO/AI search, Google AI Overviews/AI Mode, Bing Copilot/AI citations, ChatGPT/Claude/Perplexity visibility: `references/ai-search-2026.md` + `references/geo.md` when deeper page criteria are needed.
- Technical/crawl/index/render/CWV: `references/technical.md`, `sitemap.md`, `schema.md`, `hreflang.md`, or `cwv-thresholds.md` as needed.
- Page/content/query ownership: `references/page.md`, `eeat-framework.md`, `blog-post-contract.md`, or `images.md`; use `scripts/query_ownership.py` for first-party ownership evidence.
- Questions/AEO inventory: `references/ai-search-2026.md`; use `scripts/question_inventory.py` for GSC-first question extraction.
- Rank tracking: `references/openseo-absorption.md`; use `scripts/rank_tracker.py` to persist normalized provider observations and ownership changes.
- SERP intent/page-type mismatch or search experience: `references/search-experience.md`.
- Keyword/topic architecture or semantic clustering: `references/topic-clusters.md`.
- Ecommerce/product/category/Merchant Center/shopping: `references/ecommerce-2026.md` plus `schema.md` when markup is in scope.
- Local: `references/local.md` plus only relevant maps/local-schema reference.
- Links/authority: `references/backlinks.md`, `backlink-quality.md`, or `off-page.md`.
- Programmatic: `references/programmatic.md`; international: `references/hreflang.md`.

## Execute

1. Establish the best available baseline before recommending mutation. Owned first-party evidence leads within its measured scope; provider estimates stay labelled estimates.
2. Run deterministic collection/checks before model judgment. Treat tool output as evidence, not verdict; preserve raw errors and unavailable data.
3. Diagnose structural blockers before copy: indexability, canonical/redirect state, render gaps, page family, query ownership, SERP page-type fit, internal links, and intent.
4. Keep `Evidence -> Finding -> Recommendation -> Action -> Outcome` distinct. Missing evidence is `partial` or `not_testable`, never pass. Separate observed fact, estimate, hypothesis, recommendation, and causal claim.
5. For decision requests, compare eligible interventions and select one primary next action, or explicitly choose `wait`/`retain` when intervention is not justified. Do not optimize for producing work.
6. For changes, capture baseline + hypothesis + target + deployment identity + primary metric + guardrails + evaluation condition before execution; verify deployment separately from later search/business outcome. Use `scripts/search_ops.py` for durable intervention/run state when the host/repo permits artifact writes.
7. For Search Console analytics, prefer `scripts/gsc_query_v2.py`: aggregate totals come from a separate dimensionless query and returned-dimension coverage is explicit. Legacy `gsc_query.py` delegates analytical queries to v2 semantics.
8. For Google/Bing AI-search exports, normalize with `scripts/ai_visibility_import.py`. Preserve provider/source limitations and never equate impressions, citations, visits, rankings or conversions.
9. For site-scale metadata audits, use `scripts/templated_metadata.py` where parsed page data is available; its output is heuristic evidence, not a ranking verdict.
10. Apply project country/language defaults to compatible keyword/SERP/rank/provider work. Retrieve deeper SERPs only when the decision requires it. Paid-provider work must preserve cost/provenance and must not become a dependency for owned-site first-party operation.
11. The governed checklist source is `config/control-catalog.json`; all 30 phases require an owner and exact source range. `scripts/checklist_compiler.py` keeps source changes reviewable. Run `scripts/seo_closure.py` before claiming repository implementation completeness.
12. Prefer current Google, Bing, schema.org, browser/platform, or protocol authority for unstable rules. `references/ai-search-2026.md` is the current correction layer for AI-search crawler/control/report semantics.
13. Produce machine findings plus one concise human report. A scheduled run is an operator brief, not a full audit dump.
14. Require explicit current authority before indexing submission, external mutation, spend, outreach, publication, deletion, redirect/consolidation, or other consequential effect.

Never treat `llms.txt`, AI crawler training access, schema markup, prompt samples, or third-party visibility estimates as proof of Google/Bing AI citation performance. Never conflate training crawlers with search/citation crawlers.