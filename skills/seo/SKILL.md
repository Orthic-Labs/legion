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

Freeze domain, market, language, page/query set, dates, repository, access, business goal, irreversible effects, and evidence budget.

SEO owns search diagnosis and search-specific methods. Legion owns orchestration across capabilities; this skill does not spawn agents or invoke other skills. Writing owns prose, Marketing owns broader commercial strategy, Designer owns presentation/UX work, and authorized execution follows Legion's normal effect/verification lifecycle.

## Route

- Full audit, ecommerce, or unfamiliar request: `references/manual.md` + `references/quality-gates.md`.
- Recurring operation, prioritization, "what next", decay, or intervention review: `references/operations.md`.
- GEO/AEO/AI search, Google AI Overviews/AI Mode, Bing Copilot/AI citations, ChatGPT/Claude/Perplexity visibility: `references/ai-search-2026.md` + `references/geo.md` when deeper page criteria are needed.
- Technical/crawl/index/render/CWV: `references/technical.md`, `sitemap.md`, `schema.md`, `hreflang.md`, or `cwv-thresholds.md` as needed.
- Page/content/query ownership: `references/page.md`, `eeat-framework.md`, `blog-post-contract.md`, or `images.md`.
- SERP intent/page-type mismatch or search experience: `references/search-experience.md`.
- Keyword/topic architecture or semantic clustering: `references/topic-clusters.md`.
- Local: `references/local.md` plus only relevant maps/local-schema reference.
- Links/authority: `references/backlinks.md`, `backlink-quality.md`, or `off-page.md`.
- Programmatic: `references/programmatic.md`; international: `references/hreflang.md`.

## Execute

1. Establish the best available baseline before recommending mutation. Owned first-party evidence leads within its measured scope; provider estimates stay labelled estimates.
2. Run deterministic collection/checks before model judgment. Treat tool output as evidence, not verdict; preserve raw errors and unavailable data.
3. Diagnose structural blockers before copy: indexability, canonical/redirect state, render gaps, page family, query ownership, SERP page-type fit, internal links, and intent.
4. Keep `Evidence -> Finding -> Recommendation -> Action -> Outcome` distinct. Missing evidence is `partial` or `not_testable`, never pass. Separate observed fact, estimate, hypothesis, recommendation, and causal claim.
5. For decision requests, compare eligible interventions and select one primary next action, or explicitly choose `wait`/`retain` when intervention is not justified. Do not optimize for producing work.
6. For changes, capture baseline + hypothesis + target + deployment identity + primary metric + guardrails + evaluation condition before execution; verify deployment separately from later search/business outcome.
7. Prefer current Google, Bing, schema.org, browser/platform, or protocol authority for unstable rules. `references/ai-search-2026.md` is the current correction layer for AI-search crawler/control/report semantics.
8. Produce machine findings plus one concise human report. A scheduled run is an operator brief, not a full audit dump.
9. Require explicit current authority before indexing submission, external mutation, spend, outreach, publication, deletion, redirect/consolidation, or other consequential effect.

Never treat `llms.txt`, AI crawler training access, schema markup, prompt samples, or third-party visibility estimates as proof of Google/Bing AI citation performance. Never conflate training crawlers with search/citation crawlers.