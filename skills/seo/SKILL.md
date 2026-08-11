---
name: seo
description: "Audit or improve SEO, GEO or AEO, AI citations, crawlability, indexing, Core Web Vitals, schema, sitemaps, content quality, E-E-A-T, images, hreflang, llms.txt, traffic drops, page speed, or repository SEO."
---

# SEO

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Rerunnable SEO findings or changes.
DISCOVERY_PROFILE: D3_EXTERNAL
EFFECT_PROFILES: external_research
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: SEO findings or changes meet frozen scope with rerunnable evidence.

Freeze domain, market, language, page set, dates, repository, access, & goal.

## Route

- Technical or crawl: read `references/technical.md`, `sitemap.md`, `schema.md`, `hreflang.md`, or `cwv-thresholds.md` as needed.
- Page or content: read `references/page.md`, `eeat-framework.md`, `blog-post-contract.md`, or `images.md`.
- GEO or AI citations: read `references/geo.md` & `llms-txt.md`.
- Local: read `references/local.md` plus only relevant maps or local-schema reference.
- Links: read `references/backlinks.md`, `backlink-quality.md`, or `off-page.md`.
- Full audit or unfamiliar command: read `references/manual.md` & `quality-gates.md`.

## Execute

1. Use deterministic scripts in `scripts/` for collection, parsing, APIs, screenshots, & reports.
2. Treat tool output as evidence, not verdict; preserve raw errors & unavailable data.
3. Prefer current Google, Bing, schema.org, platform, or protocol sources for unstable rules.
4. Separate observed facts, estimates, hypotheses, & recommendations.
5. Produce machine findings plus one prioritized human report with evidence & verification.
6. Require explicit current authority before indexing submission, external mutation, or spend.
