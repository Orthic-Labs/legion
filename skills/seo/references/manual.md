# SEO: Universal SEO Analysis Skill

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Bounded SEO, GEO, or AEO findings for frozen domains or URLs.
DISCOVERY_PROFILE: D3_EXTERNAL
EFFECT_PROFILES: external_research
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Requested findings meet frozen D3 source budget.

> **Vendored from** AgriciDaniel's universal SEO skill **v2.0.0** (frontmatter metadata above).
> **Local changes — preserve on any upstream sync (diff, never overwrite):** the Damned Designs
> store map + SS passive-only rule below, the native-subagent lock (no external model APIs), the
> `findings.json` machine-truth contract, and the conditional MCP lanes. An upstream update must be
> merged around these blocks, not dropped in wholesale.

**Invocation:** `/seo $1 $2` where `$1` is the command and `$2` is the URL or argument.

**Scripts:** Reach them through the portable skills symlink — `<external-reference>` — which resolves on both machines from ANY working directory. `/seo` is normally invoked from the site repo being audited (rightsites, an app repo), not from the workspace, so never use a `tools/skills/seo`-relative path or a `cd` into the workspace.

Comprehensive SEO analysis across all industries (SaaS, local services, e-commerce, publishers, agencies). Sub-references in `references/` are loaded on demand based on intent.

Uses an **LLM-first, agentic approach**: the LLM is the primary analyst with deterministic script-backed evidence for verification. For full/page audits the **machine source of truth** is `findings.json` (every finding as a structured row — agents and the box `apply-fixes-*` scripts read this, not the prose). The **one human deliverable** is `FULL-AUDIT-REPORT.md`, rendered from `findings.json` and ending in a prioritized Action Plan section. Do NOT emit a separate `ACTION-PLAN.md` — it folds into the report.

## Store Map (Damned Designs ventures)

Rotten Hand → rottenhand.com (priority 1, most active); Stunning Strangers → stunningstrangers.com (PASSIVE technical only — clean HTML/meta/schema/CWV/alt/sitemap; NO active commercial SEO, keyword campaigns, link-building, or GEO/AEO push, per brands.md SS rule); Damned Designs → damneddesigns.com (priority 3).

## Routing — match user's intent to a reference

| Intent / phrasing | Read reference |
|---|---|
| Full site audit, "audit my site", "SEO health check" | Run the workflow below — collect deterministic evidence, then fan the analysis lanes out as parallel NATIVE subagents (haiku mechanical / sonnet judgment; NO external model APIs — locked 2026-07-05) |
| Single-page deep analysis, "analyze this page" | `references/page.md` |
| **Blog post — write, audit, or upgrade (any brand blog)** | **Use `/writing blog` first. Then load `references/blog-post-contract.md` for SEO-specific validation if needed.** |
| Technical SEO (crawl, index, CWV, JS rendering) | `references/technical.md` |
| Schema / structured data / JSON-LD / rich results | `references/schema.md` (also `references/schema-markup.md`) |
| Sitemap analysis or generation | `references/sitemap.md` |
| Image SEO (alt text, file sizes, formats, CLS) | `references/images.md` |
| Image generation (OG, hero, blog, schema images) | `references/image-gen.md` |
| Hreflang / international SEO | `references/hreflang.md` |
| Local SEO (GBP, NAP, citations, location pages) | `references/local.md` |
| GEO / AEO / AI Overviews / ChatGPT search | `references/geo.md` |
| **Generate an llms.txt / pricing.md for AI crawlers ("llms.txt", "AI search file", "Perplexity file")** | **`references/llms-txt.md`** (the GENERATOR; auditing an existing llms.txt stays in `references/geo.md` via seo-geo) |
| Backlink profile, referring domains, toxic links (diagnosis) | `references/backlinks.md` |
| **Off-page / link building / digital PR / HARO / guest posts / unlinked mentions / outreach (acquisition)** | **`references/off-page.md`** |
| Programmatic SEO (template-generated pages at scale) | `references/programmatic.md` |
| Competitor/alternatives pages | `references/competitor-pages.md` |
| Live data — Ahrefs MCP queries | `references/ahrefs.md` |
| Ahrefs UI manual export, logged-in export, XLSX/CSV download, "use my Ahrefs account", "navigate Ahrefs and export" | `references/ahrefs.md` — use **Manual Export Mode** |
| Live data — DataForSEO MCP queries | `references/dataforseo.md` |
| Live data — Google Search Console / PageSpeed / CrUX | `references/google.md` |
| Free data providers, API-key setup, "which free tools", "how do I connect GSC/Bing", missing-key errors | `references/free-data-sources.md` |
| Bing rankings / Bing backlinks / instant-index a URL (IndexNow) | `scripts/bing_webmaster.py`, `scripts/indexnow.py` (setup in `references/free-data-sources.md`) |
| Crawl/scrape via Firecrawl MCP | `references/firecrawl.md` |

When invoked, decide which reference(s) match → `Read` them → follow their instructions. For a full audit, the SEO router workflow below orchestrates several refs in parallel.

## Cross-Cutting Audit Checklist

Run all five for every full audit; each can also be invoked standalone. Where the free-provider
env vars are configured (`references/free-data-sources.md`), also pull the owned-site evidence lanes:
Google Search Console (`gsc_query.py`/`gsc_inspect.py` — rankings + indexation), PageSpeed/CrUX
(field CWV), GA4 (traffic), and **Bing Webmaster** (`bing_webmaster.py` — Bing rankings, crawl issues,
your Bing backlinks). These give real index/ranking truth the crawler can't; if a key is missing the
lane is skipped (audit still runs on `site_audit.py` alone). `indexnow.py` is a push action, not an
audit read — use it to instant-index changed URLs after a fix.

0. **site-audit crawler (deterministic — run FIRST on any full/site audit)** — `seo-site-audit --url <url> --json <out>/site_audit.json --summary` crawls from the sitemap + internal links and reproduces the **Ahrefs Site Audit mechanical issue taxonomy** with no LLM judgment: broken internal links + 4xx/5xx, redirect (3xx) internal links, 3xx/4xx URLs in the sitemap, missing/empty/duplicate/too-long/too-short `<title>`, missing/duplicate/too-long/too-short meta description, missing/multiple `<h1>`, missing canonical, canonical-points-elsewhere, images missing alt, thin content (<200w), missing viewport, orphan-in-sitemap, noindex-in-sitemap, mixed content. Exit 1 if error-class issues found. This is the evidence layer the LLM lenses reason over — do NOT hand-eyeball these; run the scanner. It reads real `<a href>` anchors only (so Qwik `q:base="/build/"` and CF `/cdn-cgi/` are NOT false-flagged) and collapses trailing-slash URL variants. Full taxonomy + Ahrefs mapping: `references/site-audit-checks.md`. (Stdlib-only crawler, sites up to ~300 URLs; pair with `render_gap.mjs` for JS-rendered signals and GSC/CrUX for indexation + field CWV.)
1. **cannibalization-detector** — identify ≥2 pages targeting the same primary intent; measure authority split via position and traffic share; recommend pillar+cluster consolidation with 301/canonical to the stronger URL.
2. **intent-drift-mapper** — find pages that rank for a query whose intent (informational / commercial / transactional / navigational) mismatches the content format; emit the specific page-split or reformat recommendation per URL.
3. **render-gap-analyzer** — run `seo-render-gap --url <url>` to diff raw HTTP vs JS-rendered DOM for 8 signals (title, meta description, canonical, JSON-LD count, h1, main text length, internal links, meta robots). Client-only signals are invisible to non-rendering crawlers. NOTE: this directly fixes the DD/RH Qwik false "no schema" false-positive — Qwik renders schema/meta at runtime so raw HTML has no JSON-LD; the rendered DOM does.
4. **content-decay-tracker** — identify pages with deteriorating ranking trajectory (position trending up = worse) with no technical cause; compare last-modified date against top-3 competitor freshness; flag for content refresh or consolidation.

## Internal SEO Council

Run this internally after evidence collection and before recommendations. It is not `/review`; it is a way to separate technical, content, AI-search, and business-value lenses. Cite evidence for factual/current claims.

| Task/ref group | Role pass |
|---|---|
| Technical/page audits | Technical SEO, crawl/indexation lead, performance/CWV lead, UX/search-intent skeptic |
| Schema/structured data | Schema specialist, rich-result skeptic, entity/knowledge graph lead, implementation validator |
| GEO/AEO/AI search | Answer-extraction strategist, entity clarity lead, AI-crawler access checker, citation-worthiness skeptic |
| Local/maps | Local SEO, GBP/NAP auditor, review/reputation analyst, service-area strategist |
| Programmatic/site structure | Information architect, uniqueness/quality-gate skeptic, internal-linking lead, maintenance operator |
| Images/image-gen | Image SEO, accessibility/alt-text reviewer, performance lead, visual-brand guard |
| Backlinks/competitors | Authority analyst, toxic-link skeptic, competitor gap mapper, outreach strategist |
| Live data tools | Data-source verifier, recency checker, anomaly skeptic, action-priority lead |

Final recommendations should separate: evidence, impact, confidence, effort, and next action. Where the next action is executable, name the downstream skill and offer the handoff rather than ending at the report: technical/config fixes (redirects, sitemap, meta APIs) → dispatch Sage to plan then `/commit` to ship; thin/intent-drift content → `/writing`; CTR / hero / hierarchy problems → `/designer` (many ranking problems are presentation problems, not copy); commercial prioritisation of the findings → `/marketing`.

## Quick Reference

| Command | What it does |
|---------|-------------|
| `/seo audit <url>` | Full website audit with parallel subagent delegation |
| `/seo page <url>` | Deep single-page analysis |
| `/seo sitemap <url or generate>` | Analyze or generate XML sitemaps |
| `/seo schema <url>` | Detect, validate, and generate Schema.org markup |
| `/seo images <url>` | Image optimization analysis |
| `/seo technical <url>` | Technical SEO audit (9 categories) |
| `/seo content <url>` | E-E-A-T and content quality analysis |
| `/seo geo <url>` | AI Overviews / Generative Engine Optimization |
| `/seo llms-txt <brand>` | Generate an `llms.txt` (+ optional `/pricing.md`) for AI crawlers — DD/RH/HR/TS only, never SS |
| `/seo plan <business-type>` | Strategic SEO planning |
| `/seo programmatic [url\|plan]` | Programmatic SEO analysis and planning |
| `/seo competitor-pages [url\|generate]` | Competitor comparison page generation |
| `/seo local <url>` | Local SEO analysis (GBP, citations, reviews, map pack) |
| `/seo maps [command] [args]` | Maps intelligence (geo-grid, GBP audit, reviews, competitors) |
| `/seo hreflang [url]` | Hreflang/i18n SEO audit and generation |
| `/seo google [command] [url]` | Google SEO APIs (GSC, PageSpeed, CrUX, Indexing, GA4) |
| `/seo backlinks <url>` | Backlink profile analysis (requires DataForSEO extension) |
| `/seo off-page [tactic] <domain>` | Link/trust acquisition: digital PR/HARO, unlinked-mention reclamation, guest posting, distribution, outreach tracking (white-hat only) |
| `/seo firecrawl [command] <url>` | Full-site crawling and site mapping (extension) |
| `/seo dataforseo [command]` | Live SEO data via DataForSEO (extension) |
| `/seo ahrefs [command]` | Live SEO data via Ahrefs MCP (extension) — DR, backlinks, keywords, rank tracker, GSC, Brand Radar, site audit, web analytics |
| `/seo ahrefs manual-export [report]` | Use built-in browser only to navigate the logged-in Ahrefs UI, click official export/download controls, then parse the downloaded XLSX/CSV |
| `/seo image-gen [use-case] <description>` | AI image generation for SEO assets (extension) |
| `/seo github <repo_or_url>` | GitHub repository discoverability, README, topics, community health |
| `/seo article <url>` | Article data extraction & LLM optimization |
| `/seo links <url>` | External backlink profile & link health |
| `/seo aeo <url>` | Answer Engine Optimization (Featured Snippets, PAA, Knowledge Panel) |

## Orchestration Logic

When the user invokes `/seo audit`, use this evidence-first pipeline:
0. **Run the deterministic `site_audit.py` crawler first** (Cross-Cutting item 0) → `findings.json` seeds from its `issues`/`severity` output. Every mechanical Ahrefs-class issue (broken links, dup/missing/long titles+meta, missing/multiple h1, canonical, thin content, orphans, sitemap 3xx/4xx) comes from the scanner, not from eyeballing — the LLM lanes then verify/prioritize and add the judgment-only findings (E-E-A-T, intent, cannibalization, GEO).
1. Detect business type (SaaS, local, ecommerce, publisher, agency, other)
2. Fan the read-only reasoning lanes out as parallel NATIVE subagents (haiku for mechanical checks, sonnet for judgment; never opus, never external model APIs — the `/coder` api-worker lane is retired for this skill, locked 2026-07-05): seo-technical, seo-content, seo-schema, seo-sitemap, seo-performance, seo-geo. The main session reconciles all lane output itself.
3. If Google API credentials detected (`python legion-skill://seo/scripts/google_auth.py --check --json`), also run the seo-google lane
4. If local business detected, also spawn seo-local agent
5. If local business detected AND DataForSEO MCP available, also spawn seo-maps agent
6. If Firecrawl MCP available, use `firecrawl_map` to discover all site URLs before analysis
7. If Ahrefs MCP available (check for `site-explorer-metrics` tool), also spawn seo-ahrefs agent for DR, backlinks, organic keywords, rank tracking, GSC, and Brand Radar data — runs in parallel alongside DataForSEO if both present
8. Collect results into `findings.json`
9. Generate one unified `FULL-AUDIT-REPORT.md` with SEO Health Score (0-100) and the prioritized Action Plan folded in

For individual commands, load the relevant sub-skill directly.
Do not auto-offer or generate a PDF after routine analysis. If the approving human asks for a PDF, use `legion-skill://seo/scripts/google_report.py` or the relevant report script after the Markdown report is complete.

## Output: `findings.json` (machine) + ONE human `FULL-AUDIT-REPORT.md`

**MANDATORY after rendering (Skill Output Contract):** `skill-emit report <FULL-AUDIT-REPORT.md> --type seo --repo <site-dir>` emits the findings as OKF concepts into the memory engine; `findings.json` stays the gitignored machine cache.

`findings.json` is the source of truth — one row per finding:

```json
[{"id":"seo-001","category":"technical|content|schema|geo|images|links|local","severity":"critical|high|medium|low","url":"https://...","evidence":"file:line or crawl locus","fix":"specific action","priority":1}]
```

For portable agent consumption, also emit findings as a **compressed OKF bundle** (one concept per finding/page, required `type` frontmatter, link graph; prose compressed structure-safely) via `okf emit <out>/okf <concepts.json> --compress`. `findings.json` stays the machine source of truth and `FULL-AUDIT-REPORT.md` stays the uncompressed human deliverable. Pattern: `tools/lib/OKF-OUTPUT.md`. For agent INPUTS (page reads, repo files), prep with `crypt prep <tmp> <files...>` (code→skel, prose→compress) on SURVEY reads only. Full compaction stack: `tools/lib/CONTEXT-ENGINEERING.md`.

`FULL-AUDIT-REPORT.md` is rendered FROM `findings.json` by the main agent unless/until a dedicated renderer exists. It must include these sections in order:

1. **Health Score** — overall 0-100 weighted score + category breakdown table.
2. **Critical Blockers** — issues that block indexing or cause penalties; list with URL and fix.
3. **Semantic Opportunities** — keyword gaps, intent-drift pages, cannibalization clusters; each with estimated traffic impact.
4. **Competitive Gaps** — where top competitors outrank on authority, freshness, or schema signals; actionable.
5. **Slop Report** — mandatory section. Report: (a) AI content spam detected (thin, generic, keyword-stuffed pages without original insight); (b) keyword cannibalization instances (URL pairs + primary keyword + authority split); (c) schema theater (markup added for appearance that does not match visible page content or targets deprecated types); (d) template-tell copy (repeated kicker-then-h2 section scaffolding, and section furniture whose text restates the adjacent heading — kicker ≈ h2, deck ≈ headline; each instance with URL + the redundant pair).
6. **Action Plan** — `findings.json` sorted by severity then `priority`, as a do-this-next checklist. Replaces the old separate `ACTION-PLAN.md`.
7. **Evidence & Coverage** — which scanners/lanes ran (site_audit.py, render_gap, PageSpeed/CrUX, GSC/GA4, Ahrefs, visual) with artifact paths, and which were `skipped` with the reason.

### Scanner honesty + verdict floors (same contract as /audit and /audit-visual)

- **An absent or failed tool is `skipped` and named in the Evidence & Coverage section — never
  silently treated as clean.** A lane that didn't run proves nothing; "no findings" from a lane
  that was skipped is a coverage gap, not a pass.
- **No crawl, no health verdict.** If `site_audit.py` did not run against the live site, the
  output is labeled **Partial Review — no crawl evidence**, carries NO Health Score, and every
  mechanical claim (titles, links, canonicals, sitemap) is labeled unverified. Hand-eyeballed
  mechanical findings never substitute for the scanner.
- **Error-class floor.** While `site_audit.py` reports error-class issues (exit 1), the Health
  Score is capped below 80 and the verdict cannot be "healthy" — errors lead the Action Plan. No
  lane, subagent, or juror may average a mechanical error away; only the approving human can explicitly waive
  one, per finding.
- **Universal Hard Gates are floors, not advice:** a recommendation that fails the keyword-map,
  internal-link, schema-truth, indexability, or evidence gate is dropped or labeled
  non-compliant — it does not ship in the Action Plan as a normal item.
- Subagent lanes inherit all of the above; the main agent verifies lane outputs against
  `findings.json` before rendering the report.

## Industry Detection

Detect business type from homepage signals:
- **SaaS**: pricing page, /features, /integrations, /docs, "free trial", "sign up"
- **Local Service**: phone number, address, service area, "serving [city]", Google Maps embed --> auto-suggest `/seo local` for deeper analysis
- **E-commerce**: /products, /collections, /cart, "add to cart", product schema
- **Publisher**: /blog, /articles, /topics, article schema, author pages, publication dates
- **Agency**: /case-studies, /portfolio, /industries, "our work", client logos

## Quality Gates

SEO recommendations are not allowed to be vibes. Every material recommendation must name evidence, impact, confidence, effort, and next action.

### Parametric Content Gate (mandatory)

SEO content work (writing, auditing, or upgrading pages/posts) is parametrized per
`tools/skills/_shared/parametric-design.md`: express the target page as an explicit vector
before generating or scoring — search intent (brand/commercial/educational), entity
density, E-E-A-T level, SERP risk, and passage-citability, at minimum. The SEO default-region
fingerprint (H2-per-keyword scaffold, definition-then-list every section, FAQ blocks
restating headings) is both a scored audit defect (Slop Report item d, "template-tell
copy") and a pattern this skill must never generate — do not ship it and flag it later.

Every piece of prose this skill produces or reviews (page copy, blog drafts, meta
descriptions, FAQ answers) gets the anti-slop pass per `tools/skills/_shared/anti-slop.md`:
embedded mode (silent, pre-ship) when producing content, detect mode (named findings) when
auditing existing content. This doubles as GEO/AEO hygiene — slop patterns (rule-of-three
lists, throat-clearing, weasel attribution, fake-profound kickers) read as low-quality
signal to LLM answer engines as well as human readers.

### Universal SEO Hard Gates

- **Keyword map gate:** every page/post recommendation must identify primary query, intent, secondary cluster, and target URL. If missing, create or request the map before writing/auditing content.
- **Internal-link graph gate:** every content/page plan must include source pages, target pages, descriptive anchors, and reciprocal opportunities. Blog posts route to `/writing blog` for the stricter blog link gate.
- **Metadata gate:** title, description, canonical, robots, OG/Twitter, article/product/local metadata as appropriate.
- **Schema gate:** schema must match visible page content. Do not add schema as theater. Do not recommend deprecated rich-result schema benefits.
- **Indexability gate:** crawlability, canonicalization, robots, sitemap inclusion, redirects, and status codes must be checked before content recommendations.
- **Evidence gate:** live/current claims about traffic, rankings, SERPs, competitors, CWV, or Google behavior require tool/search evidence or must be labeled as assumptions. Recency validity: Technical SEO claims must be ≤2 years old; UX/behavioral claims ≤5 years; business/market claims ≤1 year — older sources must be labeled "potentially stale". Per-finding confidence tag required: **high** = 2+ independent sources confirming, **medium** = single strong authoritative source, **low** = inference or single weak source.
- **AI-slop gate:** no generic SEO advice such as "create high-quality content", "optimize keywords", or "build backlinks" without exact page/query/action.
- **No competitor-link gate:** for portfolio blog/site work, never recommend outbound competitor links; use neutral authority sources.
- **Authenticated SEO tool export gate:** when the user asks to use a logged-in SEO tool account such as Ahrefs to export data, use only the host's built-in browser UI automation. Do not scrape the DOM, call hidden XHR/API endpoints, use Scrapling/stealth/proxies, bypass limits, or automate anything other than normal UI navigation and official export/download buttons. Treat the exported XLSX/CSV as the evidence source.
- **Visual/site preview gate:** when SEO work requires screenshots, mobile/desktop preview, above-fold review, rendered JS inspection, or live page interaction, use the qa-engine for hidden browser evidence. Prefer the project's `qa:browser` URL when available, then `tools/lib/qa-engine/qa-shot.mjs` for viewport screenshots and `tools/lib/qa-engine/qa-functional.mjs` for click/hover/assert flows. Do not use foreground desktop screenshots for routine SEO visual evidence.

Read `references/quality-gates.md` for thin content thresholds per page type.
Hard rules:
- WARNING at 30+ location pages (enforce 60%+ unique content)
- HARD STOP at 50+ location pages (require user justification)
- Never recommend HowTo schema (deprecated Sept 2023)
- FAQ schema for Google rich results: only government and healthcare sites (Aug 2023 restriction); existing FAQPage on commercial sites -> flag Info priority (not Critical), noting AI/LLM citation benefit; adding new FAQPage -> not recommended for Google benefit
- All Core Web Vitals references use INP, never FID

## Reference Files

Load these on-demand as needed (do NOT load all at startup):
- `references/site-audit-checks.md`: the deterministic `site_audit.py` crawler's full check list + Ahrefs Site Audit issue-taxonomy mapping (run it FIRST on any full audit; see Cross-Cutting item 0)
- `references/free-data-sources.md`: the **100% free automated provider stack** (GSC, PageSpeed, CrUX, GA4, Bing Webmaster, IndexNow) — what each gives, where to get the credential, the exact PowerShell env-var setup, and why owned sites need no paid tool. Read this when a data lane errors on a missing key or when setting up a new machine/site.
- `references/cwv-thresholds.md`: Current Core Web Vitals thresholds and measurement details
- `references/schema-types.md`: All supported schema types with deprecation status
- `references/eeat-framework.md`: E-E-A-T evaluation criteria (Sept 2025 QRG update)
- `references/quality-gates.md`: Content length minimums, uniqueness thresholds
- `references/local-seo-signals.md`: Local ranking factors, review benchmarks, citation tiers, GBP status
- `references/local-schema-types.md`: LocalBusiness subtypes, industry-specific schema and citation sources

Maps-specific references (loaded by seo-maps skill, not at startup):
- `references/maps-geo-grid.md`, `references/maps-gbp-checklist.md`, `references/maps-api-endpoints.md`, `references/maps-free-apis.md`

## Scoring Methodology

### SEO Health Score (0-100)
Weighted aggregate of all categories:

| Category | Weight |
|----------|--------|
| Technical SEO | 22% |
| Content Quality | 23% |
| On-Page SEO | 20% |
| Schema / Structured Data | 10% |
| Performance (CWV) | 10% |
| AI Search Readiness | 10% |
| Images | 5% |

**Single-critical-failure escalation rule:** If any finding is rated Critical (blocks indexing, active penalty, or deindexed pages), the overall Health Score is capped at 49/100 regardless of subscore averages. Fix Critical findings before reporting an overall grade above 49.

### Priority Levels
- **Critical**: Blocks indexing or causes penalties (immediate fix required)
- **High**: Significantly impacts rankings (fix within 1 week)
- **Medium**: Optimization opportunity (fix within 1 month)
- **Low**: Nice to have (backlog)

## Sub-Skills

This skill orchestrates 15 specialized sub-skills (+ 2 extensions):

1. **seo-audit** -- Full website audit with parallel delegation
2. **seo-page** -- Deep single-page analysis
3. **seo-technical** -- Technical SEO (9 categories)
4. **seo-content** -- E-E-A-T and content quality
5. **seo-schema** -- Schema markup detection and generation
6. **seo-images** -- Image optimization
7. **seo-sitemap** -- Sitemap analysis and generation
8. **seo-geo** -- AI Overviews / GEO optimization
9. **seo-plan** -- Strategic planning with templates
10. **seo-programmatic** -- Programmatic SEO analysis and planning
11. **seo-competitor-pages** -- Competitor comparison page generation
12. **seo-hreflang** -- Hreflang/i18n SEO audit and generation
13. **seo-local** -- Local SEO (GBP, NAP, citations, reviews, local schema, multi-location)
14. **seo-maps** -- Maps intelligence (geo-grid, GBP audit, reviews, competitor radius)
15. **seo-google** -- Google SEO APIs (GSC, PageSpeed, CrUX, Indexing API, GA4)
16. **seo-backlinks** -- Backlink profile analysis (requires DataForSEO extension)
17. **seo-firecrawl** -- Full-site crawling and site mapping via Firecrawl MCP (extension)
18. **seo-dataforseo** -- Live SEO data via DataForSEO MCP (extension)
19. **seo-ahrefs** -- Live SEO data via Ahrefs MCP (extension) — DR, backlinks, organic keywords, rank tracker, site audit, Brand Radar AI visibility, GSC, web analytics
20. **seo-image-gen** -- AI image generation for SEO assets via Gemini (extension)

## Subagents

For parallel analysis during audits:
- All lanes run as NATIVE subagents (no external model APIs — locked 2026-07-05). Fan out in one message after crawl/render evidence is collected; the main session merges findings into `findings.json` itself.
- `seo-technical` -- Crawlability, indexability, security, CWV
- `seo-content` -- E-E-A-T, readability, thin content
- `seo-schema` -- Detection, validation, generation
- `seo-sitemap` -- Structure, coverage, quality gates
- `seo-performance` -- Core Web Vitals measurement
- `seo-visual` -- Screenshots, mobile testing, above-fold; use shared `qa` for hidden browser viewport evidence when a rendered URL must be opened
- `seo-geo` -- AI crawler access, llms.txt, citability, brand mention signals
- `seo-local` -- GBP signals, NAP consistency, reviews, local schema, industry-specific local factors (conditional: spawned when Local Service detected)
- `seo-maps` -- Geo-grid rank tracking, GBP audit, review intelligence, competitor radius mapping (conditional: spawned when Local Service detected AND DataForSEO MCP available)
- `seo-google` -- CWV field data, URL indexation status, organic traffic trends (conditional: spawned when Google API credentials detected)
- `seo-dataforseo` -- Live SERP, keyword, backlink, local SEO data (extension, optional)
- `seo-ahrefs` -- DR, backlinks, organic keywords, rank tracker, GSC, Brand Radar AI visibility, web analytics (extension, optional; runs alongside DataForSEO when both present)
- `seo-image-gen` -- SEO image audit and generation plan (extension, optional)
- `seo-firecrawl` -- Full-site crawl and site mapping (extension, optional; used by audit for URL discovery)

## Error Handling

| Scenario | Action |
|----------|--------|
| Unrecognized command | List available commands from the Quick Reference table. Suggest the closest matching command. |
| URL unreachable | Report the error and suggest the user verify the URL. Do not attempt to guess site content. |
| Sub-skill fails during audit | Report partial results from successful sub-skills. Clearly note which sub-skill failed and why. Suggest re-running the failed sub-skill individually. |
| Ambiguous business type detection | Pick the type with the strongest signals and proceed; if genuinely unclear after applying `/covenant`, note the assumption in the report and flag it as correctable. |
