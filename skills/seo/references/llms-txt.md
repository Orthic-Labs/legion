# llms.txt Generator (`/seo llms-txt`)

Generate `/llms.txt` for a brand site — the AI-crawler equivalent of `sitemap.xml`. It tells AI crawlers (ChatGPT, Perplexity, Claude, Google AI Overviews) what the site is about and which pages are worth citing. Spec: https://llmstxt.org.

This is the GENERATOR. The `seo-geo` subagent + `references/geo.md` handle AUDITING an existing llms.txt for compliance; come here to WRITE one.

**Trigger:** `/seo llms-txt`, "llms.txt", "AI search file", "Perplexity file", "AI crawler file", "generate an llms.txt".

> **SS EXCLUSION (hard rule):** Willow and Pine is a passion project. `llms.txt-for-ranking` is **banned** for SS (per `<private-overlay>/rules/brands.md` — SS gets the defensive AI-training block + passive technical optimization ONLY, no active commercial SEO). Never generate an llms.txt for SS. Valid brands for this generator: **DD, RH, HR, TS** (and other commercial ventures).

## Always start with

1. `/brand <DD|RH|HR|TS>` — pulls voice + positioning. (NOT SS.)
2. Site URL + crawl access (use `references/firecrawl.md` or the site's `sitemap.xml`)
3. Identify "hero content" — the pages most worth citing

## Workflow

1. **Crawl** — pull URL + title + H1 for the top 50-100 pages
2. **Categorize** — products / collections / blog / about / policies / tools
3. **Hero list** — pick 10-20 pages that, if cited, would drive the best results
4. **Write llms.txt** in spec format (template below)
5. **Optional AI-buyer file:** generate `/pricing.md` when agents need machine-readable pricing, tiers, limits, and features (mostly for software/SaaS like HR)
6. **Save** to `<local-path>` — user deploys to site root
7. **Optional:** also generate `llms-full.txt` (full content of hero pages)

## Template

```markdown
# [Brand Name]

> [One-paragraph: who you are, what you sell, what makes you different. 2-3 sentences. Brand voice.]

[Optional second paragraph: who this is for, what they'll find.]

## Products
- [Top product]: [URL] — [one-line description]

## Collections
- [Collection name]: [URL] — [one-line]

## Guides & Articles
- [Hero blog post]: [URL] — [why it matters]

## About
- About [Brand]: [URL]
- Our process: [URL]
- Sustainability/ethics (if applicable): [URL]
```

## AI-buyer file (`/pricing.md`) template

For software/SaaS, agents increasingly want machine-readable pricing. Generate a `/pricing.md` alongside `llms.txt` when the brand sells plans:

```markdown
# [Product] Pricing

> [One line: what the product does + the pricing model — one-time, subscription, freemium.]

## Plans
- **[Plan name]** — [price] [billing cadence]. [What's included, as a comma list].
- **[Plan name]** — [price] [billing cadence]. [What's included].

## Limits
- [Any usage limits, seats, device counts, fair-use caps].

## Included features
- [Feature]: [one line].

## Contact / buy
- Pricing page: [URL]
- Buy / start: [URL]
```

Keep `/pricing.md` linked from the pricing page and updated with every pricing change. (HR example: Free basic dictation + Pro one-time — confirm current locked pricing from the HR brand docs before writing numbers; never fabricate prices.)

## Brand templates

### RH
Position: ethical manufacturing, textile science, anti-fast-fashion, longevity. Hero = textile-science blog posts + collection pages.

### DD
Position: precision EDC, craftsmanship, materials science. Hero = product pages for hero SKUs + craft-process blog posts.

### HR
Position: local-first transcription + voice commands. Hero = the homepage, feature/how-it-works pages, and the pricing page. Generate a companion `/pricing.md` (machine-readable plans) since HR is software. Use the locked HR voice + banned-vocabulary list from the brand card.

### TS
Position: counter-culture streetwear, slow-fashion wedge ("the antidote to fast fashion"). Hero = manifesto/about pages + hero product/collection pages.

### SS — NOT ELIGIBLE
SS is excluded — `llms.txt-for-ranking` is banned for the passion project (`<private-overlay>/rules/brands.md`). If asked to generate an llms.txt for SS, decline and explain the SS rule.

## Deploy notes

- File at root: `https://domain.com/llms.txt` (not `/llms.txt.html`, not under `/docs`)
- Plain-text `Content-Type`
- No auth, no robots block
- Update quarterly minimum
- For software/SaaS, consider `/pricing.md` with clear plan names, prices, limits, included features, and contact route. Keep it linked from the pricing page and updated with every pricing change.

## Anti-patterns

- Listing every page (this isn't `sitemap.xml`)
- Marketing speak (LLMs cite specifics, not slogans)
- Forgetting the `>` description block (parsers expect it)
- Inventing URLs or page titles — require an actual crawl (site URL + sitemap or firecrawl) before listing any hero page
- Generating one for SS (banned — see above)
