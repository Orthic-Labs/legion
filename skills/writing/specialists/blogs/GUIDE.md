---
name: writing-blogs
description: Use when writing, auditing, upgrading, publishing, planning, or QA-checking blog posts, article pages, blog templates, content calendars, SEO posts, founder-led posts, or any request involving blog SEO, internal links, schema, keywords, citations, or pre-publish checks.
---

# Blogs

The job is not "write an article." The job is to ship a post that can rank, convert, and survive expert review: keyword-mapped, answer-first, internally linked, cited, brand-voiced, non-generic, schema-ready, and preview-tested.

This skill is based on `<local-path>`, `<local-path>`, `<local-path>`, and `references/writing-research.md`.

Load `references/writing-research.md` for serious drafts, audits, upgrades, posts that feel generic, or any request asking for better writing craft, research depth, hooks, intros, information gain, or "why would this rank?" For blog titles, intros, TL;DRs, meta descriptions, CTAs, and section hooks, apply the copy craft gates from `<local-path>`; do not route the whole blog task to `copywriting` unless the user is writing sales/landing-page copy rather than a blog post.

## State Machine

Linear with hard gates. Never call a post done until every gate passes.

| # | Phase | Mode | Emits / blocks on |
|---|---|---|---|
| 0 | **Setup** | auto, ask if target/site unknown | site, audience, post type, target action |
| 1 | **Local corpus scan** | auto **HARD GATE** | docs/product decisions/existing posts worth turning into a post |
| 2 | **Query + intent** | auto **HARD GATE** | primary keyword/query + secondary cluster |
| 3 | **Research dossier** | auto **HARD GATE** | sources, real questions, SERP sameness, information gain |
| 4 | **Experience moat** | human touchpoint if missing | founder/expert facts, examples, opinions |
| 5 | **Outline contract** | auto **HARD GATE** | anatomy, H2 flow, CTA/link plan |
| 6 | **Draft** | auto | answer-first article in brand voice |
| 7 | **SEO/content QA** | auto **HARD GATE** | keyword, links, facts, schema, craft, anti-slop |
| 8 | **Preview/publish QA** | auto **HARD GATE** | mobile preview, image/meta/schema/publish checks |
| 9 | **Post-publish loop** | auto | GSC/Bing submission + monitoring plan |

## Phase 0: Setup

Identify:

- Site/brand
- Audience and geography
- Target reader problem
- Target action after reading
- Post type: guide, how-to, comparison, seasonal, listicle, case/story, FAQ, announcement
- Primary service/product/page this post should support
- Brand voice or site-specific writer skill

If site or target reader is unknown, ask. Do not write generic content for an unknown audience.

## Phase 1: Local Corpus Scan

Before choosing or drafting a topic, look for real local material that can become a post:

- Product and engineering decisions: PRDs, specs, ADRs, README/docs, commit history, changelogs, release notes, tickets/issues, bug reports, design notes, roadmap notes
- Customer/operator material: support logs, sales notes, founder voice notes/transcripts, research notes, call notes, FAQs, objections, examples, mistakes observed
- Existing content: current blog index, related posts, service/product pages, docs pages, landing pages, case studies, comparison pages
- Media/artifacts: screenshots, diagrams, app states, product photos, before/after examples, implementation snippets that can be safely shown

Emit one of:

- **Blog opportunity**: source material + reader question + why it deserves a post
- **Refresh opportunity**: existing post + what changed + why update beats a new URL
- **No-post decision**: why the source material is not useful, too private, too thin, or better suited to docs/changelog/social/email

Do not turn private engineering decisions, security details, secrets, unreleased roadmap, customer PII, or internal-only strategy into public copy. When in doubt, summarize the public-safe lesson and omit sensitive implementation details.

## Phase 2: Query + Intent Gate

Hard stop until these exist:

- One primary target query/keyword
- Search intent: informational, commercial, local, troubleshooting, comparison, transactional
- Secondary keyword cluster
- 4-6 FAQ questions from real related queries or plausible long-tail intent — source from real-question tools (findquestions.com, AnswerThePublic) or the GSC 8+ word query export in `seo/references/google.md`, not keyword-planner abstractions
- Ranking angle: why this post deserves to exist
- Internal destination pages: 2-3 related posts, 2-3 service/product pages, 1 pricing/contact/shop page
- Existing-post decision: create new post, refresh existing post, consolidate/canonicalize, or skip

The H1 must contain the primary keyword naturally. The first sentence must answer the title/query in 40 words or less, or a 2-3 line TL;DR must immediately follow the intro.

## Phase 3: Research Dossier

Hard stop until the post has a research basis:

- Local source material from Phase 1, with private/sensitive material filtered out
- Current blog/content inventory for this topic: existing posts, related URLs, internal link targets, duplicate/cannibalization risk
- Real reader questions from GSC, People Also Ask, forums, support logs, customer conversations, or real-question tools
- Source plan for every current, factual, legal, medical, safety, financial, or technical claim
- SERP/competitor sameness notes: what ranking pages and direct competitors already say
- Information-gain angle: what this post adds that generic competitors do not
- Examples, screenshots, product artifacts, photos, workflows, prices, timelines, or decision rules to include
- Internal link targets and target action

Never draft a serious SEO post from keyword volume or keyword-planner abstraction alone. For high-stakes/current facts, verify with primary/current sources before writing the claim.

## Phase 4: Experience Moat

Generic AI posts do not rank or persuade. Add first-hand experience before drafting.

If no real experience is provided, ask up to 10 short questions, one at a time, to surface:

- Founder/operator opinion
- Customer stories
- Real mistakes observed
- Specific prices, timelines, quantities, geography, tools, constraints
- Before/after examples
- What competitors or generic advice gets wrong

Never invent credentials, stories, surveys, case studies, quotes, or numbers.

## Phase 5: Outline Contract

Every post outline must include:

- Breadcrumb path
- Category tag
- Keyword-led H1
- Author, date, read time
- Hero image plan
- Answer-first opening or TL;DR
- "In This Guide" TOC when 3+ H2s exist
- Contextual CTA after TOC
- Logical H2 flow
- Callout boxes where useful
- Mistakes to avoid
- When to go professional / when to buy / when to contact
- FAQ with 4-6 questions
- CTA before FAQ or near close
- Author bio
- Continue Reading: 2 related posts + 1 service/product/contact page

If the outline cannot place internal links naturally, revise the topic or angle before drafting.

## Phase 6: Draft

Writing rules:

- Direct address: "you", "your"
- Concrete specifics over abstractions
- Short paragraphs
- Strong H2/H3 labels
- No padding to hit word count
- No generic AI intros
- Title, intro, and major H2s must be visualizable, falsifiable, and ownable where they make a claim
- First sentence must deliver topic clarity and speed-to-value
- Title, intro, TL;DR, meta description, CTA, and section hooks must pass the copywriting corpus gates: visualizable, falsifiable, ownable, pointable proof, every-word-works
- Every H2 must add evidence, example, decision rule, comparison, workflow, or opinionated tradeoff
- Point to concrete proof; do not merely claim expertise
- Run a But/Therefore sweep on long sections so the article has tension, tradeoffs, and decisions
- No "in today's fast-paced world", "unlock", "leverage", "game-changer", "seamless", "ultimate guide" unless the title truly requires it
- Brand mention naturally in opening or author intro
- Local references when the post is local
- Conversion CTA must match the post context, not generic site boilerplate

Length defaults:

- Guides: 1,200-2,000 words
- Tips/listicles: 800-1,200 words
- Short announcements: only as long as useful

## Phase 7: SEO / Content QA Gate

Hard stop until all pass.

### Keyword Gate

- H1 contains target keyword naturally
- Meta title <= 60 chars, includes keyword + brand, no duplicate brand suffix
- Meta description <= 155 chars, includes keyword + value/action hook
- Primary keyword appears naturally in opening
- Secondary terms appear where they genuinely belong
- No keyword stuffing

### Internal Linking Gate

- Existing blog inventory checked for related/cannibalized posts before deciding links
- 2-3 related blog links in body, contextual, not dumped in a list
- 2-3 service/product links in body where the service/product solves the issue
- 1 pricing/contact/shop link
- Continue Reading block has 2 related posts + 1 service/product/contact page
- Anchor text is descriptive and keyword-rich
- No "click here"
- Add reciprocal-link task: relevant service/product pages should link back to this post

### Outbound Link Gate

Never link to competitors or adjacent businesses, even nofollow.

Allowed outbound links only:

- Wikipedia for neutral background
- Government/municipal/official sources
- Academic/scientific sources, standards bodies, white papers
- Major organizations such as WHO, ISO, BIS where relevant
- Media that reviewed/featured the brand
- Own social profiles
- Google Maps for own location

### Fact Gate

- Every statistic, factual claim, quote, legal/medical/safety/financial claim, or technical benchmark is cited or removed
- No fabricated surveys, quotes, press, case studies, or founder stories
- Scope geo stats correctly
- For high-stakes topics, verify current facts with primary/current sources

### E-E-A-T Gate

- Author bio uses real known credentials or clearly marked role/persona
- Experience appears in body, not only author box
- The post includes first-hand specifics or a clear reason this brand can answer the query
- No invented expertise

### Information-Gain Gate

- Article uses local source material, founder/operator experience, current research, or a clear public artifact; no generic-only posts
- Every H2 earns its place with at least one of: first-hand observation, concrete example, current cited fact, comparison, decision rule, workflow/checklist/template, visual/image plan, or opinionated tradeoff
- The post explicitly improves on SERP sameness instead of repeating the same generic list
- Title, intro, and subheads pass topic clarity and speed-to-value
- Major claims are visualizable, falsifiable, and tied to the brand/source instead of competitor-pasteable
- Generic sections are deleted, merged, or rewritten with proof

### Anti-AI-Slop Gate

Fail if it contains:

- Generic opener
- Fluffy conclusion that restates the intro
- Heading furniture that restates its neighbor (kicker/eyebrow ≈ H2, subhead ≈ first sentence, H2 ≈ the paragraph it opens) — keep the stronger line, delete the echo
- Equal-weight list with no judgment
- Vague claims without proof
- Overuse of "comprehensive", "unlock", "leverage", "seamless", "transform"
- Advice that could be pasted onto any competitor site
- Stock-photo-looking imagery plan
- Sections with no information gain

## Phase 8: Preview / Publish QA Gate

Every publishable post must have:

- Canonical URL
- `meta-robots: noai, noimageai` if site policy uses it
- OG/Twitter image 1200x630 minimum
- Article metadata: author, published_time, modified_time, section, tag
- JSON-LD: Article/BlogPosting + BreadcrumbList + Person/Organization
- FAQPage JSON-LD when FAQ exists and site policy supports it; do not overclaim Google rich-result benefit for commercial sites
- HowTo JSON-LD is not recommended for Google rich-result benefit. Add it only when a non-Google consumer/site policy explicitly needs machine-readable steps, and label that rationale.
- Hero image: real brand photo or generated/commissioned, never stock
- Alt text for every image
- Images optimized, `.webp` preferred, body images lazy-loaded
- Mobile preview checked
- Lighthouse 90+ target for live/published page where applicable
- Share buttons appropriate to audience

For a live/local preview URL, use the shared `qa` skill for preview evidence instead of ad hoc browser screenshots: start the project's `qa:browser` route when available, capture viewport screenshots with `<local-path>`, and use `<local-path>` for menu/share/button/CTA checks. Capture only the page/app viewport, not the desktop.

## Phase 9: Post-Publish Loop

After publish:

- Submit URL to Google Search Console
- Submit to Bing Webmaster
- Share on appropriate brand channels
- Add 1-2 links from existing high-traffic posts
- Monitor GSC impressions/CTR after 14 days
- If CTR is below 2% with meaningful impressions, revise title/meta
- Refresh modified_time when materially updated

## Audit Mode

When auditing an existing post, report:

- Overall score out of 100
- Gate failures
- Local corpus/source-material gaps
- Keyword and intent fit
- Research dossier gaps
- Anatomy/template gaps
- Writing craft gaps: title/intro delay, generic H2s, no information gain, weak examples
- Internal link gaps
- Outbound link violations
- Citation/fact risks
- E-E-A-T gaps
- AI-slop symptoms
- Schema/meta gaps
- Image/alt/performance gaps
- Exact fixes in priority order

Do not "fix" a suspected issue without checking live/current content if the post is accessible.

## Completion Checklist

Before calling a blog post ready:

- Query + intent gate passed
- Local corpus scan passed or skipped with explicit reason
- Research dossier passed
- Experience moat included or missing-experience assumption stated
- Outline contract passed
- Draft follows brand voice
- Keyword gate passed
- Internal linking gate passed
- Outbound policy passed
- Fact gate passed
- E-E-A-T gate passed
- Information-gain gate passed
- Anti-AI-slop gate passed
- Preview/publish QA passed
- Post-publish loop defined
