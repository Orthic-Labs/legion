# Blog Post Contract (enforced standard for every brand blog post)

**Load this for any blog work** (new posts OR auditing/upgrading existing ones). Derived from the production blog-playbook + implemented in the Vendure/Qwik blog template 2026-05-25. Every post — new or existing — must satisfy this. Brands: DD, RH, TS, HR (SS = technical only, no marketing blog).

## 1. Template anatomy (built into `~/sites/<brand>/store/src/routes/blog/[slug]/index.tsx`)
Every post page must render:
- Breadcrumb nav (Home › Journal › title) + visible
- Keyword-led H1, author byline + date + read-time
- **TL;DR / answer-first block** — directly above or as the first paragraph, answer the title's
  question in the **first sentence** (≤40 words, self-contained, quotable). If a one-sentence
  answer isn't possible, lead with a 2–3 line "TL;DR:" summary. This is the single highest-ROI
  AEO win — AI lifts the answer and humans don't bounce. (See `geo.md` citability.)
- **Hero image** (`featuredAsset`) — see §3
- **"In this guide" TOC** — auto-built from `<h2>`s (show if ≥3); inject `id`s for anchor links
- Body with H2 sections (ids), callouts where useful
- **Author bio block** (E-E-A-T) — real credentials from `SEO/AUTHOR-PROFILE.md`, never invented
- **"Continue reading"** — 2-3 related posts + 1 product/shop link (2nd routeLoader → `getBlogPosts`)
- Contextual **internal product links** in body — see §4

## 2. Head / schema / meta (in `head()` + `utils/seo.ts`)
- Title ≤60 (dedup brand suffix — strip trailing `| Brand` variants, append once), meta-desc ≤155, canonical
- OG: type=article, title, desc, url, **image (per-post `featuredAsset`, 1200×630, width+height)**, site_name; twitter summary_large_image
- `article:published_time / modified_time / section / tag / author`
- **`<meta name="robots" content="noai, noimageai">`** site-wide (training opt-out; does NOT block citation)
- **JSON-LD:** Article/BlogPosting + BreadcrumbList + Person/Organization author + **FAQPage** (derive from body — extractor handles BOTH `<h3>/<h4>` questions AND `<p><strong>Q?</strong></p>`; emit only if ≥2 pairs) + HowTo where step-based

## 3. Hero + body images
- **Use real brand photography where topically appropriate.** DD has a 4–5yr library (`<local-path> Drive\Damned Designs\Content`); RH = `Anshul Edits` only, and only where a model/lifestyle shot fits.
- **No appropriate real photo → GENERATE via Codex** (do NOT force a mismatched photo). Give a per-post Codex prompt + **1920×1080 (16:9)** + the brand palette suffix. Same for any DD post needing a scene/prop not in the library (workbench, etc.).
- **Never stock photos.** Resize >20MB locally before upload (Vendure caps at 20MB): `py -3.11` PIL `thumbnail((3000,3000))`.
- `featuredAsset` auto-becomes the per-post OG image via the template.

## 4. Linking
- **Internal:** 2-4 contextual product links woven into body + reciprocal (product pages → posts). Descriptive anchors, never "click here". DD products: `/products/{fenrir-fixed,cerberus-fixed,basilisk-fixed,anzu,pocket-fixed-blade}/`. RH: `/shop/{longsleeveshirt,shortsleeveshirt}/`, `/shop/`.
- **Outbound:** citations only — Wikipedia, gov, academic, standards bodies, **media that reviewed/featured the brand** (credibility links OK), own social. **Never link competitor brands.**

## 4.5 Ideation — real questions + founder interview (E-E-A-T moat)
Generic AI-written posts don't rank or get cited. Make each post unique with the approving human's real
experience:
1. **Mine real questions** for the topic — PAA boxes, AlsoAsked, AnswerThePublic, findquestions,
   Reddit/forum threads, GSC 8+ word queries (see `google.md`). Pick the actual question people ask.
2. **Interview the founder, don't invent.** Prompt: *"I'm writing a post answering <question>. Ask
   me up to 10 questions, one at a time, to surface my real experience, expertise, case studies,
   examples, and opinions."* the approving human answers (voice mode fine). Build the post from HIS answers —
   first-hand specifics, not fabricated stories (CLAUDE.md). This is the E-E-A-T the contract's
   author bio claims, delivered in the body.
3. One clear target query per post; map to the brand keyword map (`SEO/data/<brand>/keyword-map.csv`).

## 5. Facts (hard gate)
- Every statistic/claim is **cited or removed**. No fabricated surveys, quotes, press, stats. Scope geo stats correctly (e.g. "X% of textiles" is US-only).
- **When auditing existing posts, verify each flag against LIVE content before "fixing"** — an AI fact-audit over-flags (coherent dual-policies read as contradictions, cited stats read as uncited, hallucinated specifics). 2026-05-25: ~4 real issues out of ~15 flags. Don't "fix" coherent policy or delete claims that don't exist.

## 6. Pipeline mechanics (Vendure blogs: DD/RH/TS)
- Posts live in the brand DB (`vendure_db` DD, `rotten_db` RH) table `blog_post` (cols: slug, title, excerpt, bodyHtml, `featuredAssetId`→asset, tags, publishDate…). Edit bodyHtml via psql dollar-quoting; dry-run first.
- Upload images via `<local-path> <credfile> <admin-api-url> <file>` using scoped bot creds (`<local-path>`, ports 3100/3000/3200).
- Static-site blogs (HR/CF Pages) follow the same anatomy in their generator.

## 7. Pre-publish checklist
H1 keyword · TL;DR/answer-first sentence · meta title ≤60 + dedup · meta-desc ≤155 · canonical · per-post OG image 1200×630 · article:* meta · Article+BreadcrumbList+FAQPage JSON-LD · TOC anchors · 4-6 FAQ Qs · author bio · 2-3 internal product links + 1 shop · no competitor outbound · all claims cited · hero from real lib or generated (never stock) · noai/noimageai · mobile preview · submit to GSC/Bing after publish.

> Author facts: `D:/Claude/SEO/AUTHOR-PROFILE.md`. Per-brand keyword maps: `D:/Claude/SEO/data/<brand>/keyword-map.csv`. See memory `blog_template_upgrade_2026_05_25`.
