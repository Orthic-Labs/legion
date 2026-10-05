# Blog Post Contract (enforced standard for every brand blog post)

**Load this for any blog work** (new posts OR auditing/upgrading existing ones). Derived from the production blog-playbook + implemented in the Vendure/Qwik blog template 2026-05-25. Every post — new or existing — must satisfy this. Brands: DD, RH, TS, HR (SS = technical only, no marketing blog).

## 1. Template anatomy (built into `~/sites/<brand>/store/src/routes/blog/[slug]/index.tsx`)
Every post page must render:
- Breadcrumb nav (Home › Journal › title) + visible
- Keyword-led H1, author byline + date + read-time
- **TL;DR / answer-first block** — directly above or as the first paragraph, answer the title's
  question directly in the opening (self-contained & accurate). If a one-sentence
  answer isn't possible, lead with a 2–3 line "TL;DR:" summary. Use direct answers when helpful; choose length for reader task rather than a ranking formula. (See `geo.md` citability.)
- **Hero image** (`featuredAsset`) — see §3
- **"In this guide" TOC** — auto-built from `<h2>`s (show if ≥3); inject `id`s for anchor links
- Body with H2 sections (ids), callouts where useful
- **Author bio block** (E-E-A-T) — real credentials from the project-supplied author profile, never invented
- **"Continue reading"** — 2-3 related posts + 1 product/shop link (2nd routeLoader → `getBlogPosts`)
- Contextual **internal product links** in body — see §4

## 2. Head / schema / meta (in `head()` + `utils/seo.ts`)
- Title ≤60 (dedup brand suffix — strip trailing `| Brand` variants, append once), meta-desc ≤155, canonical
- OG: type=article, title, desc, url, **image (per-post `featuredAsset`, 1200×630, width+height)**, site_name; twitter summary_large_image
- `article:published_time / modified_time / section / tag / author`
- **Crawler controls:** follow project policy & documented vendor controls in `ai-search-2026.md`. Existing `noai`/`noimageai` metadata is not proof of enforced training opt-out or search access.
- **JSON-LD:** Article/BlogPosting, BreadcrumbList & truthful Person/Organization author where applicable. FAQPage/HowTo are optional only when visible content & a documented consumer justify them; neither is a mandatory blog gate or AI-citation lever. Google FAQ rich results retired May 7, 2026; see `schema-types.md`.

## 3. Hero + body images
- **Use real brand photography where topically appropriate**, drawn from whatever asset library the brand maintains, and only where a model/lifestyle shot genuinely fits the topic.
- **No appropriate real photo → GENERATE via Codex** (do NOT force a mismatched photo). Give a per-post Codex prompt + **1920×1080 (16:9)** + the brand palette suffix. Same for any DD post needing a scene/prop not in the library (workbench, etc.).
- **Never stock photos.** Resize >20MB locally before upload (Vendure caps at 20MB): `py -3.11` PIL `thumbnail((3000,3000))`.
- `featuredAsset` auto-becomes the per-post OG image via the template.

## 4. Linking
- **Internal:** 2-4 contextual product links woven into body + reciprocal (product pages → posts). Descriptive anchors, never "click here". Link to the brand's real product/shop URLs.
- **Outbound:** citations only — Wikipedia, gov, academic, standards bodies, **media that reviewed/featured the brand** (credibility links OK), own social. Respect project citation policy; comparison claims may cite first-party competitor documentation. Treat a brand-blog linking preference as scoped, not a universal ban on verifiable comparison sources.

## 4.5 Ideation — real questions + founder interview (E-E-A-T moat)
Prefer useful original evidence & real experience over generic restatement. For topics needing founder expertise:
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

## 6. Pipeline mechanics (CMS-backed blogs)
- Posts live in a `blog_post`-shaped table (cols: slug, title, excerpt, bodyHtml, `featuredAssetId`→asset, tags, publishDate…). Edit bodyHtml through the CMS's own safe edit path; dry-run first.
- Upload images through the CMS admin API using scoped bot credentials, respecting the platform's upload size limit.
- Static-site blogs follow the same anatomy in their generator.

## 7. Pre-publish checklist
Useful title & opening · deduplicated metadata · canonical · relevant OG image · truthful dates/author · applicable schema · TOC/Q&A only when useful · contextual product links & verifiable sources · appropriate hero · documented crawler policy · mobile preview. Character/image/link counts above describe project template defaults, not universal ranking gates. Indexing submission follows current authority & eligible provider workflow; publication does not automatically authorize submissions.

> Author facts and per-brand keyword maps are project-supplied: `<project-overlay>/seo/author-profile.md` and `<project-overlay>/seo/<brand>/keyword-map.csv`.
