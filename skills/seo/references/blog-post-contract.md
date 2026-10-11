# Blog Post Contract (enforced standard for every blog post)

**Load this for any blog work** (new posts OR auditing/upgrading existing ones). Every post, new or existing, must satisfy this contract. Brand facts (voice, positioning, products, claims) come from the brand card loaded via `/brand`; file locations, templates and CMS endpoints come from the consuming project's overlay. Nothing project-specific is hardcoded here.

## 1. Template anatomy (implemented in the project's own blog template)
Every post page must render:
- Breadcrumb nav (Home > Blog > title), visible
- Keyword-led H1, author byline + date + read-time
- **TL;DR / answer-first block**: directly above or as the first paragraph; answer the title's question in the **first sentence** (40 words or fewer, self-contained, quotable). If a one-sentence answer is not possible, lead with a 2-3 line "TL;DR:" summary. See `geo.md` (citability).
- **Hero image** (`featuredAsset` or the template's equivalent), see section 3
- **"In this guide" TOC**, auto-built from `<h2>`s (show if 3 or more); inject `id`s for anchor links
- Body with H2 sections (with ids), callouts where useful
- **Author bio block** (E-E-A-T): credentials from the project-supplied author profile, never invented
- **"Continue reading"**: 2-3 related posts plus one relevant product or category link
- Contextual **internal links** in the body, see section 4

## 2. Head / schema / meta
- Title 60 characters or fewer (strip any trailing brand suffix, append the brand once), meta description 155 characters or fewer, canonical
- OG: type=article, title, description, url, **image** (per-post hero, 1200x630, with width and height), site_name; twitter summary_large_image
- `article:published_time / modified_time / section / tag / author`
- `<meta name="robots" content="noai, noimageai">` where the site uses a training opt-out (this does not block search citation)
- **JSON-LD:** Article or BlogPosting, BreadcrumbList, Person or Organization author. Add FAQPage only when the page visibly contains the question-and-answer pairs and `schema.md` eligibility allows it; do not add it for rich-result benefit. Do not add HowTo (rich results removed; see `schema.md`).

## 3. Hero and body images
- Use real brand photography where it fits the topic, drawn from the brand's own asset library, and only where a model or lifestyle shot genuinely fits.
- **No appropriate real photo: generate one** through the `banana-image` host capability (`legion script seo/banana-generate --prompt "..." --aspect-ratio "16:9"`), with a per-post prompt, 16:9 (1920x1080) and the brand palette. If the image capability is unavailable, report the image step unavailable; do not substitute a mismatched photo.
- **Never use stock photos.** Resize any file above the CMS upload limit before upload. No native resize route exists; use a host image tool if one is provided.
- The hero asset becomes the per-post OG image through the template.

## 4. Linking
- **Internal:** 2-4 contextual links woven into the body, with reciprocal links from product or category pages to posts. Descriptive anchors, never "click here". Link to the brand's real product or shop URLs.
- **Outbound:** citations only: primary research, government, academic, standards bodies, media that reviewed or featured the brand, and the brand's own social profiles. **Never link to competitor brands.**

## 4.5 Ideation: real questions and first-hand experience
Generic AI-written posts neither rank nor get cited. Make each post specific to the approving human's real experience:
1. **Mine real questions** for the topic: People Also Ask, AlsoAsked, AnswerThePublic, forum threads, and long-tail Search Console queries (see `google.md`).
2. **Interview the approving human; do not invent.** Ask them, one question at a time, for their real experience, examples, case studies and opinions. Build the post from their answers: first-hand specifics, not fabricated stories.
3. One clear target query per post, mapped to the project's keyword map (project overlay).

## 5. Facts (hard gate)
- Every statistic or claim is **cited or removed**. No fabricated surveys, quotes, press or stats. Scope geographic statistics correctly (for example, a US-only figure must say so).
- **When auditing existing posts, verify each flag against live content before "fixing".** Automated fact audits over-flag: coherent policies can read as contradictions, cited statistics can read as uncited, and specifics can be hallucinated. Do not "fix" coherent policy or delete claims that do not exist.

## 6. Pipeline mechanics (CMS-backed blogs)
- Posts live in the CMS's blog table or equivalent. Edit body HTML through the CMS's own safe edit path; dry-run first.
- Upload images through the CMS admin API using scoped credentials supplied by the project, respecting the platform's upload size limit. Never place credentials in posts, the skill, or chat.
- Static-site blogs follow the same anatomy in their generator.

## 7. Pre-publish checklist
H1 keyword, TL;DR/answer-first sentence, meta title 60 characters or fewer with no duplicate brand suffix, meta description 155 characters or fewer, canonical, per-post OG image 1200x630, article:* meta, Article + BreadcrumbList JSON-LD (FAQPage only per section 2), TOC anchors, author bio, 2-3 internal product links plus one shop link, no competitor outbound links, all claims cited, hero from the real library or generated (never stock), noai/noimageai where used, mobile preview, submit to Search Console and Bing after publish.

> Author facts, brand facts and keyword maps are project-supplied: `<project-overlay>/seo/author-profile.md` and `<project-overlay>/seo/<brand>/keyword-map.csv`. Brand voice comes from the brand card (`/brand`).
