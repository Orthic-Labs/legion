# Content

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Media-production route or bounded content artifact
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: asset_read,output_write
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand,writing
TERMINAL: Return one bounded route or artifact; do not widen scope.

Choose the lightest existing production path that can create the requested asset. Provider names are
specialist branches, not separate skills.

## Route

| Primary deliverable | Read next |
|---|---|
| One-off image, product image, raster edit, or static visual | `references/routing.md`; use `$imagegen` when available |
| Article/concept illustration, including Xiaohei/Ian style | `references/article-illustrations.md`; add `references/xiaohei-illustration-style.md` only for that style |
| Biological-mechanical illustration for Orthic Labs or Right Suite | `tools/skills/_shared/illustrate/GUIDE.md`; use its style anchor & selected generator adapter |
| Motion graphic, animated promo/ad, composited video | `references/motion-graphics.md` |
| Remotion/React video implementation | `specialists/remotion/GUIDE.md`, then only the relevant `rules/*.md` |
| Edit captured footage into reviewed YouTube/Reels/TikTok deliverables | `specialists/video-editor/SKILL.md`; CutRight owns the local project/timeline path |
| Cinematic AI-generated shot / Seedance | `specialists/seedance/GUIDE.md` |
| Avatar, talking head, HeyGen, lipsync | `references/avatar-video.md` |
| Upscale, sharpen, denoise, or improve an existing image | `specialists/image-enhancement/GUIDE.md` |
| Reel, YouTube, TikTok, local audio/video transcription | `specialists/transcription/GUIDE.md`; ScrapeRight is the source of truth |
| Hands-off product demo, walkthrough, feature tour, cursor-driven screen recording | `specialists/demo-recorder/GUIDE.md`; runtime is `tools/demo/` |
| Extract or download slides from an existing Instagram carousel | `specialists/carousel/GUIDE.md`; runtime is `tools/pipelines/transcribe/carousel.py` |
| KDP/Etsy book, manuscript, cover, interior, listing, upload QA | `specialists/kdp/GUIDE.md`, then only its matching reference |

## Production contract

1. Load the relevant brand rules before prompts or assets.
2. Follow the current guarded pipeline for paid/provider execution. Never bypass its preflight,
   approval, review, provenance, or gallery rules.
3. Run the branch's smoke checklist before a batch or expensive render.
4. Keep intermediate provider files in scratch/cache paths and place only reviewed deliverables in
   the requested output location.
5. Adrian's eyes approve visual/video output before the pipeline advances.

## Quality gates

- **Parametrize creative briefs.** Image, motion, and video briefs get parametrized on named axes
  (composition, text_weight, palette discipline, risk) per `tools/skills/_shared/parametric-design.md`, with a
  variant spread rather than one candidate for non-trivial requests.
- **Anti-slop on embedded text.** Any caption, on-screen copy, or script text produced en route
  gets the `tools/skills/_shared/anti-slop.md` pass in embedded mode before the artifact ships.

## Boundaries

- Website, app, dashboard, static layout system, or frontend implementation -> `designer`.
- Essay, blog, email, caption, script, landing-page copy, or other words-first output -> `writing`.
- Platform calendar, audience growth, posting cadence, or channel optimization -> `social`.
- Carousel concept, copy, slide structure, or optimization -> `social`; existing-slide capture stays here.
- ScrapeGraph enrichment remains pipeline behavior inside ScrapeRight/transcript intelligence; it is
  not a separate skill.
