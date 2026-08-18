---
name: ideas-ad-concepts
description: >
  Generate 100+ ad/video concept variants for a creative brief BEFORE any pixel is generated. Use when
  the user wants concepts brainstormed for a new campaign, ad, reel, or video. Trigger with /concept-pack,
  "brainstorm concepts for", "give me 100 hook variants", "ideate for a campaign", or any framing that asks
  for hook angles / concept variation / ad concepts.
  This is the upstream half of the recipe library (PJ Ace's bottleneck = ideas, not the rendering tools).
  CRITICAL: mine transcripts FIRST (real founder/creator language), then LLM-expand. Never start
  inventing concepts from scratch — that's what makes AI ads sound like AI ads.
---

# Concept Pack — 100+ ad concept variants from a brief

You generate **100+ concept variants** for a creative brief, organized by hook angle category, scored by viral-potential signal, and ready to feed into the workspace recipe library (`tools/recipes/video/`, `tools/recipes/image/` — workspace-only, part of `content`; those two are the only categories that exist).

## When this skill fires

The user typed `/concept-pack <brief>` OR asked for concepts/hooks/angles for an ad/video/campaign.

## Required inputs (ask if missing)

1. **Brand** — DD / RH / TS / HR / DV / SS — drives voice + brand-default lookups
2. **Brief** — what is the campaign/ad/launch about? 1-3 sentences.
3. **Format** — Reel / TikTok / YouTube Short / Static ad / Email / Carousel / Long-form video
4. **Length** — for video, target duration (15s / 30s / 60s)
5. **Goal** — waitlist signup / preorder / launch sale / brand awareness / content marketing
6. **Channel(s)** — IG Reels / TikTok / YouTube Shorts / Meta paid / X / LinkedIn / email

If any are missing, ask once. Don't proceed with assumed inputs.

## The two-stage process (mandatory order)

### Stage 1 — Mine transcripts FIRST

Read the existing creator transcript corpus at `<local-path>` (193+ transcripts as of 2026-05-03). Extract:

- **Real hooks** — opening lines that worked. Look for: questions, contrarian claims, pattern-interrupt lines, specific stats, sensory details, founder voice.
- **Real problem framings** — how creators describe pain points in the brief's category.
- **Real callbacks/structures** — how reels build to a payoff in 15-30s.
- **Real CTA language** — soft asks vs hard sells, how creators close.

**Sources to prioritize** (verified mined as of 2026-05-03):

| Creator | What they're known for | Files |
|---|---|---|
| `byjoeym` | 1 video → 100 face swaps via NanoBanana + Kling (PJ Ace adjacent technique) | `Video_by_byjoeym*.txt` |
| `baroobi` | 3 Claude connectors deep dives | `Video_by_baroobi.txt` |
| `gannon` | Adobe Connector for editing photos/videos | `Video_by_gannon*.txt` |
| `starter_story` | Founder interview corpus + aggregator | `starter_story_aggregate.md` |
| `copywriterpiyush` | Email/copy patterns | `Video_by_copywriterpiyush*.txt` |
| `aleksheffy`, `wright_mode` | Ecom ad creative | `Video_by_aleksheffy*.txt`, `Video_by_wright_mode*.txt` |
| `brycenwood`, `theverunmayya`, `timkoda_` | Solo SaaS / indie launch hooks | various |

Plus the user's own batches: `private-source-batch.txt`, `batch_apr8.txt`.

**Mining technique:**
1. Grep transcripts for opening lines (first 50 chars of each transcript)
2. Categorize hooks by type (curiosity / contrarian / specific-stat / pain / pattern-interrupt / question / story-led)
3. Extract 20-30 real opener patterns
4. Note the structural shape (Hook→Problem→Solution→CTA, BAB, story-arc, etc.) — most transcripts will fit one of the 12 patterns in `<local-path>`

### Stage 2 — LLM-expand from the mined patterns

Now that you have 20-30 real openers + structural patterns, expand to 100+ variants for the brief:

| Category | Count | Generation rule |
|---|---|---|
| **Comedy / IP juxtaposition** (PJ Ace pattern) | 15 | Pick familiar IP (historical setting, meme, classic film, folklore) + add product as the absurd twist |
| **Problem → Solution** | 15 | Lead with specific pain in the audience's language (mined from transcripts), pivot to product |
| **Before / After (BAB)** | 10 | Visible state change — software / EDC / wellness fits this |
| **Founder direct** | 10 | First-person, lived-experience opener (mine from transcripts where founders talk to camera) |
| **Pattern interrupt** | 10 | Visual or auditory surprise in frame 1 — colors, motion, scale, dialogue |
| **Specific stat / number** | 10 | "X% of users…" "I've spent N years…" "Y people don't know…" |
| **Question / curiosity** | 10 | Open with a question that the rest of the reel answers |
| **Contrarian claim** | 10 | "Everyone tells you X. Wrong." style |
| **Demo / show-don't-tell** | 10 | Open with the product doing the thing (best for software / mechanical products) |
| **TOTAL** | 100 | |

For each variant, output:
- 1-line hook (the opening line — what plays in 0-3s)
- Pattern category
- Brief sketch of how the rest of the ad continues (one sentence)
- Which `ad-patterns.json` template fits
- Which `aesthetics.json` preset fits (UGC / lifestyle / cinematic / documentary / etc.)
- Score: viral_potential (1-10) — your honest take on scroll-stop strength
- Score: brand_fit (1-10) — how well it aligns with the brand voice
- Status: `transcript_mined` | `llm_expanded`

## Output format

Markdown table, sorted by `(viral_potential * brand_fit)` descending:

```markdown
| # | Hook line | Pattern | Continuation sketch | ad_pattern | aesthetic | viral | brand_fit | source |
|---|---|---|---|---|---|---|---|---|
| 1 | "If your accent breaks dictation, the problem isn't you." | contrarian | Show Wispr fail → SampleApp work → CTA | hook_problem_solution_cta | documentary | 9 | 9 | transcript_mined |
| 2 | ... | ... | ... | ... | ... | ... | ... | ... |
```

Then a SUMMARY with:
- Top 10 (the ones the user should consider first)
- Honest gut check on the 100 (which categories are strongest for this brand/brief)
- Suggested next step (pick 3-5 winners → expand to full storyboard)

## Brand-specific rules

| Brand | Lean into | Avoid |
|---|---|---|
| **DD** | premium, considered, "slow is premium" motion, tactile EDC sensory | salesman language, hype, fast cuts, noisy aesthetics |
| **RH** | slow fashion as anti-fast-fashion, real textile facts, US-only stat scoping | preachy environmentalism, generic sustainability speak |
| **TS** | counter-culture energy, ALL-CAPS condensed, two-beat headlines, lived-experience | influencer slang, hype emoji, vague sustainability |
| **HR** | direct without curt, founder voice, real accent examples, V3 voice command center positioning, "Speak to type. Speak to do." | "AI assistant" framing, revolutionary/disruptive, generic dictation framing |
| **DV** | founder-as-builder, technical credibility, Linear/Cron/Arc visual peers | corporate AI buzzwords, agency-speak |
| **SS** | photography brand, yellow eyes are real, first-person voice | fabricated backstory, generic photo-influencer language |

## Anti-patterns (do NOT do these)

- Skipping stage 1 — going straight to LLM expansion produces averaged training-data slop
- Generating <100 variants — at <100 the brand doesn't have meaningful choice
- Using banned vocab from each brand's brand book (revolutionary, AI-powered, unlock, leverage, synergy, "limited time")
- Outputting a single "best" concept — Codex's acceptance gate 4 requires DIVERGENCE, not convergence
- Pretending to mine transcripts without actually reading them — be specific about which transcript each pattern came from

## What's NEXT after this skill runs

User picks 3-5 winning concepts → those concepts feed into:
- `composePrompt()` for video shots (with the picked `ad_pattern` + `aesthetic` keys)
- `composeImagePrompt()` for static ads + OG images (Phase 2)
- `composeEmail()` for email lifecycle (Phase 3)
- `composeAd()` for paid creative (Phase 4)

The output of this skill is THE input to Phases 1-4 of the recipe-library pipeline.

## Source authority

- Researched + locked 2026-05-03 alongside the recipe library build
- See `<private-overlay>/projects/D--Claude/memory/ai_video_ad_creator_playbook.md` for the full creator-research foundation
- See `<local-path>` for acceptance gates this skill feeds
