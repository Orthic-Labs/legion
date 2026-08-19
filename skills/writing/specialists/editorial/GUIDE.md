---
name: writing-editorial
description: >
  Top-level non-conversion writing skill for essays, newsletters, long-form prose, scripts, captions, threads,
  explainers, and editorial drafts. Do not use as the primary workflow for blog SEO posts or conversion copy:
  route blog work to the writing blog branch and persuasive sales/landing/offer/email/DM copy to the
  matching writing specialist.
---

# Writing (Long & Short Form)

## Routing Guard

Before drafting, route sharper work to the more specific skill:

| If the user asks for | Use instead |
|---|---|
| Blog post, article page, SEO post, post audit, blog publish QA | `blogs` |
| Landing-page copy, sales copy, offer, bio, DM/email script, CTA, conversion copy | `copywriting` |
| Brand identity, voice system, guidelines, naming direction | `brand-identity` |
| Website/page design or app UI | `redesign` |

Use `writing-pro` only when the primary deliverable is prose rather than SEO/publish gates or conversion copy.

## Always start with

1. `/brand <brand-code>` — voice lock
2. **Identify form:** blog (1500-3000w) / caption (50-150w) / script (timed) / email / thread / About page / product copy
3. **Identify the level** (5 Levels framework below) the audience needs

## Owned generation surfaces (scripts, long-form research articles, repurposing)

This skill owns **video/carousel/long-form scripts**, **long-form research articles with citations**, and **content repurposing/atomization + content banks**. Load the matching reference on demand:

| Intent / phrasing | Read reference |
|---|---|
| YouTube / Shorts / Reels / IG-LinkedIn carousel script, "write a script", "make a reel/carousel" | `references/script.md` |
| Long-form research article with citations + iterative section-by-section writing | `references/research-article.md` |
| Focused 3-platform repurposing / "3 versions" / "repost 3x" / atomize into 3 native variants | `references/repurpose-content/reference.md` |
| Full content bank from one source / 10–15 platform-native outputs / "turn this into a content week" | `references/content-repurposer/reference.md` |

For social-platform calendars/optimization, route to `social`. For conversion ad copy + hooks, route to `copywriting`. For blog SEO posts, route to `blogs`.

## Internal Writing Council

Use this before drafting substantial writing. For routed work, inherit the more specific role pass from `/writing email`; this section covers direct `writing-pro` output.

Roles:
- **Reader Advocate:** what the audience needs to understand, feel, or do.
- **Editor:** structure, cuts, clarity, first sentence, ending.
- **Brand Voice Guard:** fit with the project's brand voice and forbidden cadence.
- **Proof/Facts Checker:** unsupported claims, citations, invented stories, quote risk.
- **Channel-Native Adapter:** blog, caption, script, email, thread, or product copy constraints.

Output standard: clean piece first, minimal rationale, proof gaps or repurpose suggestion only when useful.

## The 5 Levels Framework

Pick ONE level per piece. Mixing collapses depth.

| Level | Audience | Treatment | Length |
|---|---|---|---|
| **L1 — Child** | Brand new, zero context | Analogies, no jargon, 1 idea | 100-300w |
| **L2 — Teen** | Curious, basic context | Stories + comparisons | 300-600w |
| **L3 — Undergrad** | Engaged, wants depth | Frameworks + examples | 600-1200w |
| **L4 — Grad student** | Specialist | Tradeoffs, edge cases, citations | 1200-2500w |
| **L5 — Expert peer** | Pro talking to pro | Assumes shared vocabulary, novel synthesis | 2500w+ |

**Most marketing content = L2-L3.** Only go L4-L5 for thought leadership / SEO pillar pages.

## Workflow per form

### Blog post
1. Confirm: brand, level, target keyword (if SEO), promise to reader
2. Research via subagents (last30days + web search) — never fabricate stats
3. Outline (H2s only) → review → expand
5. Citations: link to sources, never invent quotes
6. Hook test: would you click the headline? Would you keep reading after sentence 1?
7. End with a peak (memorable image/insight) + clear next action

### Caption
- Hook in line 1 (curiosity, contrarian, specific number)
- 2-3 lines of body
- 1 CTA OR 1 question — never both
- Hashtags as bottom comment (cleaner feed)

### Video script
- Owned here — see `references/script.md` for the full Shorts/Reels, YouTube long-form, and carousel structures
- Opening 3 seconds = retention test. Earn it.
- Pattern: hook → tension → payoff → CTA
- Read aloud before approving — does it sound like a human said it?

### Email
- Routes to /email skill
- Subject < 40 chars, no all-caps, no emoji unless brand voice allows
- One CTA per email
- Plain text > HTML for nurture sequences

### Thread (Twitter/X)
- 6-12 posts max
- Each post completable on its own (algo separates them)
- T1 = hook, T2 = stakes, T3-N = payoff in chunks, last = CTA

### About page / Bio
- Route to offer-and-bio-writer
- Open with the reader's pain, not your story
- Brand story in middle (only if it earns its place)
- Close with what to do next

## Brand voice notes

| Brand | Voice tightening |
|---|---|
| **DD** | Cut 30% adjectives. Replace 2/3 of "really/very/truly" with nothing. Exclamation points are banned. |
| **RH** | Specific over vague. "85% of US textiles are dumped" beats "lots of textiles get dumped." Always cite scope. |
| **SS** | Sentences shorter than you think. Let images carry. First-person. No "we" — only "I." |

## Anti-patterns

- ChatGPT cadence: "delve / leverage / seamlessly / robust / unlock / harness"
- Empty intros: "In today's world..." / "Have you ever wondered..."
- Listicles without insight (just enumerated obvious)
- Fabricated quotes, stats, customer stories
- Mismatched level (L4 jargon in an L1 caption)
- AI-slop structures: "here's the thing," "not X but Y," "what if I told you," punchline fragments, false agency where data/markets/ideas act like people
- Vague significance claims: "the stakes are high," "this matters," "the implications are significant" without naming the concrete stake

## Stop-Slop Line Pass

Before delivery, score the draft 1-10 on directness, rhythm, trust, authenticity, and density. Below 35/50 means revise.

- Cut throat-clearing openers and meta-commentary.
- Replace passive voice with a named actor.
- Remove adverbs and softeners unless a brand voice explicitly needs them.
- Vary paragraph endings; not every paragraph gets a quotable last line.
- Put the reader in the room with a concrete scene, object, number, or decision.

## Output format

1. **Brief recap** (brand, form, level, target outcome)
2. **The piece** (clean, no internal commentary)
3. **One-line edit log** (what I changed from default)
4. **Repurpose suggestion** (1 line — if this works, what's the next 2 places to put it)

## Optional external jury (explicit opt-in only)

External review is explicit opt-in. When the approving human requests it, use the referenced surface's jury lane;
otherwise complete the inline editorial checks and deliver without an external model call.

If you produce text directly here (e.g. a quick caption rewrite), call
the auto-jury yourself before presenting:

```bash
node -e "import('@orthic-labs/legion/auto-jury').then(m=>m.runAutoJury({
  kind: 'copy',
  artifactPath: '<draft .md path>',
  context: { brand: '<brand-code>', notes: 'writing-pro direct output' },
  failHard: true
}).then(v=>console.log('verdict:', v.final_verdict||v.verdict||v.decision)).catch(e=>{console.error(e.message);process.exit(1)})"
```
