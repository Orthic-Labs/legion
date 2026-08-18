---
name: repurpose-content
description: >
  Atomize one piece of content into 3 platform-native variants. Use when user says "/repost-3x",
  "repurpose this", "3 versions", "platform variants", "atomize". Always /brand first. Different from
  content-repurposer (which makes 10-15) — this is focused 3-platform expansion.
---

# Repost 3x

## When to use
- You have ONE strong piece (blog, video, thread, podcast clip)
- Want it in 3 places without copy-paste
- Each platform gets native treatment

## Workflow

1. `/brand <DD|RH|HR|TS>` — SS is exempt from commercial content work; do not repurpose SS content for commercial/marketing ends
2. **Identify source:** blog / video / podcast / thread / long caption
3. **Pick 3 platforms** (defaults below)
4. **Generate native variants** — different hook, different structure, same core insight

## Brand defaults

### RH
- IG carousel (10 slides) + IG Reel (45s) + email newsletter section
- Or: blog → Pinterest pin (3 vertical variants) → IG Story sequence

### DD
- YouTube Short (60s) + IG Reel (30s) + Twitter/X thread (8 posts)
- Or: blog → email teaser → Reddit r/EDC native post

### SS
- IG carousel + Pinterest idea pin + LinkedIn long-form (visual essay)

## Variant rules

### Reel/Short/TikTok
- New hook for vertical (read-aloud test)
- Captions baked in (90% watch muted)
- hook(3s) → tension → payoff → CTA

### IG Carousel
- 10 slides max, 1 idea per slide
- Slide 1: hook image + bold text
- Slide 10: CTA to save/share/visit bio

### Twitter/X thread
- T1 = standalone hook
- T2 = stakes
- T3-N = chunked payoff (each completable)
- Last = CTA + link

### LinkedIn
- 1300-2000 chars
- First 2 lines = "see more" tease
- Storytelling > listicle

### Email
- Subject < 40 chars
- Plain text usually beats HTML
- One CTA back to source

### Pinterest
- 3 vertical (1000×1500) variants
- Each tests a different headline angle
- Optimized for Pinterest search

### Reddit
- Native: NO links if cold subreddit
- Lead with insight, not brand
- "I [did thing]. Here's what I learned."

## Output

```markdown
## Repost-3x — [source] — [brand]

### Platform 1: [name]
[Native variant, ready to post]

### Platform 2: [name]
[Native variant]

### Platform 3: [name]
[Native variant]

### Posting cadence
- Day 0: Platform 1
- Day 2: Platform 2
- Day 5: Platform 3
```

## Anti-patterns
- Same caption across platforms
- Resizing without re-hooking
- All 3 same day (looks robotic)
- Linking to source from cold platforms

## Optional external jury (explicit opt-in only)

Run this external jury only when the approving human explicitly requests it.

```bash
node -e "import('file:///src/lib/auto-jury.mjs').then(m=>m.runAutoJury({
  kind: 'copy',
  artifactPath: '<absolute path to output>',
  context: { brand: '<DD|RH|HR|TS>', notes: 'repurpose-content output' },
  failHard: true
}).then(v=>console.log('verdict:', v.final_verdict||v.verdict||v.decision)).catch(e=>{console.error(e.message);process.exit(1)})"
```
