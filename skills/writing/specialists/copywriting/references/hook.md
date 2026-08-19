---
name: hook
description: Generate scroll-stopping hooks and pattern-break opening lines for content (posts, reels, scripts, ad copy, threads). Includes a 0.3-second algorithm filter that decides if content makes the cut for distribution. Use when user says "/writing copy hook", "write hooks", "hook generator", "improve this hook", "scroll-stopping", "first line", "opening line", "0.3s filter", "algorithm filter".
---

# /writing copy hook — Hook generator + 0.3s algorithm filter

Anjela Petkova's 5-prompt sequence for scroll-stopping content. Adapted for one-pass generation. Includes the 0.3s filter as a final gate (also reusable standalone inside `/writing copy` ad copy, `/writing` scripts, `/social twitter`, and content-strategy review).

## Storytelling hook canon

Before generating, run this compact craft pass:

- **Entry contract:** the first 1-2 seconds must deliver topic clarity and on-target curiosity. If the audience cannot tell what the piece is about, curiosity-bait fails.
- **Four failure modes:** delay, confusion, irrelevance, disinterest. Diagnose the weakest one before rewriting.
- **Harry's three questions:** Can the reader visualize it? Can they falsify it? Could a competitor sign it? If yes to competitor, add a concrete owner, object, number, place, or lived detail.
- **Zoom-In drill:** vague claim -> concrete object -> named scene. "Better productivity" becomes "the 4:55pm report nobody wants to open."
- **One-Mississippi test:** read the hook aloud. The topic should be clear before "one Mississippi" ends.
- **Pattern menu:** open with a question, contrast, surprise, specific number, named pain, self-referential time-of-read, before/after state, or "I tried X and Y happened."

## Inputs (ask if missing)

- **Topic / message:** what the post is about (1-2 sentences)
- **Format:** reel script / IG carousel / X thread / blog headline / ad headline / LinkedIn post
- **Brand (if applicable):** DD / RH / HR / TS — applies brand voice rules
- **Existing draft (optional):** if rewriting, paste the current version

## Output (always all 5 sections + final filter)

### 1. Pattern-Break Hooks (10 options)

Generate **10 opening lines.** Rules:
- Each creates an immediate reaction: curiosity / recognition / shock / "finally someone said it"
- Sound like walking in mid-conversation, NOT the start of an essay
- **First word in CAPS**
- ≤15 words each

### 2. Shareable Core (the screenshot sentence)

Find the ONE sentence in this content that someone would screenshot and DM a friend right now. Output:

- **The sentence** — pulled from existing content or written fresh
- **Why this lands** — 1 sentence on the tension/insight/contradiction
- **Restructured opener** — rebuild the post so the shareable sentence (or the tension that creates it) comes first

### 3. Steal the Format (architecture transplant)

If user provided a viral reference, analyze ITS format and apply to user's topic. If not, pick a relevant proven format. Output:

- **Format breakdown:** structure / rhythm / hook type / ending / what reader feels at each stage (3-5 bullets)
- **Applied to user's topic:** same architecture, completely different content

### 4. Three Emotional Entry Points

Same topic, three rewrites for three audience states:

- **Just discovered the problem** — high curiosity, low context, needs the "wait, what is this?" hook
- **Months in, frustrated** — knows the problem, tired of bad solutions, needs validation + new angle
- **Tried everything, skeptical** — has heard every promise, needs proof, specifics, or contrarian truth

Output: 3 different opening lines + 1-line note on which audience each targets.

### 5. The 0.3s Algorithm Filter (FINAL GATE)

Run this on the BEST hook from sections 1-4 (or on user's existing draft). Output:

```
0.3s ALGORITHM FILTER
─────────────────────
Hook tested: "<paste hook>"
You are the algorithm. You have 0.3 seconds.
Based on scroll-stopping power alone:

Verdict: PUSH | BORDERLINE | PASS
Why: <≤25 words — what specifically stops scroll or fails to>
The ONE change that tips it from PASS to PUSH: <specific edit>
Revised hook: <hook with the one change applied>
```

## When to use just the filter (not full skill)

If user pastes existing content and asks "would this stop scroll?" or "run the algo filter" — skip sections 1-4 and jump straight to the 0.3s filter. Same output format.

## Hard rules

- Hooks SOUND like a real person texting, not a copywriter writing
- No "Are you tired of...", "Did you know...", "In today's world..." — banned
- No emojis unless brand voice explicitly allows
- Specific > vague. "85% of textiles end up in US landfills" beats "lots of clothes get wasted"
- For brand work, apply `/brand <X>` voice rules (load via your project's brand rules file)
- Filter verdict must be ONE of PUSH / BORDERLINE / PASS — no hedging
- "The ONE change" must be concrete and editable, not "make it punchier"

## Integration

Reference (do not auto-invoke) the 0.3s filter from:
- `/writing copy` — final gate before delivering hook/headline/ad copy
- `/writing` scripts — verify reel/Shorts opening
- `/social twitter` — match the algorithm framing
- content-strategy review — pre-flight check on the calendar's strongest hooks

