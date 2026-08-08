---
name: writing-profile-copy
description: Writes and iterates Instagram/LinkedIn bios, link-in-bio pages, and DM scripts aligned to brand positioning. Use when the user says "write my bio", "fix my Instagram bio", "my bio isn't converting", "help me write my link in bio", "write a DM script", "how should I pitch my offer", or anything involving how they show up when someone clicks their profile. For landing page copy, sales page copy, or persuasive offer copy, route to /writing copy instead — it owns that territory.
---

# Offer and Bio Writer

## Routing Guard

This skill owns: Instagram/LinkedIn bios, link-in-bio page copy, and DM scripts.

**Not in scope here — route to `/writing copy` instead:**
- Landing page copy (sales pages, offer pages, long-form persuasive copy)
- Lead magnet / opt-in page copy
- Product description or conversion copy that isn't a bio/link-in-bio format

Use `/writing copy` for any persuasive conversion copy with a 7-section sales-page structure. This skill handles the *profile layer* — the words that make someone click through in the first place.

Every word on your profile is either working for you or costing you. There's no neutral. The bio someone reads at 11pm decides whether they DM you tomorrow — or forget you ever existed.

If auditing a rendered link-in-bio page, landing page, profile page preview, or live URL, use `audit-visual` plus the shared `qa` skill for hidden viewport screenshots and click/CTA checks. This skill can judge words; rendered-page hierarchy needs pixels.

---

## Step 1 — Understand the Positioning

Before writing a single word, answer these:

1. **Who is this for?** (Be specific — not "people who want to grow" but "service providers who hate posting but need clients")
2. **What is the one result you deliver?** (Not what you do — what they get)
3. **Why you and not someone else?** (What's different — method, experience, perspective, story)
4. **What do you want them to do next?** (DM / Book a call / Download / Buy)
5. **What's your current #1 offer?** (Name, format, price range if relevant)

If the user hasn't answered these — ask before writing. Wrong positioning makes beautiful copy useless.

### Personal-brand layer check

When the asset is for a founder, creator, or profile, map the positioning before writing:

| Layer | Question | Output surface |
|---|---|---|
| ME | What lived experience, taste, constraint, or story makes this person recognizable? | bio line, About section, founder note |
| YOU | What does the audience get from following or clicking? | result line, content promise, lead magnet |
| MONEY | What commercial memory should the profile create? | offer line, CTA, DM keyword |

Also identify the dominant brand role: teacher, builder, curator, operator, artist, challenger, or guide. This keeps the bio from becoming a generic "I help X do Y" shell.

---

## Format 1 — Instagram Bio

### The 4-Line Bio Formula

**Line 1 — Who you help + the result**
> "I help [specific person] achieve [specific result]"
> Keep it under 10 words. No fluff.

**Line 2 — How / What makes you different**
> The method, the angle, the thing that makes you unlike everyone else in your niche.
> 1 line. Specific. Not "passionate creator."

**Line 3 — Proof or credibility signal**
> Numbers, transformation, experience, social proof.
> e.g., "Helped 200+ brands grow without ads" / "3 years of organic-only growth"

**Line 4 — CTA**
> One action. One link.
> e.g., "↓ Free brand audit" / "DM 'START' to begin" / "Get my free guide below"

### Bio Variations to Write

Always write 3 versions:
- **Version A** — Result-first (what they get)
- **Version B** — Story-first (who you are and why you do this)
- **Version C** — Provocative (a bold claim or reframe)

Present all three. Let the user feel which one sounds most like them.

### Bio Rules
- No emojis used as decoration — only as functional separators or emphasis
- No "🙌 passionate about..." — that's not a bio, that's a journal entry
- One CTA maximum — two CTAs = zero clicks
- The word "I" should appear once, maximum
- Every line must earn its space — if removing a line loses nothing, cut it

---

## Format 2 — Link-in-Bio Page Copy

### Page Structure

**Headline** (above the fold)
- What the visitor gets from being here
- Must match the promise made in the bio
- Max 8 words

**Subheadline** (1 line)
- Who this page is specifically for
- Creates instant "this is for me" feeling

**Primary CTA Button**
- Action verb + specific outcome
- e.g., "Book my free strategy call" not "Contact me"
- e.g., "Get the free guide" not "Click here"

**Secondary Links** (2–4 max)
- Named by what the visitor gets, not what the creator calls it internally
- e.g., "Watch: How I grew to 10K without ads" not "YouTube"
- e.g., "Read: My brand system (free)" not "Blog"

**Social proof snippet** (optional but powerful)
- One specific result from a real person / real data
- e.g., "Over 5,000 creators use this system" or a 1-line client quote

### Rules
- No "Welcome to my page" — they're already there
- Every link earns a click or remove it
- Mobile-first thinking — most people arrive on a phone

---

## Format 3 — DM Script (for outreach or response)

### Cold DM (reaching out first)

```
Line 1: Something specific about THEM (not about you)
Line 2: Why you're reaching out — in 1 sentence, max
Line 3: The ask — small, low-commitment, easy to say yes to
```

**Never open with**: "Hi, I'm [name], I do [thing], are you interested?"
**Always open with**: Something that proves you actually paid attention to them.

### Warm DM (they followed, liked, or commented)

```
Line 1: Reference their specific action — don't be creepy, be human
Line 2: Add value immediately — a tip, observation, or resource
Line 3 (optional): A natural soft ask — "Did this help?" / "Want me to send the full version?"
```

### Inquiry Response DM (they asked about your offer)

```
Line 1: Acknowledge — thank them, make it personal
Line 2: Qualify — ask 1–2 questions to understand their situation
Line 3: Position — explain briefly what you do based on their situation
Line 4: Next step — one clear action (call / form / voice note)
```

### DM Script Rules
- Never pitch in the first message
- Never send a wall of text
- Always end with a question or an action — never a statement that trails off
- Max 4 lines in any DM. If it needs more — it's a call, not a DM.

---

## Final Copy Check

Before delivering any copy, run this:

- [ ] Does the headline say what the visitor *gets*, not what the creator *does*?
- [ ] Is there one clear CTA — not two or three?
- [ ] Would a stranger understand this in 5 seconds on a phone screen?
- [ ] Is it written in the creator's voice — or in "professional copy" voice?
- [ ] Is there any word that could be removed without losing meaning? Remove it.
- [ ] Does the last line make you want to take action?

If any box fails — rewrite before delivering.

## Optional external jury (explicit opt-in only)

Run this external jury only when the approving human explicitly requests it.

```bash
node -e "import('file:///D:/workspace/tools/lib/auto-jury.mjs').then(m=>m.runAutoJury({
  kind: 'offer',
  artifactPath: '<absolute path to output>',
  context: { brand: '<DD|RH|HR|TS>', notes: 'offer-and-bio-writer output' },
  failHard: true
}).then(v=>console.log('verdict:', v.final_verdict||v.verdict||v.decision)).catch(e=>{console.error(e.message);process.exit(1)})"
```
