---
name: writing-email
description: >
  Email branch for lifecycle flows, newsletters, cold outreach, transactional, post-purchase, win-back.
  Consolidates cold-email, email-pro sequence, churn-prevention. Use when user says "/email", "newsletter",
  "drip", "sequence", "abandoned cart", "welcome series", "post-purchase", "win-back", "broadcast". Always
  /brand first.
---

# Email

## Routing

For detailed multi-email automation, drip, nurture, onboarding, welcome, re-engagement, or lifecycle sequence work, read:

`references/sequence/reference.md`

For simple one-off newsletters, transactional emails, cold outreach, or brand-specific lifecycle defaults, use this router file directly.

## Internal Email Council

Use a full role pass for sequences and lifecycle strategy. For a single low-stakes email, use only the relevant roles.

Roles:
- **Lifecycle Strategist:** journey stage, timing, trigger, next behavior.
- **Deliverability Guard:** spam risk, HTML/image bloat, sender trust, subject risk.
- **Copy Chief:** first sentence, clarity, specificity, one CTA.
- **Segmentation Lead:** audience split, personalization, exclusions.
- **Offer/CTA Skeptic:** incentive quality, discount damage, action friction.

Output standard: type/stage, subject variants, body, timing, success metric, and any risk note.

## Always start with
1. `/brand <DD|RH|HR|TS>` — voice lock
2. **Identify type:** lifecycle (automated) / broadcast (one-off) / cold (outbound) / transactional
3. **Identify stage:** awareness / consideration / first purchase / repeat / lapsed

## Lifecycle map (per brand)

### RH (Rotten Hand) — slow fashion ecommerce
- Welcome (3): brand story → fabric quality proof → first-customer offer
- Browse abandon (1): "still thinking about X?" + textile fact about it
- Cart abandon (3): 1h reminder → 24h with shipping/returns reassurance → 72h with social proof
- Post-purchase (4): order confirm → shipping → arrival care guide → 14-day fit check
- Win-back (2): 60-day "miss you" + new arrival → 120-day with discount
- Newsletter: 2x/month — textile science deep dive + new drop

### DD (Damned Designs) — premium EDC
- Welcome (3): origin/craft story → product depth (steel/handle/heat treat) → first-purchase incentive
- Cart abandon (2): "you left a [product]" → "still available, but limited"
- Post-purchase (3): confirm → shipping → care/sharpening guide
- Restock alert (transactional): "[product] is back"
- Newsletter: monthly — what's coming, sneak peek, EDC deep dive

**SS (Stunning Strangers) is excluded — passion project, no lifecycle/acquisition email (brands.md).**

## Subject line rules
- < 40 chars
- No all-caps, no emoji unless brand voice allows (DD = no, RH = sparing, SS = no)
- Curiosity > clarity for newsletters; clarity > curiosity for transactional
- Test 3 variants for broadcasts

## Body rules
- One CTA per email (exception: post-purchase confirm = 2 CTAs OK)
- Plain text > HTML for nurture (deliverability + trust)
- Personal sender ("the approving human" not "The DD Team") for top-of-funnel
- First sentence has to earn the second

## Cold outbound (B2B for RH wholesale, HR distribution)

This skill owns the cold-outbound surface. For deep reference (frameworks, benchmarks, personalization tiers, subject-line data, follow-up cadence) load on demand:

| Need | Read reference |
|---|---|
| Copywriting frameworks (PAS, AIDA, etc.) | `references/cold-outbound/frameworks.md` |
| Personalization at scale (4 levels, problem-linked) | `references/cold-outbound/personalization.md` |
| Subject-line optimization (length/data) | `references/cold-outbound/subject-lines.md` |
| Follow-up sequence design (count, cadence, reply data) | `references/cold-outbound/follow-up-sequences.md` |
| Benchmarks + expert methods (open/reply rates) | `references/cold-outbound/benchmarks.md` |

**Role:** Write like a peer, not a vendor. The reader should see their own situation reflected back.

**Before writing:** Identify (1) who + why them specifically, (2) desired outcome (reply/call/intro), (3) specific value prop for their role, (4) one proof point (result/case/mechanism).

**Voice rules:**
- Lead with their world ("You/your" dominates over "I/we")
- Every sentence earns its place — if removing it doesn't break the email, cut it
- Personalization must connect to the problem — decorative personalization is filler
- One ask per email; interest-based CTAs beat meeting requests ("Worth exploring?" beats "Book a 30-min call")
- Read it aloud — if it sounds like marketing copy, rewrite it

**Structure options (choose one per email):**
- Observation → Problem → Proof → Ask
- Question → Value → Ask
- Trigger (news/hire/funding) → Insight → Ask
- Story (similar company) → Bridge → Ask

**Subject lines:** 2-4 words, lowercase, no punctuation tricks, no pitch in the subject. Should look internal ("reply rates," "wholesale question," "quick thought").

**3-touch sequence:**
- Initial: personalized observation → problem → proof → ask
- Bump (4 days): different angle or fresh proof — never "just checking in"
- Break-up (10 days): honor it; short, no guilt, leaves the door open

**What to avoid:**
- "I hope this email finds you well" / "My name is X and I work at Y"
- Jargon: synergy, leverage, circle back, best-in-class, leading provider
- Feature dumps — one proof point beats ten features
- HTML, images, multiple links
- Fake Re:/Fwd: subject lines
- Identical templates with only {{FirstName}} swapped
- 30-min call ask in first touch

## Anti-patterns
- "Just checking in" / "wanted to follow up"
- HTML bloat (images-only fails spam filters)
- Two competing CTAs
- Discount as opener (kills LTV)
- Generic merge tags

## Output
1. Type + stage recap
2. Subject lines (3 variants)
3. Email body
4. Send timing recommendation
5. Success metric (open / click / reply / purchase)

