---
name: seo-off-page
description: >
  Off-page SEO and link/trust-signal ACQUISITION — the earn-links half of SEO that
  the rest of this skill only diagnoses. Digital PR / HARO (journalist sourcing +
  linkable-asset stat pages), unlinked brand-mention reclamation, guest posting,
  content distribution/syndication, and outreach tracking. Use when user says
  "link building", "get backlinks", "digital PR", "HARO", "Qwoted", "guest post",
  "outreach", "brand mentions", "unlinked mentions", "content distribution",
  "syndication", "earn links", or "off-page SEO".
user-invokable: true
argument-hint: "[tactic] [domain]"
license: MIT
metadata:
  category: seo
  version: "1.0.0"
---

# Off-Page SEO — Link & Trust-Signal Acquisition

The rest of `/seo` analyzes the link profile (`backlinks.md`: toxic links, anchor ratios,
competitor gap). **This reference is the missing half: how to actually EARN links and
brand/trust signals.** Pair with `geo.md` & `ai-search-2026.md` for observed citation opportunities. Earned presence can support discovery; correlation does not prove a ranking/citation mechanism.

## HARD GUARDRAIL — white-hat only (non-negotiable)

These tactics circulate as "growth hacks." **We never do them.** They risk manual
actions, brand damage, and violate the approving human's no-fabrication rule:

| Banned | Why |
|--------|-----|
| Buying reviews (Trustpilot/Google/G2/Glassdoor farms) | Fake testimonials; fraud; review-platform bans |
| Reddit / forum comment spam, bought upvotes | Astroturfing; subreddit + Google spam actions |
| Paid "PR" placements that are really link sells (Forbes/Reuters/Yahoo "$300–1000") | Paid links passing PageRank = link scheme |
| Parasite SEO (Medium/Substack/UGC stuffed with your links) | Thin doorway content; host crackdowns |
| Backlink-exchange / reciprocal link networks (incl. Distribb's "give links to get links") | Link scheme per Google guidelines |
| PBNs, mass directory submission, automated outreach blasts | Classic spam footprints |

Everything below is the **legitimate** version of the same goal: real relationships,
real value, real earned coverage. If a tactic requires faking a signal, stop.

---

## Tactic 1 — Digital PR / HARO (highest authority, hardest)

Earn editorial links + brand mentions from journalists by being a real source.
Pattern proven by the Qwoted skill (`github.com/Bomx/qwoted-seo-backlinks-skill`):
sourcing platforms (Qwoted, Featured, Help a B2B Writer, SourceBottle) connect experts
to reporters writing stories who need a quote/stat.

**Workflow:**
1. **Identify newsworthy evidence.** Use original research, useful tools, product demonstrations, customer evidence or real founder expertise. A sourced statistics page is one option, with no count quota. Cite primary sources for statistics; apply Article/Dataset schema only when content qualifies.
2. **Find requests** matching real expertise (the approving human: 11+ yr fashion buying → RH/TS;
   product/CNC/EDC → DD; local-first software → HR). Filter by deadline + relevance.
3. **Pitch** a tight, specific, quotable answer (2–4 sentences) + 1 stat from the asset +
   1-line credential. No fluff. Reference the asset only where it genuinely supports the story.
4. **Log every pitch** (dedupe; track placement). See Outreach Tracker below.

Evaluate audience relevance, factual accuracy, placements & qualified referrals; no placement quota or presumed ranking/citation effect.

## Tactic 2 — Unlinked brand-mention reclamation (best ROI)

Someone already mentioned the brand without linking. Converting it is the easiest link
you'll ever get — they already like you. (Tool: Unlinked.io; also Ahrefs Content Explorer /
Mentions, Google Alerts, GSC.)

**Workflow:**
1. **Find mentions:** search `"<Brand Name>" -site:<brand-domain>` (repeat per brand +
   product names + founder/spokesperson name + common misspellings) via WebSearch / Ahrefs mentions /
   Google Alerts (standing alerts per brand). Press outlets already known to have featured the
   brand are prime candidates.
2. **Qualify:** mention is live, on a reputable page, no link (or links elsewhere).
3. **Outreach:** short, warm, specific — "thanks for mentioning [brand] in [article]; if
   you're open to it, a link to [exact URL] would help readers find us." One follow-up max.
4. **Log it.**

## Tactic 3 — Guest posting (scalable, relationship-led)

Codified from the algoblueprints 2026 guest-post playbook.

**Prospect** with search operators (per niche):
`"<niche>" "write for us"`, `"guest post"`, `"submit a post"`, `"become a contributor"`,
`"contributor guidelines"` + competitor-backlink mining (Ahrefs: where do competitors have
guest links → those sites accept pitches).

**Qualify (don't chase vanity DA):**

| Tier | DA/DR | Monthly traffic | Target volume |
|------|-------|-----------------|---------------|
| Foundation | 10–29 | 1K–10K | 5–10/mo |
| Growth | 30–49 | 10K–50K | 3–5/mo |
| Authority | 50–69 | 50K–200K | 1–2/mo |
| Elite | 70+ | 200K+ | relationship-only |

Plus: spam score <5% (Moz), organic traffic trending up, fresh content <30 days, niche-relevant.
**A DA-35 niche-relevant site beats a DA-65 generalist.**

**Pitch template (<200 words):**
- Subject: `Contributor pitch: 3 ideas for <Site>'s <category>`
- Open: reference a specific recent article of theirs (proof you read it)
- Body: 2–3 tailored, data-backed topic ideas
- Proof: 2 published samples (prefer DA 50+, niche-relevant)
- Close: offer outline or full draft. **One** follow-up after 7 business days. No third.

**Content standards:** follow publisher guidelines & task-appropriate length, original research/firsthand data, clear headings,
author bio (50–100 words, verifiable credentials from the project-supplied author profile), 2–5 original/
royalty-free images w/ alt text, suggested internal links to THEIR content. Follow their
guidelines exactly. Record actual acceptance & outcomes; evaluate when the intervention maturity condition is met.

## Tactic 4 — Content distribution / syndication (amplify, don't spam)

Get existing content in front of more humans + AI crawlers — **legitimately** (NOT the
Distribb backlink-exchange). Repurpose each pillar post into: LinkedIn article (the approving human's
founder voice), a useful product/problem YouTube explainer,
genuine participation in relevant Reddit/forum/Quora threads (answer first, link only if it
truly helps), an email-list send, and brand social. Canonical-tag any full-text syndication
back to the original. Route platform specifics through `/social`.

---

## Proactive journalist beat research

Find relevant reporters & inspect recent articles. Record beat, article URLs/dates, audience fit & real story evidence; develop a specific angle consistent with their coverage. Prepare a concise tailored draft, then use existing authorized outreach/logging workflow. Newsworthiness comes from evidence, not a fixed statistic quota or a promised Knowledge Panel.

## Product demonstrations for search

Choose a customer problem/long-tail query from first-party questions & observed results. Show an actual product solving it, with accurate limitations, relevant title/description & useful CTA. Where a site watch page is warranted, apply video checks in `workflow-packs.md`. Record query, video/watch URL, product destination, publish identity & evaluation window. Measure Google/YouTube discovery, qualified referral, activation & revenue separately from views. Platform properties follow `google.md`; production routes through Legion's existing social/video capabilities.

## Evergreen affiliate/partner content

Identify relevant partners, including observed competitor affiliates; qualify audience, expertise & product fit. Map tutorial/comparison tasks, provide verifiable facts/demo access & record content URL, target query, referral identifier, relationship/disclosure, compensated-link treatment & outcome. Marketing owns offer/commission terms. Verify current platform disclosure/link rules before publication. Evaluate referred activation/revenue alongside discovery; avoid duplicate thin reviews or paid links passing ranking credit.

## Curated SaaS listings

For software/product projects, qualify individual directories/review/integration destinations by audience fit & eligibility. Record:

`project | platform | audience/eligibility evidence | profile URL | owner | facts checked | submission state | checked date | referral/outcome`

Prepare accurate profile facts, dedupe existing listings & verify resulting profile after authorized submission. Current names/fees/requirements must be checked; a saved directory list is a prospect list. Measure useful discovery/referrals, not directory volume or host DA. Do not build an extension merely to obtain a store-domain backlink.


## Outreach Tracker (always maintain)

Mirror Qwoted's pitch log. One row per prospect, per brand, to dedupe and measure:

`brand | tactic | target_domain | DA/DR | contact | url_mentioned | pitch_date | follow_up_date | status | placement_url | anchor`

Statuses: `prospect → pitched → followed_up → won → lost → no-reply`. Save as
`SEO/data/<brand>/outreach-log.csv`. Never pitch a `won`/`pitched` domain twice.

## Where this plugs into the rest of /seo

- **Targets come from** `backlinks.md` §6 competitor gap (domains linking to rivals, not us) +
  unlinked mentions found here.
- **Linkable assets** are built to `blog-post-contract.md` (cited stats, schema, author bio).
- **Brand-mention earning = AEO/GEO** — see `geo.md` Pillar 3 (Presence) + the brand-mention
  vs backlink correlation table.
- **Measure** placements + referral traffic via `seo-google` (GSC links report, GA4 referral)
  and `ahrefs` (new/lost backlinks, referring domains).

## Output

When asked to "build links" / "off-page plan" for a domain, produce `OFF-PAGE-PLAN.md`:
1. Evidence-backed linkable asset or contribution recommendation (research, expertise, useful tool or demonstration)
2. Unlinked-mention list (found via WebSearch/Ahrefs) + outreach drafts
3. Guest-post prospect list (qualified by the tier table) + pitch drafts
4. Distribution plan per pillar post
5. Outreach tracker seeded (`SEO/data/<brand>/outreach-log.csv`)
6. 30/60/90 measurement plan (GSC + GA4 + Ahrefs)

> Author facts: `<project-overlay>/seo/author-profile.md`. Brand voice: `/brand <brand-code>`.
> Never fabricate stats, reviews, quotes, or press (CLAUDE.md). White-hat guardrail above is hard.
