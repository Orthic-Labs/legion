---
name: marketing-ideas
description: >
  Ideation branch. Routes to specialized references for ad/video concept variants, domain name
  brainstorming, marketing ideas (tactical + psychological). Use when user says "/marketing ideas", "brainstorm",
  "concept variants", "domain ideas", "marketing ideas", "100 concepts for", "campaign concepts".
argument-hint: "ad-concepts | domain | marketing | <freeform>"
---

# Divergent Ideation Guide

Single entry for all DIVERGENT IDEATION (generate options, not pick one). Sub-references in `references/` are loaded on demand.

## Routing - match user intent to a reference

| Intent / phrasing | Read reference |
|---|---|
| 100+ ad/video concept variants for a campaign brief | `references/ad-concepts.md` |
| Domain name brainstorming + availability check | `references/domain.md` |
| Marketing tactics + psychological principles (channel mixes, growth tactics) | `references/marketing.md` |

When invoked, decide which reference matches, Read it, follow its instructions.

## Internal Ideas Council

Use this for divergent ideation before ranking. It is a self-council for range and quality, not a verdict gate. Use `/covenant` only after there are surviving candidates to judge.

| Reference | Role pass |
|---|---|
| `ad-concepts.md` | Creative provocateur, audience pain miner, platform-native producer, feasibility filter |
| `domain.md` | Naming strategist, memorability critic, category/SEO thinker, legal/confusion skeptic |
| `marketing.md` | Channel strategist, psychology/principle mapper, operator, brand-fit skeptic |

Output standard: broad option set, clusters/themes, strongest 3-5, why they survived, and what to test next.

**Diverge first, then converge.** Pair with `/covenant` to advise, revise, and verdict the surviving candidates.
