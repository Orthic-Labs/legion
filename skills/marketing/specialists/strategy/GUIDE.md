---
name: marketing-strategy
description: >
  Top-level STRATEGY router (marketing/strategy only). Routes to specialized references for ad
  campaigns, content strategy, free tools, Graham 5-stage idea validation, product launches, SEO
  strategy/structure, visual storytelling. Use when user says "/marketing strategy", "plan a campaign", "plan a
  launch", "content plan", "SEO plan", "site structure", "validate this idea", "go-to-market".
  Engineering/code planning → Architect.
argument-hint: "ad-campaign | content | free-tool | graham | launch | seo | seo-structure | visual-story | <freeform>"
---

# Strategy and Decision Guide

Single entry for all STRATEGIC PLANNING (decision before build). The skill's reference files live at the skill root (`../../references/`); they are loaded on demand.

## Routing - match user intent to a reference

| Intent / phrasing | Read reference |
|---|---|
| Paid ad campaign architecture, channel mix, budget split | `../../references/ad-campaign.md` |
| Content strategy, calendar, what to write about | `../../references/content.md` |
| Free tool / engineering-as-marketing / lead-gen tool | `../../references/free-tool.md` |
| Idea validation, Graham 5-stage, first-10 customers, 14-day MVP | `../../references/graham.md` |
| Product launch, Product Hunt, feature release, GTM | `../../references/launch.md` |
| SEO strategy, content roadmap, competitive SEO | `../../references/seo.md` |
| Site hierarchy, URL structure, navigation, internal linking | `../../references/seo-structure.md` |
| Visual storytelling - shot-by-shot, art direction, image/video prompts | `../../references/visual-story.md` |

When invoked, decide which reference matches, Read it, follow its instructions.

> **Engineering/code planning** (ADR, implementation plan, refactor, schema/library choice) → use **Architect**, not this router. `/marketing strategy` is strategy/marketing only.

## Internal Planning Council

Run a short self-council before drafting the plan. This is an internal planning aid, not an independent review.

| Reference | Role pass |
|---|---|
| `ad-campaign.md` | Media buyer, creative strategist, tracking lead, compliance guard |
| `content.md` | Editorial strategist, channel-native planner, proof/fact checker, distribution operator |
| `free-tool.md` | Product strategist, UX lead, distribution lead, maintenance skeptic |
| `graham.md` | User-pain finder, wedge finder, first-10-customers operator, idea skeptic |
| `launch.md` | Founder, growth lead, ops lead, risk lead, customer advocate |
| `seo.md` | Technical SEO, content strategist, GEO/AEO lead, authority/link strategist |
| `seo-structure.md` | Information architect, crawl/internal-linking strategist, UX navigator, maintenance skeptic |
| `visual-story.md` | Narrative director, visual director, production operator, audience advocate |

Output standard: decision, rejected alternatives, assumptions, risks, validation path, and the smallest next move.

For a high-stakes plan, offer `/council` (or `/jury` for a verdict-only pass) AFTER drafting.

## Execution units

When a plan produces **3+ distinct execution units** (or any phased P0/P1/P2-style sequence), list them in the output: for each unit give the phase, the owning capability or channel, the acceptance criterion, and any ordering dependency. Only add a dependency where starting early would actually be wrong.

Create host tasks (`TaskCreate` / `TaskUpdate`) only if the user asks for them. Skip the list for single-step or trivial plans.
