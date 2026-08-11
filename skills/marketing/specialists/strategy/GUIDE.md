---
name: marketing-strategy
description: >
  Top-level STRATEGY router (marketing/strategy only). Routes to specialized references for ad
  campaigns, content strategy, free tools, Graham 5-stage idea validation, product launches, SEO
  strategy/structure, visual storytelling. Use when user says "/marketing strategy", "plan a campaign", "plan a
  launch", "content plan", "SEO plan", "site structure", "validate this idea", "go-to-market".
  Engineering/code planning → cortex.
argument-hint: "ad-campaign | content | free-tool | graham | launch | seo | seo-structure | visual-story | <freeform>"
---

# Strategy and Decision Guide

Single entry for all STRATEGIC PLANNING (decision before build). Sub-references in `references/` are loaded on demand.

## Routing - match user intent to a reference

| Intent / phrasing | Read reference |
|---|---|
| Paid ad campaign architecture, channel mix, budget split | `references/ad-campaign.md` |
| Content strategy, calendar, what to write about | `references/content.md` |
| Free tool / engineering-as-marketing / lead-gen tool | `references/free-tool.md` |
| Idea validation, Graham 5-stage, first-10 customers, 14-day MVP | `references/graham.md` |
| Product launch, Product Hunt, feature release, GTM | `references/launch.md` |
| SEO strategy, content roadmap, competitive SEO | `references/seo.md` |
| Site hierarchy, URL structure, navigation, internal linking | `references/seo-structure.md` |
| Visual storytelling - shot-by-shot, art direction, image/video prompts | `references/visual-story.md` |

When invoked, decide which reference matches, Read it, follow its instructions.

> **Engineering/code planning** (ADR, implementation plan, refactor, schema/library choice) → use **`cortex`**, not this router. `/marketing strategy` is strategy/marketing only.

## Internal Planning Council

Run a short self-council before drafting the plan. This is an internal planning aid, not `/review plan`; `/review plan` is still the external API jury after the draft exists.

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

Pair with `/review plan` AFTER drafting to validate via multi-LLM jury.

## Plan → tasklist handoff (MANDATORY for multi-step plans)

A plan is the thinking; a tasklist is the doing. Do not leave a phased or multi-step plan as prose only — wire it into live, checkable tasks so progress is tracked and nothing is silently skipped.

When a plan produces **3+ distinct execution units** (or any phased P0/P1/P2-style sequence):

1. **Emit tasks immediately after the plan is approved.** Create one `TaskCreate` per execution unit. Prefix the subject with the phase when phased (e.g. `[P0] …`). Put the file:line evidence and the acceptance criterion in the description so the task stands alone.
2. **Encode ordering with dependencies.** Use `TaskUpdate addBlockedBy` for hard sequencing (e.g. "write tests before the refactor"), not prose ordering. Don't over-constrain — only add a dependency where starting early would actually be wrong.
3. **Mark done as you go — never batch.** Set a task `in_progress` BEFORE starting it and `completed` the moment it's truly done (tests pass, change verified). One task in_progress at a time for sequential work. This mirrors the root `CLAUDE.md` non-negotiable: mark completed as soon as done, don't batch.
4. **Keep the list honest.** If a task is blocked, leave it `in_progress` and create a new task describing the blocker; if scope changes, update or delete the task rather than letting it rot.

Skip the tasklist only for single-step or trivial plans. For audits/reviews that yield a fix list, the same rule applies: the fix table becomes the tasklist.
