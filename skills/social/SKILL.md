---
name: social
description: "Route Instagram, Pinterest, YouTube, Twitter or X, LinkedIn, Reels, Shorts, pins, threads, calendars, distribution, analytics, and social growth. Use /social or when social strategy or content is the deliverable."
kind: capability
capabilityClass: domain
discoverability: public
domain: commercial
operations:
  - analyze
  - decide
  - produce
effects:
  - source-read
  - artifact-write
  - network-request
hostRequirements: []
---

# Social

PRIMARY_DELIVERABLE: Platform-native artifact or strategy.
SPECIALIST_REFS_MAX: 1 (optional extras beyond REQUIRED_READS)
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (brand code known or customer-facing output), writing (prose), designer (visual), ads (paid), marketing (positioning), qa (rendered evidence)
REQUIRED_READS:
- `references/<platform>/reference.md` or `references/content/reference.md` for the selected route
- `../_shared/anti-slop.md` for any prose output
- `../_shared/parametric-design.md` for any visual direction work
- `references/manual.md` for strategy, calendar, audit, analytics, or multi-platform work
PRECEDENCE: The selected specialist's REQUIRED_READS override this router's budget; draft mode may skip the edit pass only when the user says draft.
TERMINAL: Platform-native artifact or strategy meets frozen scope.

1. Freeze brand, platform, account, audience, objective, period, source material, constraints, & metrics.
2. Load `/brand` before branded output.
3. Route platform craft to `references/<platform>/reference.md`; route cross-platform content to `references/content/reference.md`.
4. Read `references/manual.md` for strategy, calendar, audit, analytics, or multi-platform work.
5. Use Writing for prose, Ads for paid distribution, & Marketing for positioning; media production is a host capability, not a Legion skill.
6. Verify current platform formats, limits, policies, & analytics definitions from primary sources.
7. Never invent engagement, reach, testimonials, audience evidence, or performance.
8. Return platform-native outputs plus assumptions, source links, publishing order, & measurement plan.
9. Require explicit current authority before posting, scheduling, account mutation, or spend.
