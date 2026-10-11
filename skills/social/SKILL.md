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
hostRequirements:
  - web-search
  - media-production
---

# Social

PRIMARY_DELIVERABLE: Platform-native artifact or strategy.
SPECIALIST_REFS_MAX: 1 (optional extras beyond REQUIRED_READS)
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (brand code known or customer-facing output), writing (prose and scripts), designer (visual), ads (paid), marketing (positioning), qa (rendered evidence), seo (YouTube and search optimization)
REQUIRED_READS:
- `references/<platform>/reference.md` or `references/content/reference.md` for the selected route
- `../_shared/anti-slop.md` for any prose output
- `../_shared/parametric-design.md` for any visual direction work
- `references/manual.md` for strategy, calendar, review, analytics, or multi-platform work
PRECEDENCE: The selected specialist's REQUIRED_READS override this router's budget; draft mode may skip the edit pass (`../_shared/anti-slop.md`) only when the user says draft.
TERMINAL: Platform-native artifact or strategy meets frozen scope.

1. Freeze brand, platform, account, audience, objective, period, source material, constraints, & metrics.
2. Load `/brand` before branded output.
3. Route platform craft to `references/<platform>/reference.md`; route cross-platform content to `references/content/reference.md`.
4. Read `references/manual.md` for strategy, calendar, review, analytics, or multi-platform work. Analytics definitions and the weekly review live in `references/content/reference.md` (Analytics & Optimization).
5. Use Writing for prose, Ads for paid distribution, & Marketing for positioning. Video and rich-media production is the host `media-production` capability, not a Legion skill; if the host does not provide it, deliver the shot list as text and say production was skipped.
6. Verify current platform formats, limits, policies, & analytics definitions from primary sources using the host `web-search` capability. If it is unavailable, label those rules unverified.
7. Never invent engagement, reach, testimonials, audience evidence, or performance.
8. Return platform-native outputs plus assumptions, publishing order, & measurement plan.
9. Require explicit current authority before posting, scheduling, account mutation, or spend.
