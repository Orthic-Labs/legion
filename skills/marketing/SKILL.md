---
name: marketing
description: "Route positioning, offers, packaging, guarantees, launches, validation, growth, analytics, pricing, CRO, retention, and commercial ideation. Use for Grand Slam Offers or what, whom, why, and how to market; route execution to Ads, SEO, Social, Research, or Writing."
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
  - network-request
hostRequirements:
  - dataforseo
  - ahrefs
---

# Marketing

PRIMARY_DELIVERABLE: Commercial decision or specialist route.
SPECIALIST_REFS_MAX: 1 (optional extras beyond REQUIRED_READS)
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (brand code known or customer-facing output), research (evidence), ads, seo, social, writing (prose), designer (visual)
REQUIRED_READS:
- The selected branch's GUIDE or reference (routes below)
- `../_shared/anti-slop.md` for any prose output
- `../_shared/parametric-design.md` for any visual direction work (`references/visual-story.md`)
- `references/manual.md` for mixed or unfamiliar strategy
PRECEDENCE: The selected specialist's REQUIRED_READS override this router's budget; draft mode may skip the edit pass only when the user says draft.
TERMINAL: One bounded commercial decision or specialist route exists.

Load `/brand` when branded. Route one decision:

- Product context or positioning: `specialists/product-context/GUIDE.md`.
- Strategy or launch: `specialists/strategy/GUIDE.md` plus one reference.
- Validation: `references/graham.md`; rapid MVP: `specialists/daily-mvp/GUIDE.md`.
- Offer, packaging, price, bonus, or guarantee: `specialists/offer-design/GUIDE.md`.
- Growth or analytics: `specialists/growth/GUIDE.md`; conversion or retention: `specialists/cro/GUIDE.md`; ideation: `specialists/ideas/GUIDE.md`.

Read one branch plus its REQUIRED_READS. Read `references/manual.md` for mixed or unfamiliar strategy. Freeze product, market, audience, proof, economics, constraints, decision, & evidence. Separate facts from assumptions. Route evidence to Research, paid execution to Ads, search to SEO, distribution to Social, prose to Writing, & design to Designer. Never invent proof or performance.
