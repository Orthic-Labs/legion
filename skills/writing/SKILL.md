---
name: writing
description: "Route editorial prose, essays, newsletters, scripts, captions, threads, research articles, blogs, SEO posts, conversion copy, bios, DMs, product copy, email, and changelogs. Use when words are the deliverable."
kind: capability
capabilityClass: domain
discoverability: public
domain: editorial
operations:
  - analyze
  - produce
  - evaluate
effects:
  - source-read
  - artifact-write
hostRequirements: []
---

# Writing

PRIMARY_DELIVERABLE: Prose artifact.
SPECIALIST_REFS_MAX: 1 (optional extras beyond REQUIRED_READS)
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (brand code known or customer-facing output), designer (layout handoff), social (distribution handoff), marketing (strategy handoff)
REQUIRED_READS:
- The selected branch's GUIDE or reference (routes below)
- `../_shared/anti-slop.md` for any prose output
- `../_shared/parametric-design.md` for non-trivial pieces (see `references/manual.md`)
- `references/manual.md` for mixed work
PRECEDENCE: The selected specialist's REQUIRED_READS override this router's budget; draft mode may skip the edit pass only when the user says draft.
TERMINAL: Artifact meets brief & evidence limits.

Load `/brand` when branded. Route one deliverable:

- Editorial: `specialists/editorial/GUIDE.md`; research article: `references/research-article.md`; script: `references/script.md`; repurpose: `references/content-repurposer/reference.md`.
- SEO blog: `specialists/blogs/GUIDE.md`; persuasive copy: `specialists/copywriting/GUIDE.md`; profile: `specialists/profile-copy/GUIDE.md`; email: `specialists/email/GUIDE.md`; changelog: `specialists/changelog/GUIDE.md`.

Read one branch plus its REQUIRED_READS. Use `references/manual.md` for mixed work. Freeze audience, goal, channel, length, facts, CTA, voice, & restrictions. Never invent quotes, statistics, testimonials, stories, or product facts. Remove generic openings, repetition, unsupported claims, rhythm monotony, & wrong-channel structure. Media production is a host capability, not a Legion skill; design → Designer; distribution → Social; strategy → Marketing.
