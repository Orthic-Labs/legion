---
name: writing
description: "Draft, rewrite, or edit any prose a reader will receive: emails, internal updates and announcements, newsletters, scripts, captions, posts, documentation, proposals, specs, FAQs, blog and SEO copy, bios, DMs, product copy, and changelogs. Load before drafting: it applies the skill's voice and anti-filler checks. Use whenever words are the deliverable, even short ones."
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
hostRequirements:
  - media-production
---

# Writing

PRIMARY_DELIVERABLE: Prose artifact.
SPECIALIST_REFS_MAX: 1 (optional extras beyond REQUIRED_READS)
CHILD_AGENTS_MAX: 0 normally; 1 fresh-context Oracle for the document-coauthoring reader check
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (branded output), designer (layout handoff), social (distribution handoff), marketing (strategy handoff), seo (search intent, indexing, publish SEO), research (sourcing), ads (paid-media handoff), qa and audit-visual (rendered-page evidence), oracle and council (optional independent review)
REQUIRED_READS:
- The selected branch's GUIDE or reference (routes below)
- `../_shared/anti-slop.md` for any prose output
- `../_shared/parametric-design.md` for non-trivial pieces (see `references/manual.md`)
- `references/manual.md` for mixed work
PRECEDENCE: The selected specialist's REQUIRED_READS override this router's budget; draft mode may skip the edit pass only when the user says draft.
TERMINAL: Artifact meets brief & evidence limits.

Load `/brand` when branded. Route one deliverable:

- Editorial: `specialists/editorial/GUIDE.md`; documentation/proposals/specs: `references/document-coauthoring.md`; internal updates/newsletters/FAQs: `references/internal-comms.md`; research article: `references/research-article.md`; script: `references/script.md`; repurpose: `references/content-repurposer/reference.md`.
- SEO blog: `specialists/blogs/GUIDE.md`; persuasive copy: `specialists/copywriting/GUIDE.md`; profile: `specialists/profile-copy/GUIDE.md`; email: `specialists/email/GUIDE.md`; changelog: `specialists/changelog/GUIDE.md`.

Read one branch plus its REQUIRED_READS. Use `references/manual.md` for mixed work. Freeze audience, goal, channel, length, facts, CTA, voice, & restrictions. Never invent quotes, statistics, testimonials, stories, or product facts. Remove generic openings, repetition, unsupported claims, rhythm monotony, & wrong-channel structure. Media production is a host capability, not a Legion skill; design → Designer; distribution → Social; strategy → Marketing.
Do not infer operational procedures from audience roles: include procedures in factual drafts only when supplied or authorized, label optional recommendations as suggestions outside the draft, & provide staff/customer script guidance when explicitly requested.
