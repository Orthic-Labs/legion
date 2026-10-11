---
name: brand-identity
description: "Create, audit, evolve, or apply brand identities, systems, guidelines, visual identity, voice, logo direction, brand books, rebrands, and the identity system behind a website or app (usage proofs only)."
kind: capability
capabilityClass: domain
discoverability: public
domain: design
operations:
  - analyze
  - decide
  - produce
  - evaluate
effects:
  - source-read
  - artifact-write
hostRequirements:
  - legion
---

# Brand Identity

PRIMARY_DELIVERABLE: Identity decisions, assets, restrictions, & QA evidence.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 1
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand, audit-visual, research
TERMINAL: Identity decisions, assets, restrictions, & QA evidence exist.

1. Load `/brand` when an existing venture is named.
2. Freeze audience, promise, positioning, constraints, assets, production media, & required deliverables.
3. Read `references/manual.md` for identity creation, evolution, audit, or application.
4. Read the project's brand registry before the differentiation guard (`references/brand-registry.md` is its template; the consuming project owns the file); use `visual-reference-libraries.md` only when visual research is needed.
5. Define one signature identity mechanism before colors, type, marks, voice, & applications.
6. Create materially divergent directions when exploration is requested.
7. Test contrast, scale, reproduction, accessibility, platform fit, & banned defaults.
8. Separate approved identity from exploration; never overwrite locked assets or rules.
9. Deliver decisions, tokens, assets, application examples, restrictions, provenance, & QA evidence.
