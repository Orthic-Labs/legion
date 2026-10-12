---
name: designer
description: "Create, critique, redesign, or polish websites, app UI, dashboards, components, static creative, print, motion systems, glass materials, illustration direction, and frontend craft. Route deterministic rendered-state coverage/regression evidence to Audit Visual and identity systems to Brand Identity."
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
  - banana-image
  - web-search
---

# Designer

PRIMARY_DELIVERABLE: Rendered design artifact.
SPECIALIST_REFS_MAX: 1 (optional extras beyond REQUIRED_READS)
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 3 (web-search for fact checks; official brand-channel page and asset fetches; public asset-library downloads)
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: brand (brand code known or customer-facing output), qa (rendered evidence), writing (copy handoff), audit-visual (coverage evidence)
REQUIRED_READS:
- The selected branch's GUIDE (routes below), including every input that GUIDE names
- `../_shared/parametric-design.md` for any visual direction work
- The platform reference (`references/website.md`, `app.md`, or `native-app.md`) when a platform is named
- `../_shared/anti-slop.md` for any prose output (microcopy, copy)
- `references/manual.md` for mixed, production, unfamiliar, or non-trivial work requiring candidate comparison
- `engine/reference/critique.md` for qualitative critique; load `references/visual-qa-capture.md` when rendered evidence is needed
- `references/animations.md` when a critique assesses motion; platform-specific motion guidance remains canonical for design/implementation
PRECEDENCE: The selected specialist's REQUIRED_READS override this router's budget; exploration mode may omit completion work only when the user explicitly asks for exploration or a draft.
TERMINAL: Rendered acceptance proven.

Load `/brand` when branded. Choose exploration for explicitly rough work, deliverable for a finished standalone artifact, or ship for production work. A one-shot request does not imply exploration.

- Web or app: `specialists/surface-design/GUIDE.md`, then `references/website.md`, `app.md`, or `native-app.md`.
- Static or print: `specialists/static-creative/GUIDE.md`.
- Craft command: `engine/GUIDE.md`, then one matching command reference.
- Slides or motion render: `engine/huashu/GUIDE.md`.
- Motion: `specialists/motion/GUIDE.md`; glass: `specialists/glass/GUIDE.md`; illustration direction: `specialists/illustration/GUIDE.md`.

Read one branch plus its REQUIRED_READS. Read `references/manual.md` for mixed, production, or unfamiliar work. Freeze content, truth, platform, states, dimensions, accessibility, & acceptance. Build one exemplar before scaling. Reuse existing tokens & components. Inspect rendered states at target sizes and verify labels, controls, and artwork fit without clipping. Designer owns qualitative critique & remediation. Route deterministic rendered-state coverage/regression evidence to Audit Visual, functional/runtime checks to QA, & identity creation to Brand Identity.

**Completion check:** For non-trivial design work, confirm concrete candidate evidence exists at fidelity suited to the decision and a separate critique exists. Labels or parameter vectors alone are not evidence. If either is missing, report partial and continue; follow `references/manual.md` for candidate count and divergence. Keep trivial work proportionate; explicit exploration stays exploratory at requested fidelity.
