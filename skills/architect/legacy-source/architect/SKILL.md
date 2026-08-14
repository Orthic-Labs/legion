---
name: architect
description: "Design an engineering change or implementation plan grounded in Cortex and current primary sources. Use for architecture, ADRs, refactors, approach comparisons, file maps, TDD plans, or how to build something. Not for repo mapping, audits, or commercial strategy."
---

# Architect

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Evidence-grounded design or implementation plan.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: One evidence-grounded decision or implementation plan.

Use current repository evidence. Do not implement unless requested.

1. Read Cortex output, repository overlay, relevant code, tests, & existing decisions.
2. For a full design, ADR, refactor, or implementation plan, read `references/manual.md`.
3. Freeze problem, constraints, invariants, non-goals, & acceptance evidence.
4. Compare at least two viable options when a material decision exists.
5. Choose one option; state tradeoffs, reversibility, migration, rollback, & failure modes.
6. Map exact files, interfaces, data flow, tests, sequence, dependencies, & owners.
7. Separate verified current state from proposal.
8. Use current primary sources for unstable external APIs, standards, or libraries.
9. Return one executable plan; keep research notes outside it.

Do not use Architect for repository discovery (`/cortex`), whole-repo diagnosis (`/audit`), or commercial strategy (`/marketing`).
