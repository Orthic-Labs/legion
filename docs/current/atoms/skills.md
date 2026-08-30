# Skills capability canon

Owner boundary: packaged domain, workflow, context capabilities & explicit entrypoints. Domains are grouping metadata only.

## Group register

| Group | Meaning |
|---|---|
| SKL-G01 | catalog, resolution & projection |
| SKL-G02 | engineering capabilities |
| SKL-G03 | research capabilities |
| SKL-G04 | commercial capabilities |
| SKL-G05 | editorial & design capabilities |
| SKL-G06 | workflows & explicit entrypoints |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| SKL-001 | SKL-G01 | Skills | COMMITTED | Load each capability from canonical `skills/<id>/SKILL.md` frontmatter & body. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `scripts/generate-skill-catalog.mjs@c498a604`; `src/registry/skill-catalog.json@c498a604` |
| SKL-002 | SKL-G01 | Skills | COMMITTED | Resolve package-internal, host-capability, project-overlay & historical-evidence references without conflation. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `src/registry/capabilities.json@c498a604`; `docs/architecture/skills.md@c498a604` |
| SKL-003 | SKL-G01 | Skills | COMMITTED | Project canonical public skills to host surfaces while keeping explicit entrypoints out of automatic catalog membership. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `scripts/generate-host-projection.mjs@c498a604`; `docs/architecture/skills.md@c498a604` |
| SKL-004 | SKL-G02 | Skills | COMMITTED | Provide Architect for architecture decisions, ADRs, invariants, interfaces & migrations. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/architect/SKILL.md@c498a604` |
| SKL-005 | SKL-G02 | Skills | COMMITTED | Provide Debugger for reproduction, disconfirmable hypotheses, root cause & routine repair selection. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/debugger/SKILL.md@c498a604` |
| SKL-006 | SKL-G02 | Skills | COMMITTED | Provide Audit for frozen-plan repository-wide evidence review. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/audit/SKILL.md@c498a604` |
| SKL-007 | SKL-G02 | Skills | COMMITTED | Provide Audit Fix for bounded remediation & same-plan rerun from frozen Audit results. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/audit-fix/SKILL.md@c498a604` |
| SKL-008 | SKL-G02 | Skills | COMMITTED | Provide Audit Visual for rendered-state inventory, capture, comparison & reconciliation. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/audit-visual/SKILL.md@c498a604` |
| SKL-009 | SKL-G02 | Skills | COMMITTED | Provide QA for local web/Tauri functional, browser, runtime & contract-test work. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/qa/SKILL.md@c498a604` |
| SKL-010 | SKL-G03 | Skills | COMMITTED | Provide Research as top-level general, technical, market, scholarly, medical, legal & audience evidence router. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/research/SKILL.md@c498a604` |
| SKL-011 | SKL-G04 | Skills | COMMITTED | Provide Marketing for positioning, offers, launches, pricing, CRO, retention & growth strategy. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/marketing/SKILL.md@c498a604` |
| SKL-012 | SKL-G04 | Skills | COMMITTED | Provide Ads for paid-campaign audit, planning, creation & optimization. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/ads/SKILL.md@c498a604` |
| SKL-013 | SKL-G04 | Skills | COMMITTED | Provide SEO for technical SEO, GEO/AEO, indexing, schema, content quality & traffic diagnosis. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/seo/SKILL.md@c498a604` |
| SKL-014 | SKL-G04 | Skills | COMMITTED | Provide Social for platform strategy, calendars, distribution, analytics & growth. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/social/SKILL.md@c498a604` |
| SKL-015 | SKL-G05 | Skills | COMMITTED | Provide Designer for product UI, frontend craft, visual systems, print, motion & critique. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/designer/SKILL.md@c498a604` |
| SKL-016 | SKL-G05 | Skills | COMMITTED | Provide Brand Identity for identity systems, naming, rebrands, guidelines & visual/voice application. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/brand-identity/SKILL.md@c498a604` |
| SKL-017 | SKL-G05 | Skills | COMMITTED | Provide Writing for editorial, conversion, product, email, social & changelog prose. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/writing/SKILL.md@c498a604` |
| SKL-018 | SKL-G06 | Skills | COMMITTED | Provide Alchemist explicit entrypoint for settled bounded controlled transformation. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/alchemist/SKILL.md@c498a604` |
| SKL-019 | SKL-G06 | Skills | COMMITTED | Provide Covenant explicit entrypoint for bounded adversarial challenge. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/covenant/SKILL.md@c498a604` |
| SKL-020 | SKL-G06 | Skills | COMMITTED | Provide Oracle explicit entrypoint for independent Completion Validation packet procedure. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/oracle/SKILL.md@c498a604` |
| SKL-021 | SKL-G06 | Skills | COMMITTED | Provide Dispatch for validated zero-context work packets while caller retains integration ownership. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/dispatch/SKILL.md@c498a604` |
| SKL-022 | SKL-G06 | Skills | COMMITTED | Provide Tasklist for executable same-agent work lists. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/tasklist/SKILL.md@c498a604` |
| SKL-023 | SKL-G06 | Skills | COMMITTED | Provide Handoff for hash-bound fresh-task continuity. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/handoff/SKILL.md@c498a604` |
| SKL-024 | SKL-G06 | Skills | COMMITTED | Provide Commit for guarded review, verification, commit & push of one frozen diff. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/commit/SKILL.md@c498a604` |
| SKL-025 | SKL-G06 | Skills | COMMITTED | Provide Coder only for explicit outsourced analysis through declared external provider CLI. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/coder/SKILL.md@c498a604` |
| SKL-026 | SKL-G06 | Skills | COMMITTED | Provide Wake for one bounded state recheck without polling loop. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/wake/SKILL.md@c498a604` |
| SKL-027 | SKL-G06 | Skills | COMMITTED | Provide Gotchas for evidence-bound recurring failure lessons. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/gotchas/SKILL.md@c498a604` |
| SKL-028 | SKL-G05 | Skills | COMMITTED | Provide Brand for loading approved brand voice, visuals, tone & restrictions before branded work. | DELIVERED | FOCUSED_PASS | NOT_REQUIRED | COMMITTED | RETAIN | `skills/brand/SKILL.md@c498a604` |
