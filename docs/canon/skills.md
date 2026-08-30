# Skills capability canon

Owner boundary: packaged domain, workflow, context capabilities & explicit entrypoints. Domains are grouping metadata only.

Required delivery boundary: `RELEASED`.

## Group register

| ID | Parent | Owner | Scope | Derived rollup |
|---|---|---|---|---|
| SKL-G01 | — | Skills | COMMITTED | catalog, resolution & projection |
| SKL-G02 | — | Skills | COMMITTED | engineering capabilities |
| SKL-G03 | — | Skills | COMMITTED | research capabilities |
| SKL-G04 | — | Skills | COMMITTED | commercial capabilities |
| SKL-G05 | — | Skills | COMMITTED | editorial & design capabilities |
| SKL-G06 | — | Skills | COMMITTED | workflows & explicit entrypoints |

## Capability ledger

| ID | Parent | Owner | Scope | Observable behavior | Implementation | Verification | Qualification | Delivery | Action | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| SKL-001 | SKL-G01 | Skills | COMMITTED | Load each capability from canonical `skills/<id>/SKILL.md` frontmatter & body. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-002 | SKL-G01 | Skills | COMMITTED | Resolve package-internal, host-capability, project-overlay & historical-evidence references without conflation. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-003 | SKL-G01 | Skills | COMMITTED | Project canonical public skills to host surfaces while keeping explicit entrypoints out of automatic catalog membership. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-004 | SKL-G02 | Architect | COMMITTED | Provide Architect for architecture decisions, ADRs, invariants, interfaces & migrations. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-005 | SKL-G02 | Debugger | COMMITTED | Provide Debugger for reproduction, disconfirmable hypotheses, root cause & routine repair selection. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-006 | SKL-G02 | Audit | COMMITTED | Provide Audit for frozen-plan repository-wide evidence review. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-007 | SKL-G02 | Audit Fix | COMMITTED | Provide Audit Fix for bounded remediation & same-plan rerun from frozen Audit results. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-008 | SKL-G02 | Audit Visual | COMMITTED | Provide Audit Visual for rendered-state inventory, capture, comparison & reconciliation. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-009 | SKL-G02 | QA | COMMITTED | Provide QA for local web/Tauri functional, browser, runtime & contract-test work. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-010 | SKL-G03 | Research | COMMITTED | Provide Research as top-level general, technical, market, scholarly, medical, legal & audience evidence router. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-011 | SKL-G04 | Marketing | COMMITTED | Provide Marketing for positioning, offers, launches, pricing, CRO, retention & growth strategy. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-012 | SKL-G04 | Ads | COMMITTED | Provide Ads for paid-campaign audit, planning, creation & optimization. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-013 | SKL-G04 | SEO | COMMITTED | Provide SEO for technical SEO, GEO/AEO, indexing, schema, content quality & traffic diagnosis. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-014 | SKL-G04 | Social | COMMITTED | Provide Social for platform strategy, calendars, distribution, analytics & growth. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-015 | SKL-G05 | Designer | COMMITTED | Provide Designer for product UI, frontend craft, visual systems, print, motion & critique. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-016 | SKL-G05 | Brand Identity | COMMITTED | Provide Brand Identity for identity systems, naming, rebrands, guidelines & visual/voice application. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-017 | SKL-G05 | Writing | COMMITTED | Provide Writing for editorial, conversion, product, email, social & changelog prose. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-018 | SKL-G06 | Alchemist | COMMITTED | Provide Alchemist explicit entrypoint for settled bounded controlled transformation. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-019 | SKL-G06 | Covenant | COMMITTED | Provide Covenant explicit entrypoint for bounded adversarial challenge. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-020 | SKL-G06 | Oracle | COMMITTED | Provide Oracle explicit entrypoint for independent Completion Validation packet procedure. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-021 | SKL-G06 | Dispatch | COMMITTED | Provide Dispatch for validated zero-context work packets while caller retains integration ownership. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-022 | SKL-G06 | Tasklist | COMMITTED | Provide Tasklist for executable same-agent work lists. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-023 | SKL-G06 | Handoff | COMMITTED | Provide Handoff for hash-bound fresh-task continuity. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-024 | SKL-G06 | Commit | COMMITTED | Provide Commit for guarded review, verification, commit & push of one frozen diff. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-025 | SKL-G06 | Coder | COMMITTED | Provide Coder only for explicit outsourced analysis through declared external provider CLI. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-026 | SKL-G06 | Wake | COMMITTED | Provide Wake for one bounded state recheck without polling loop. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-027 | SKL-G06 | Gotchas | COMMITTED | Provide Gotchas for evidence-bound recurring failure lessons. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-028 | SKL-G05 | Brand | COMMITTED | Provide Brand for loading approved brand voice, visuals, tone & restrictions before branded work. | DELIVERED | PENDING | PENDING | COMMITTED | EVIDENCE | PENDING |
| SKL-029 | SKL-G03 | Foundation | COMMITTED | Provide Foundation comparative-intelligence skill: atomic product-foundation creation (Atom protocol Stages 0-4), cross-repository comparison (absorbing retired CompShop as `/foundation compare`), audit, normalize & reconcile modes. | DELIVERED | PENDING | PENDING | LOCAL | EVIDENCE | PENDING |

## Implementation register

| ID | Capability targets | Mechanism | Source/donor | Reuse mode | State | Production consumer |
|---|---|---|---|---|---|---|
| SKL-I001 | SKL-001 | Canonical skill-catalog generation | `scripts/generate-skill-catalog.mjs@c498a604`; `src/registry/skills/index.json@c498a604` | DIRECT_PORT | DELIVERED | Catalog resolver |
| SKL-I002 | SKL-003 | Canonical public-skill host projection | `scripts/generate-host-projection.mjs@c498a604`; `docs/architecture/skills.md@c498a604` | DIRECT_PORT | DELIVERED | Host skill surfaces |
| SKL-I003 | SKL-029 | Unified Foundation skill absorbing Atom protocol (creation Stages 0-4) & CompShop (compare mode); validator ported | `skills/foundation/SKILL.md@LOCAL`; `skills/foundation/references/protocol.md@LOCAL`; `skills/foundation/references/model.md@LOCAL`; `skills/foundation/scripts/validate_atom_report.py@LOCAL` (donors: Atom archive, `compshop` workspace skill) | ADAPT | DELIVERED | Skill catalog, host projection & junctioned workspace/user skill surfaces |

## Qualification ledger

| ID | Capability targets | Acceptance boundary | State | Evidence | Material revision |
|---|---|---|---|---|---|
| SKL-Q001 | SKL-001, SKL-002, SKL-003, SKL-004, SKL-005, SKL-006, SKL-007, SKL-008, SKL-009, SKL-010, SKL-011, SKL-012, SKL-013, SKL-014, SKL-015, SKL-016, SKL-017, SKL-018, SKL-019, SKL-020, SKL-021, SKL-022, SKL-023, SKL-024, SKL-025, SKL-026, SKL-027, SKL-028 | Skills-AC-BOUNDARY-001: reconcile each observable through live consumer at RELEASED boundary | PENDING | NONE | LOCAL |

## Decision register

| ID | Kind | Capability targets | Decision | Authority/evidence | State |
|---|---|---|---|---|---|
| SKL-D001 | REFERENCE | SKL-003 | Skills owns skill projection semantics; Legion owns role & hook projection integration. | Canon reconciliation | RECORDED |
| SKL-D002 | REFERENCE | SKL-029 | Executed 2026-08-30: skill named **Foundation** (`canon` & `compshop` retained as retired aliases); canonical home `legion/skills/foundation`; workspace & user copies are junctions; Atom protocol installed as creation engine per plan Part B. Artifact directories stay `docs/canon/`. | `docs/pending/plans/2026-08-30-canon-pipeline-and-repairs.md` Part B | RECORDED |
