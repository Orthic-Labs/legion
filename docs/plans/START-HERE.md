# Audit implementation handoff

Extend existing Legion Audit in this repository. This package maps requested production coverage onto inspected source at commit `3b72295cccbfcb6633a67dc8cd06d419a646b299`.

Prepared with **legion:architect** & **legion:dispatch**. Architecture: significant / D2 / best_shape; critical rigor for authority & evidence. Eighteen bounded assignments; shared integration stays with root. This is an implementation plan, not completed source work.

## Give implementation lead this prompt

> Read the handoff package (HANDOFF; the maintainer's local archive holds its original location, which is not recorded here). Implement Audit extension described in `HANDOFF/ARCHITECTURE.md`, `HANDOFF/INTEGRATION.md` & `HANDOFF/ACCEPTANCE.md`. Respect current repository AGENTS & preserve existing dirty files, including untracked vendor/. Extend current Rust engine; no Node/Python in Audit-owned execution. Reuse existing provider/results, effect admission, snapshots, review runtime, finding store & reports. Native execution requires actual owner integration, not a trusted-offline bypass.
>
> Dispatch bounded packets below using legion:dispatch. Each worker receives WORKER-COMMON.md, one packet, needed upstream signatures & bounded source pointers; fresh context, edit-only, exact writable scope. Do not give every worker this entire package. Root integrates shared files, then runs one admitted verification batch after all coding. Do not invent successful receipts or qualification. Deliver integrated changes, observed verification & precise per-target coverage.

If handed to a nested subagent, its assignment remains edit-only: implement assigned packet(s) in dependency order, return integration notes & leave execution/checks to parent root. Initial independently dispatchable packets are **A01, A02 & A14**.

## Read only what your role needs

| Document | Use |
|---|---|
| [Architecture](ARCHITECTURE.md) | Decisions, current ownership, constraints & observable requirements |
| [Root integration](INTEGRATION.md) | Shared types, exact integration files, CLI/doc migration & verification ownership |
| [Acceptance](ACCEPTANCE.md) | Every requested stack, 22 negative cases & required checks |
| [Worker common rules](WORKER-COMMON.md) | Scope, exclusions, edit-only execution & return protocol |
| [RightKit capabilities](RIGHTKIT-CAPABILITIES.txt) | Inspected shared-owner inventory; availability is not integration proof |

Earlier [master design](../MASTER-AUDIT-DESIGN.md) & [fixture catalog](../RULE-FIXTURES.md) explain rationale. This folder overrides earlier illustrative CLI/module proposals where source inspection identified existing owners.

## Assignments

| Packet | Change | Prerequisites | Role |
|---|---|---|---|
| [A01](packets/A01-native-admission.md) | Native owner admission & sandboxed execution | Preflight | Specialist |
| [A02](packets/A02-coverage-profiles.md) | Product obligations, qualification scope & runtime constraints | Preflight | Specialist |
| [A03](packets/A03-authenticated-imports.md) | Authenticated build, test, runtime & artifact imports | A02 | Specialist |
| [A04](packets/A04-detekt.md) | Independent Kotlin source & typed detekt coverage | A01, A02 | Alchemist |
| [A05](packets/A05-android-lint.md) | Android variants, Lint & platform execution | A01, A02, A03 | Specialist |
| [A06](packets/A06-apple-targets.md) | Xcode/iOS target coverage beyond SwiftPM | A01, A02, A03 | Specialist |
| [A07](packets/A07-native-web.md) | Node-free JS/TS lint coverage & Qwik applicability | A01, A02, A03 | Alchemist |
| [A08](packets/A08-dependency-health.md) | Dependency inventory, advisories & maintenance | A01, A02, A03 | Alchemist |
| [A09](packets/A09-structure-quality.md) | Native structural analysis, dead-code candidates & decomposition | A02 | Alchemist |
| [A10](packets/A10-postgres.md) | PostgreSQL migration safety & workload evidence | A01, A02, A03 | Specialist |
| [A11](packets/A11-nginx.md) | Effective Nginx configuration & deployed behavior | A01, A02, A03 | Specialist |
| [A12](packets/A12-domain-contracts.md) | Domain vocabulary & cross-repository contracts | A02, A03 | Specialist |
| [A13](packets/A13-semantic-packs.md) | Platform semantic cards, security & production invariants | A02, A12 | Specialist |
| [A14](packets/A14-source-anchors.md) | Canonical source anchors & safe PR projection | Preflight | Specialist |
| [A15](packets/A15-finding-lifecycle.md) | Context-aware finding history, debt & trends | A02, A08, A12, A14 | Specialist |
| [A16](packets/A16-runtime-journeys.md) | Production journeys, performance & release artifact matrices | A02, A03, A05, A06, A07, A10, A11, A12 | Specialist |
| [A17](packets/A17-review-budget.md) | Review packet completeness & bounded parallel execution | A02, A12 | Specialist |
| [A18](packets/A18-native-qualification.md) | Native qualification checks & adversarial acceptance corpus | A02 | Specialist |

“Specialist” means `alchemist-specialist`; each packet states why ordinary compilation would miss material risk. Other assignments use `alchemist`. All packet writable scopes are disjoint. Root retains Cargo/exports/registries/CLI/generated files.

## Dispatch order

1. **Foundations:** A01 admission, A02 obligations, A14 anchors.
2. **Available after foundations:** A03 imports, A04 detekt, A09 structure, A18 qualification validator.
3. **Platform/domain adapters:** A05 Android, A06 Apple, A07 native web, A08 dependencies, A10 PostgreSQL, A11 Nginx, A12 domain contracts.
4. **Context & runtime:** A13 semantic cards, A15 finding lifecycle, A16 runtime journeys, A17 review budget.
5. **Root:** shared wiring/docs/generation, coordinated verification, observed qualification & independent source assurance.

These are dependency groups, not forced global barriers. Dispatch ready independent work within admitted capacity; supply completed interface signatures before dependent edits. Runtime owner blockers do not stop pure parser/planner work.

## Completion

Handoff validation: 18 packet files, 64 unique write scopes, acyclic dependencies, valid document links & existing source references checked. Independent read-only Oracle review returned PASS for specification, ownership & false-clean protections. No product builds/tests or implementation were performed during planning.

Every requested concern has an implementation owner & acceptance case. Implementation, fixture qualification, host qualification & actual application qualification remain separate claims. Finish with evidence-backed native Audit coverage for each declared product target.

