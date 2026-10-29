---
name: architect
description: Software and system architecture capability for architecture decisions, ADRs, quality attributes, invariants, migrations, and architecture-significant planning.
kind: capability
capabilityClass: domain
discoverability: public
domain: engineering
operations:
  - analyze
  - decide
  - produce
effects:
  - source-read
  - artifact-write
hostRequirements:
  - rightkit-owns
---

# Architect

`/architect` is the engineering architecture capability. Architect owns software/system
architecture craft and routine architecture judgment; it does not route through Sage for routine
decisions. Sage attaches only when a material unresolved decision cannot safely close under
Architect's routine mandate.

## Owns

- context and boundaries;
- architecture-significant requirements;
- quality attributes and quality scenarios;
- responsibility allocation;
- invariants;
- state/data authority;
- consistency and lifecycle;
- runtime and deployment topology;
- alternatives and trade-offs;
- ADRs where warranted;
- migration and evolution;
- architectural risk;
- simplest-sufficient architecture;
- technology or model selection studies that commit an integration shape (Research supplies the evidence; Architect owns the decision).

## Method

Method lives in `doctrine/architecture/**` (workflow, controls, methods, reviews, templates,
schemas) and `references/manual.md`. Progressive loading: load the current workflow phase plus the
triggered method only. At entry, read `references/manual.md`, apply
`doctrine/architecture/00-charter-significance-tailoring.md`
before creating an architecture record or choosing depth: insignificant questions get a direct D0
answer with no architecture record; significant work follows the charter's D1/D2 routing and
objective rules. State the charter result (significance, depth, objective) before answering; assessing or
improving the shape of an existing subsystem is significant, not D0. For D1/D2 work that reshapes modules,
interfaces, or ownership, load `doctrine/architecture/methods/add.md` before recommending. Start new significant work at
`doctrine/architecture/workflow/01-frame.md`; for continuing work, resume the recorded current
phase instead of restarting. D2 `best_shape` means complete the relevant
architecture reasoning to a defensible recommendation, not invoke every specialist framework.
Reopen an earlier phase only for a material delta with cause, scope, and affected IDs.

When intent or constraints leave materially different architecture directions open, load
`doctrine/architecture/methods/brainstorming.md` across the frame/context/candidate/selection
phases. Skip it for clear, routine work; it resolves meaningful uncertainty, not a universal
design gate or a requirement to obtain approval before ordinary execution.

## Shared platform first

Before proposing new components or dependencies, read the host-declared shared-capability index
(session-injected ownership index or host-declared lookup command) and the workspace/repository
agent rules, then decide reuse owner → extend owner → build new. Building new, or adding a
third-party dependency for a capability the index declares, needs a recorded reason. When the host provides `rustright owns --compact`, start every design from its full output:
name the owner for each capability, integrate owners, and design only the gaps. Carry that output
into the tasklist's RightKit Capabilities block. If the host
declares no index, say so and proceed. Detail: `doctrine/architecture/workflow/01-frame.md`.

## Prior art

Before a design, bakeoff, export, or runtime change, name the open-source projects that already
solve or attempt the same problem. For each, state its runtime, format, adoption numbers (dated),
and licence, then either reuse it or state the reason not to. Record this under a mandatory
"Prior art" section of the output. Run it as the second question after `rustright owns`. Research
performs the lookup from fetched sources; Architect owns the reuse decision. A design without a
Prior art record is incomplete; "none found" must name the searches run. Detail:
`doctrine/architecture/workflow/01-frame.md`.

## Current-state entrypoint

Blueprint is public current-reality owner, not Audit-only plumbing. For existing-repository
architecture, use `/blueprint` when material current-reality evidence is missing, stale,
contradictory, or when requested scope needs a repository map. It supplies fresh architecture,
flows, symbols, impact, freshness, doc truth, contradictions, & coverage gaps to Architect. A
request only to map, understand, onboard to, or reconcile current repository/docs routes to
Blueprint. A bounded architecture question already grounded in supplied/current evidence may
proceed directly to Architect; a request to judge, change, migrate, or design architecture should
route available Blueprint evidence into Architect.

## Depth follows intent

A question gets an answer. A design request gets architecture. An implementation request may
proceed through ordinary ambient execution; it does not imply a contract. Use an executable
contract only for explicit or locked governed work. Never force ceremony the request did not ask for.

## Boundaries

Architect never performs product-source effects; settled effects route to ambient execution or
Alchemist under policy. "Architect" as a non-engineering verb routes to the owning capability
(designer, research, seo, marketing), never through the engineering Architect.

Evaluation manifest: `evals/evals.json`.
