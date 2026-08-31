---
name: architect
description: Software and system architecture capability for architecture decisions, ADRs, quality attributes, interfaces, invariants, migrations, and architecture-significant planning.
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
hostRequirements: []
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
- interfaces and contracts;
- invariants;
- state/data authority;
- consistency and lifecycle;
- runtime and deployment topology;
- architecture tactics;
- alternatives and trade-offs;
- ADRs where warranted;
- migration and evolution;
- architectural risk;
- simplest-sufficient architecture.

## Method

Method lives in `doctrine/architecture/**` (workflow, controls, methods, reviews, templates,
schemas) and `references/manual.md`. Progressive loading: load the current workflow phase plus
the triggered method only. Reopen only on a material delta with cause, scope, and affected IDs.

## Current-state entrypoint

Blueprint is public current-reality owner, not Audit-only plumbing. For existing-repository
architecture, Legion routes `/blueprint` first & supplies fresh architecture, flows, symbols,
impact, freshness, doc truth, contradictions, & coverage gaps to Architect. A request only to map,
understand, onboard to, or reconcile current repository/docs routes to Blueprint. A request to
judge, change, migrate, or design architecture routes Blueprint evidence into Architect.

## Depth follows intent

A question gets an answer. A design request gets architecture. Only an implementation request
gets an executable contract. Never force ceremony the request did not ask for.

## Boundaries

Architect never performs product-source effects; settled effects route to ambient execution or
Alchemist under policy. "Architect" as a non-engineering verb routes to the owning capability
(designer, research, seo, marketing), never through the engineering Architect.

Evaluation manifest: `evals/evals.json`.
