# Capability architecture — proposal

**Status:** proposed, not implemented. Drawn from `main` at `5da4fcb`.

Skills do not live inside roles. Domain and authority are independent axes, and fusing them is why
asking for an audit lands you at Oracle. This states the target shape, the frontmatter contract it
rests on, and what gets deleted.

## Measured state

| | |
|---|---|
| Skills on disk | 23 — all indexed, none missing |
| Unreachable by domain | **13** — every one of them engineering |
| Places a skill is described | **5** |
| Regexes doing the actual routing | **15** |
| Tokens for the entire routing surface | **1,291** |

Only two skills were ever dropped across all history: `content` (media production) and `compshop`.
Nothing else was lost in the move.

## The correction

The tempting fix is to file the new non-engineering skills under Sage, Alchemist, and Oracle the
way engineering's were. That repeats the original mistake in a larger space.

**Roles are not parents of skills.** Sage decides, Alchemist executes, Oracle certifies — and those
three phases apply to *every* domain. An SEO audit needs deciding, doing, and certifying exactly as
much as a code audit does. So the roles cannot be engineering's children; they cut across all five
domains at once.

What went wrong is historical, not conceptual: the tree was built when engineering was the only
domain, so the roles were parked in the only slot available. Everything non-engineering that
arrived later had nowhere to go.

### What is there now

```
engineering
  ├─ sage        (role)
  ├─ alchemist   (role)
  └─ oracle      (role)
commercial
  └─ ads · marketing · seo · social
editorial · design · research
  └─ writing · designer · brand …

(no parent)
      audit · architect · coder · commit
      cortex · debugger · qa · tasklist
      dispatch · handoff · covenant · audit-fix · audit-visual
```

Advisory domains route to skills. Engineering routes to three roles, because `loader.mjs` hardcodes
`domain.id === 'engineering'` to take the registry list verbatim. Thirteen skills have no parent at
all.

Two further facts make this worse than it looks:

- `loadRoutingGraph` is consumed only by lens validation and its own tests. **The tree routes
  nothing.**
- `resolver.mjs` — the code that actually turns a request into a skill — contains zero references
  to `domains.json`. What really routes is `NATURAL_ROUTES`, a hardcoded 15-entry regex table.

Live behaviour of that table:

```
"audit this repo"              -> not-found
"review my repository health"  -> not-found
"write me a blog post"         -> not-found
"design a landing page"        -> not-found
"plan a launch"                -> architect      ← should be marketing
```

`audit` triggers on `/before claiming .* verify tests pass/`. `alchemist` on "just fucking do it".
`marketing` only on "Product Hunt launch". Two entries point at things that are not skills.
Designer, writing, seo, social, and research are absent entirely. These are eval fixtures that got
promoted into a router.

### Target shape

```
engineering  └─ audit · audit-fix · audit-visual · coder · cortex · debugger · qa
commercial   └─ ads · marketing · seo · social
editorial    └─ writing
design       └─ designer · brand-identity
research     └─ research

ROLE AXIS — crosses every domain above
sage decides · alchemist executes · oracle certifies
```

Five domains project from the skill index uniformly. The roles sit on their own axis, reachable
from any domain, and stop pretending to be engineering's leaves.

## Three kinds of thing share one folder

Part of the disorder is that `skills/` holds three categories that behave differently, with nothing
marking which is which:

- **Domain capabilities** — the actual work. `audit`, `writing`, `seo`, `designer`, `qa`.
- **Role entrypoints** — thin routers into an authority. `architect` says in its own description
  that it routes to Sage; `alchemist` and `covenant` do the same for their authorities. These are
  not domain capabilities and should not be filed as if they were.
- **Cross-domain utilities** — mechanics every domain borrows. `commit`, `tasklist`, `dispatch`,
  `handoff`, `brand`.

Once `kind` is explicit, the tree stops needing special cases: capabilities hang under domains,
entrypoints resolve to the role axis, utilities are reachable from everywhere.

## Assignment for all 23

Rows marked **?** are the five skills that declare no `MODE` today. Those values are proposed from
each skill's description and need confirmation before anything generates from them.

### Domain capabilities — engineering

| Skill | Domain | Mode | Change from today |
|---|---|---|---|
| `audit` | engineering | `DIAGNOSE` | newly routable |
| `audit-fix` | engineering | `EXECUTE` | newly routable · `IMPLEMENT`→`EXECUTE` |
| `audit-visual` | engineering | `DIAGNOSE` | newly routable |
| `coder` | engineering | `ROUTE` **?** | newly routable · mode missing today |
| `cortex` | engineering | `DIAGNOSE` | newly routable |
| `debugger` | engineering | `DIAGNOSE` **?** | newly routable · mode missing today |
| `qa` | engineering | `EXECUTE` | newly routable |

### Domain capabilities — advisory

| Skill | Domain | Mode | Change from today |
|---|---|---|---|
| `ads` | commercial | `DIAGNOSE` | unchanged |
| `marketing` | commercial | `PRODUCE` | `OUTPUT_ONLY`→`PRODUCE` |
| `seo` | commercial | `DIAGNOSE` | unchanged |
| `social` | commercial | `PRODUCE` | rename only |
| `writing` | editorial | `PRODUCE` | rename only |
| `designer` | design | `PRODUCE` | rename only |
| `brand-identity` | design | `PRODUCE` | rename only |
| `research` | research | `ROUTE` | unchanged |

### Role entrypoints — resolve to the role axis, not a domain

| Skill | Resolves to | Mode | Change from today |
|---|---|---|---|
| `architect` | sage | `ROUTE` **?** | reclassified · mode missing today |
| `alchemist` | alchemist | `EXECUTE` | reclassified out of engineering |
| `covenant` | covenant | `DIAGNOSE` | reclassified · newly routable |

### Cross-domain utilities — reachable from every domain

| Skill | Mode | Change from today |
|---|---|---|
| `brand` | `PRODUCE` | moves out of `design` |
| `commit` | `EXECUTE` **?** | newly routable · mode missing today |
| `dispatch` | `PRODUCE` | newly routable |
| `handoff` | `PRODUCE` | newly routable |
| `tasklist` | `PRODUCE` **?** | newly routable · mode missing today |

## The mode vocabulary

Eighteen skills already declare a `MODE`. It is the role axis, half-built — but the vocabulary has
five values where four will do, and `IMPLEMENT` and `EXECUTE` name the same phase.

Mode says what a skill does to the world, which is what determines the authority that must be
involved:

- `DIAGNOSE` — reads only, produces findings. Oracle certifies the finding; nothing mutates.
- `PRODUCE` — creates an artifact outside tracked state. *Absorbs* `OUTPUT_ONLY`.
- `EXECUTE` — mutates tracked state. Alchemist owns the effect; Oracle certifies before delivery.
  *Absorbs* `IMPLEMENT`.
- `ROUTE` — selects another capability and has no effect of its own.

Four values, each with a defined consequence for which role gets involved — which is the point of
having the axis at all.

## The frontmatter contract

Today the contract block lives in the *body* of each `SKILL.md` as loose prose: four skills wrap it
in a ` ```text ` fence, fourteen leave it bare, five have none. Field coverage is ragged — `MODE`
appears 18 times, `DISCOVERY_PROFILE` 16, `SPECIALIST_REFS_MAX` 14. Nothing parses any of it.

Move it into frontmatter, where it becomes the single source of truth:

```yaml
---
name: audit
description: "Diagnose a whole repository through Legion's frozen Audit
  provider plan. Use for /audit or repository-wide read-only health,
  security, runtime, & evidence review."
legion:
  kind: capability        # capability | entrypoint | utility
  domain: engineering     # omitted for utility; role name for entrypoint
  mode: DIAGNOSE          # DIAGNOSE | PRODUCE | EXECUTE | ROUTE
  deliverable: "Re-runnable audit report with bounded findings."
  terminal: "Frozen provider plan reconciles to evidence or typed degradation."
  effects: [audit_engine]
  requiresHostCapability: [cortex-graph]   # optional; keys from capabilities.json
  limits: { childAgents: 0, externalRequests: 0, specialistRefs: 0 }
  rights: { provenance: legion-authored, licenseState: licensed,
            rightsReceipt: LICENSE, publish: true }
---
```

`name` and `description` stay exactly where they are — they already work, and they are what the
model routes on. Everything else is the body block, lifted and typed. `requiresHostCapability` keys
against the capability registry that already exists, so a skill can no longer quietly depend on
something the host may not provide.

## What generates from what

| Role | File | Note |
|---|---|---|
| **Source of truth** | `skills/*/SKILL.md` | 23 files, hand-edited, the only place a skill is described |
| Generated | `src/registry/routing/domains.json` | projected from frontmatter; no engineering special case |
| Generated | `src/registry/skills/index.json` | same pass; cannot drift from disk |
| **Deleted** | `NATURAL_ROUTES` | 15 regexes; demote to eval fixtures, which is what they were |

This pattern already exists here: `generate-schemas.mjs --check` runs inside `legion:check` and
fails the build on drift. A `generate-routing.mjs --check` beside it means the tree can never again
disagree with what is on disk — the failure that produced thirteen orphans in the first place.

`capability-aliases.json` stays. Legacy slash aliases are a separate concern, and the dangling-alias
check already guards it.

## Why not retrieval

RAG means: when you have more candidates than fit in a prompt, embed them all, and at query time
fetch only the nearest few. It solves a scale problem.

**The entire routing surface here — all 23 names and descriptions — is 1,291 tokens.** Everything
fits, permanently, with room to spare. The research motivating tool retrieval targets corpora in the
thousands; the practical crossover is somewhere around fifty to a hundred candidates. This is an
order of magnitude below it.

At this scale a vector index is a straight downgrade. It adds an index to rebuild on every skill
edit, a similarity threshold to tune, embedding drift as descriptions change, and one new failure
mode that does not exist today: *semantically near but wrong*, which is worse than not-found because
it routes silently and confidently.

A capability graph is the same answer. Twenty-three nodes across five domains is a JSON file, which
is what `domains.json` already is. Cortex is a graph engine, but it maps repositories, not
capabilities. The problem was never representation — the file is incomplete and nothing reads it.

The mechanism to use is the one the harness already implements: **progressive disclosure**. Every
skill's name and description stay in context; the body loads only once selected. That is why the
descriptions are well-written in the first place. The regex table is a hand-rolled substitute for
it, and a lossy one.

## Order of work

1. **Settle the vocabulary and the five unknowns.** Confirm the four modes, and the proposed values
   for `architect`, `coder`, `commit`, `debugger`, `tasklist`. Documentation only — nothing executes.
2. **Lift the contract into frontmatter.** Mechanical, one skill at a time, fully reversible. The
   body block goes away; `name` and `description` never move.
3. **Write the generator and its drift check.** `generate-routing.mjs` plus `--check` in
   `legion:check`. Regenerating kills the engineering special case, and the thirteen orphans become
   routable in the same commit.
4. **Delete `NATURAL_ROUTES`.** Route on descriptions. Keep the regexes as eval fixtures so the
   routing assertions they encode are not lost.
5. **Wire the resolver to the graph.** `resolver.mjs` has zero references to `domains.json` today.
   This is the step that makes the architecture the thing that runs, rather than a document about
   itself.

## Open decisions

- **The five missing modes.** Inferred from each description. `debugger` in particular could be
  `DIAGNOSE` or `ROUTE` depending on whether it investigates or delegates.
- **`brand` as a utility.** It currently sits under `design`, but its own description says it loads
  before content, design, marketing, social, and media work — that is cross-domain.
- **Whether entrypoints stay skills at all.** `architect`, `alchemist`, and `covenant` are thin
  routers to authorities. They could be role definitions instead of skill bundles, which would
  shrink `skills/` to 20 genuine capabilities.
- **`covenant`'s home.** It is a challenge chamber convened across domains, not an engineering
  capability. Filed as an entrypoint here; it may deserve its own standing.

---

Sources: `src/registry/routing/domains.json`, `src/registry/skills/index.json`,
`src/lib/routing/loader.mjs`, `src/lib/skills/resolver.mjs`, and the 23 `skills/*/SKILL.md`
frontmatter blocks. Counts were measured, not estimated.
