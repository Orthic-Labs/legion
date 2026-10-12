# Architecture method index / ownership statement

**Canonical owner:** `skills/architect/SKILL.md` + `skills/architect/doctrine/architecture/**` for software/system
architecture craft. Architect owns architecture method; Sage is not the architecture owner.

Ordered manifest: `workflow/01-frame.md`, `workflow/02-context-stakeholders.md`, `workflow/03-drivers-quality-scenarios.md`, `workflow/04-domain-data-change.md`, `workflow/05-risk-uncertainty.md`, `workflow/06-candidates.md`, `workflow/07-evaluate-select.md`, `workflow/08-minimize.md`, `workflow/09-describe-views.md`, `workflow/10-assure-accept.md`, `workflow/11-govern-evolve-retire.md`.

## Bootstrap and resume

Read `00-charter-significance-tailoring.md` first. It decides whether architecture applies and
sets objective, depth, and rigor. Insignificant work, including a simple question, routes to D0
without an architecture record. For significant new work, begin at `workflow/01-frame.md`; for
continuing work, resume the recorded current phase. The charter assigns D2 `best_shape` where
appropriate; complete the relevant reasoning without making every specialist method mandatory.
Load the current phase plus only methods triggered by its inputs. Go backward only for a material
delta with cause, scope, and affected IDs.

Reject unknown phase, cancelled epoch, restart without delta, backward no cause scope, frame no fingerprint, objective upgrade, reviewer REQUIRED, and frozen reload no trigger.

## Scope of this directory

- `workflow/**` — ordered architecture workflow modules.
- `controls/**` — deterministic architecture/execution control method.
- `methods/**` — specialist architecture method modules.
- `reviews/**` — architecture review method.
- `templates/**` — architecture artifact templates.
- `schemas/**` — architecture state/control schemas.

## Stage and ledger ids (Sxx, S02-08)

`Stage: Sxx` and `Ledger: Sxx-nn` labels in `controls/**` (for example `S02`, `S02-08`, `S10`) are
historical stage labels from the original build plan. They carry no current meaning in this skill,
and no stage plan ships here to look them up. Where a control names an owning stage, that naming
is historical; read the control text itself for the rule it states.

Sage participates only when a material unresolved architecture decision requires exceptional
adjudication beyond Architect's routine mandate.
