# Research router

The public skill resolves orthogonal axes rather than choosing among dozens of skills:

- **domain:** general | market | technical | scientific | medical | legal
- **operation:** discover | compare | verify | analyze | advise | review | draft | procedure | manage-corpus | generate-artifact
- **methods:** web | competitor | reddit | audience | trends | scholarly | document | authority
- **provider:** browser | local-corpus | notebooklm | domain-default
- **assurance:** quick | standard | verified
- **scale:** focused | broad | dossier

`scholarly` and `authority` remain methods on the frozen route. Their concrete runtime adapters
are selected inside `domain-default` after the route is frozen; they are not public provider values.
Customer/JTBD wording is normalized into the `audience` method instead of adding a separate route
method; outbound lead generation is outside this Research consolidation.

## What actually ships: `legion research`

The two-stage route/approve/grant flow and the medical/legal/scientific/technical/market
domain classifier described below were built as a Python prototype
(`src/lib/research-core/`) that is **not part of the installed plugin** — it never leaves
the source checkout and `SKILL.md` calls it retired. The only thing that ships and runs is
the native `legion research` command (`legion-research` crate). Use `legion research --help`
for its real, current contract: `--query`, `--provider`, `--max-hits`,
`--source-record <record.json>` (host-opened evidence you supply), `--min-independent-providers`,
`--domain`, and `--sensitivity` (defined in `engine/bins/legion/src/commands/research.rs`).

**Domain and sensitivity flags:** `--domain` defaults to `general` and accepts `general`,
`market`, `technical`, `scientific`, `medical`, `legal`. `--sensitivity` defaults to `public`
and accepts `public`, `private`, `highly-sensitive`. The route is built with the values given
and validated (`ResearchRoute::host_injected_with` in
`engine/crates/legion-research/src/workflow.rs`); an undeclared value is refused. The CLI has
no query classifier, so the caller chooses the domain.

**Medical and legal routes are refused by the CLI.** `--domain medical` requires
`subject.patient.kind`, and `--domain legal` requires `subject.country` (ISO alpha-2) and
`subject.area`, plus an issue. The CLI has no flags for those subject fields, so validation
fails closed and the route never reaches a provider. The gates for these routes
(`gates_satisfied`, `medical_effects_satisfied`) are enforced in the native run path but cannot
be satisfied from the command line. Do not tell a user the installed skill can run a medical
or legal route; route them to a human or a host that supplies the subject context.

The sections below describe the prototype's design: its query classifier, two-stage flow, and
medical/legal context rules. The native CLI implements none of the classifier and cannot supply
the subject context those rules need. The sections are kept for anyone working from a source
checkout; they do not describe the current native runtime.

## Stage 1 — route only (prototype design, not shipped)

Resolve a typed route with `allowed_effects: []`. Stage 1:

- performs no sensitive read, search, fetch, upload, write, or worker spawn;
- never guesses a legal country, legal area, or missing issue;
- defaults generic medical questions to `patient.kind=anonymous`;
- records pending human gates and route-specific forbidden resources.

When context is missing, pass a small context JSON or ask one material clarifying question.
The frozen route is persisted in the run manifest.

## Stage 2 — approval resume and effect grant (prototype design, not shipped)

Approvals are separate receipts stored in the run manifest. Stage 2 reloads the frozen route;
it does not reclassify the prompt. Every pending gate must have an approval receipt and every
deterministic domain gate must pass before effects are granted.

## Medical context (prototype design, not shipped)

Medical requires `patient + issue`:

- `anonymous`: no personal history may be read;
- `self` or `other-identified`: explicit route approval plus a readable, project-configured history source;
- generic evidence questions never load the personal history source;
- personal questions may load the configured history only after the route freezes, and the route
  blocks rather than infers if no history source is configured.

## Legal context (prototype design, not shipped)

Legal requires `country + area + issue` before jurisdictional conclusions. Country is inferred
only from explicit jurisdiction markers such as India, IPC/BNS, e-Jagriti, US federal law, or
GDPR/EU law. Otherwise the route asks.

India criminal research is permitted but carries hard forbidden-resource patterns for every
consumer/e-Jagriti path. India consumer drafting additionally requires pecuniary value,
cause-of-action date, and notice status.

## NotebookLM

NotebookLM is a provider/artifact route. Its answers are leads, never evidence. Private or
medical uploads require a per-run approval receipt. Promotion requires opening the underlying
source and locating the supporting passage through the normal provider contract.
