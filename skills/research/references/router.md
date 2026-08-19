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

## Stage 1 — route only

Run `src/lib/research-core/router/route_resolve.py --intent ...`. Stage 1:

- resolves a typed route with `allowed_effects: []`;
- performs no sensitive read, search, fetch, upload, write, or worker spawn;
- never guesses a legal country, legal area, or missing issue;
- defaults generic medical questions to `patient.kind=anonymous`;
- records pending human gates and route-specific forbidden resources.

When context is missing, pass a small context JSON or ask one material clarifying question.
The frozen route is persisted in the run manifest.

## Stage 2 — approval resume and effect grant

Approvals are separate receipts stored in the run manifest. Stage 2 reloads the frozen route;
it does not reclassify the prompt. Every pending gate must have an approval receipt and every
deterministic domain gate must pass before effects are granted.

Use `src/lib/research-core/run.py approve ...` followed by `run.py grant ...`.

## Medical context

Medical requires `patient + issue`:

- `anonymous`: no personal history may be read;
- `self` or `other-identified`: explicit route approval plus a readable, project-configured history source;
- generic evidence questions never load the personal history source;
- personal questions may load the configured history only after the route freezes, and the route
  blocks rather than infers if no history source is configured.

## Legal context

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
