# Readiness, review submission & workflows

## Adapter boundary

`asc` is an external App Store Connect CLI. Follow [external `asc` setup](../tool-setup.md#asc), then keep this process-scoped environment active before any command below:

```bash
export ASC_TELEMETRY_DISABLED=1
export DO_NOT_TRACK=1
asc version
```

Inspect the relevant leaf `--help`, output mode & capability. Examples below are version-conditioned procedures, not proof that Legion's native adapter exposes identical verbs or flags. Keep `IOS` for iOS/iPadOS targets; use `MAC_OS` for macOS targets.

## Stage before submit

Resolve exact app/version/platform/build IDs. Pull & validate metadata, screenshots, privacy, export compliance, pricing/availability & required product items. Run read-only readiness before submission. Use `asc release stage` to attach an existing processed build & validate; use `asc review submit` only for a prepared version; use `asc publish appstore` for high-level upload/build plus optional submit.

`PREPARE_FOR_SUBMISSION` is product-version readiness. `READY_FOR_REVIEW` is review-submission draft state; one does not prove the other. Require dry-run where supported, inspect planned effects & pass explicit `--confirm` for submission. Do not mix high-level lanes after review submission exists; inspect current submission & continue with matching lower-level commands. Build-not-attached before staging is expected, not a submission-health failure.

When validation identifies encryption, content rights, age rating, metadata, privacy URL, screenshots, availability, review details or App Privacy gaps, follow the [on-demand submission repair guide](submission-repairs.md). It separates public API repairs from authenticated web-session or manual work, & distinguishes applied App Privacy answers from published state.

## Multi-item submissions

When version includes IAP, subscription or Game Center version items, resolve exact `VERSION_ID` plus each item version ID, localization, review screenshot & review notes. Complete product preparation before assembly. Do not treat product `PREPARE_FOR_SUBMISSION` as review-draft `READY_FOR_REVIEW`.

Inspect existing submissions first. If handed a submission ID, read it back with items & app-store-version relationship; reuse only when it is the intended `READY_FOR_REVIEW` draft. Without a handed-off ID, reuse exactly one matching `READY_FOR_REVIEW` draft; create one only when no matching draft or active submission exists; stop when multiple drafts or an active mismatch make intent ambiguous. Never create a second submission.

List draft items before writes. Compare intended item type & exact version resource ID; skip exact matches. Add only missing version IDs, app version first, then resolved IAP, subscription, subscription-group or Game Center version IDs. Do not attach parent product IDs or placeholders. Inspect submission & item list again before `asc review submissions-submit --id SUBMISSION_ID --confirm`. Preserve unrelated items & report per-item blockers. See [multi-item submission mechanics](submission-repairs.md#multi-item-draft-assembly) for command-shaped procedure.

## Workflow files

`asc workflow` is optional repo-local external-CLI automation. If used, follow [asc workflow procedures](asc-workflows.md): inspect installed help, validate `.asc/workflow.json`, list the intended workflow, run a dry-run, then execute only trusted steps. Do not introduce a mandatory workflow or agent orchestration requirement. Keep JSON on stdout, diagnostics on stderr, stable step names & secret-free outputs. Retry only commands proven safe to repeat; timeout alone is terminal because remote mutation may have completed. Resume with run ID & no extra parameters; persisted workflow file, params & outputs are reused.

## Terminal submission evidence

Read back submission state after every request & continue until requested terminal state: accepted for review, rejected with actionable errors, cancelled or still processing. Non-empty stdout is not success when JSON says invalid or partial. Stuck, cancellation, retry & non-Game Center readiness defects route to submission-health; Game Center item preparation remains in this release lane.
