# Readiness, review submission & workflows

## Stage before submit

Resolve exact app/version/platform/build. Pull/validate metadata, screenshots, privacy, export compliance, pricing/availability & required product items. Run the read-only readiness gate before any submission. Use `asc release stage` to attach an existing processed build and validate; use `asc review submit` only for a prepared version; use `asc publish appstore` for a high-level upload/build plus optional submit lane.

Require dry-run where supported, inspect planned effects and pass explicit `--confirm` for submission. Do not mix high-level lanes after a review submission exists; inspect current submission and continue with matching lower-level commands. Build-not-attached before staging is expected, not a submission-health failure.

## Multi-item submissions

When app version includes IAP, subscription or Game Center version items, resolve every item's version, localization, review screenshot and review notes. Create only when filtered state is empty; reuse the single `PREPARE_FOR_SUBMISSION` object; stop when multiple matches need explicit ID. Assemble one submission only after every item is ready. Preserve unrelated items and report per-item blockers.

## Workflow files

Treat `.asc/workflow.json` as code. Validate first, run `--dry-run`, then execute trusted steps. Use JSON stdout for outputs, stable step names and references like `${steps.name.FIELD}`. Retry only commands proven safe to repeat; timeout alone is terminal because remote mutation may have completed. Resume with run ID and no extra params; persisted workflow file, params & outputs are reused. Keep secrets out of outputs.

## Terminal submission evidence

Read back submission state after request and continue until requested terminal state: accepted for review, rejected with actionable errors, cancelled, or still processing. Non-empty stdout is not success if JSON says invalid/partial. Stuck, cancellation, retry and non-Game Center readiness defects route to submission-health owner; Game Center item preparation remains in this release lane.
