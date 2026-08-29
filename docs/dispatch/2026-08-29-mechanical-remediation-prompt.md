# Dispatch prompt artifact — mechanical remediation lanes (2026-08-29)

Repository: this legion checkout @ ab4c1302. Workers edit ONLY their allowlist. Workers never run
cargo, tests, builds, generators, installs, commits, pushes, merges, or expensive checks; the
integration owner runs all checks after merge. Inspect any read path needed.

## lane-ci-python-tests
Edit `scripts/ci/right-git-ci.sh` and `package.json` only.
- Add a `test:python` script to package.json: runs `python3 -m unittest discover -s skills/alchemist/tests -v`
  then `python3 -m unittest src.lib.dispatch-validator.test_validate_dispatch` — use the invocation style
  that actually resolves (`python3 src/lib/dispatch-validator/test_validate_dispatch.py` is acceptable if
  the module path contains hyphens; inspect the file's __main__ guard and choose accordingly).
- Invoke that script from scripts/ci/right-git-ci.sh after the existing `pnpm test` step, guarded so a
  missing python3 skips with a loud warning line rather than failing the pipeline.
- Match surrounding style; no other script changes.
Intended integration checks: `pnpm test:python` passes locally; `pnpm legion:check` unaffected.

## lane-alchemist-python-capability
Edit `skills/alchemist/dependencies.json` and `skills/manifests/alchemist.json` only.
- Add `python-runtime` as a HOST_CAPABILITY dependency alongside `omniroute` in dependencies.json,
  mirroring the declaration shape the file already uses; rationale: scripts/run-worker.sh shells out to
  python3 unconditionally (parse_events.py). Match how skills/coder declares python-runtime if present.
- Do NOT hand-compute digests in skills/manifests/alchemist.json; only append the dependencies.json
  entry change if the manifest lists per-file digests that the integrator will regenerate — leave the
  manifest file untouched if unsure and note it. The integrator runs
  `node scripts/refresh-local-skill-manifests.mjs alchemist` after merge; the manifest is in this lane's
  allowlist so the regenerated output belongs to this lane's change set.
Intended integration checks: `node scripts/refresh-local-skill-manifests.mjs --check alchemist` clean.

## lane-parity-doctrine
Edit `scripts/check-authority-parity.mjs` only.
- Extend the parity comparison so each role's `doctrine/<role>.md` frontmatter `description:` is compared
  against the canonical `src/roster/<role>.md` description, in addition to the existing `agents/<role>.md`
  comparison. If a doctrine file intentionally carries a longer description, compare only when a
  `description:` key is present and fail with a message naming all three paths on mismatch.
- Keep output format and exit-code behavior consistent with the current script.
Intended integration checks: `node scripts/check-authority-parity.mjs` passes on current tree (fix nothing
else; if it fails on current doctrine text, report the mismatch as a finding instead of editing doctrine).

## lane-schema-citation-hygiene
Edit `src/packages/contracts/schemas/oracle-completion-validation-v1.schema.json` and
`src/packages/oracle/README.md` only.
- Replace citations of `docs/audits/oracle-audit.md` (and any other local audit-report paths) in the
  schema's `description` and `subject.digest` description with self-contained rationale text conveying
  the same requirement. Do not change `$id`, `$schema`, structure, property names, patterns, or
  `additionalProperties`.
- In src/packages/oracle/README.md, remove references to local audit report paths while preserving the
  name-collision notice and its deferred rename/removal decision.
Intended integration checks: `node --test src/packages/contracts/smoke.test.mjs` passes; grep shows no
`docs/audits/` references remain in either file.

## Amendment (post-review repair)
lane-alchemist-python-capability additionally owns `skills/alchemist/SKILL.md`: add `python-runtime`
to its `hostRequirements` frontmatter list (alongside `omniroute`, matching skills/coder/SKILL.md's
style) so declared HOST_CAPABILITY entries and hostRequirements stay in sync per
src/lib/skills/dependency-closure.mjs. No other SKILL.md change.
