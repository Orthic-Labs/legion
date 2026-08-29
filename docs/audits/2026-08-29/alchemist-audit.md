# Alchemist Subsystem Audit — 2026-08-29

Fresh audit; prior documents in `docs/audits/` were not read. Evidence anchored to file:line at read time.

## 1. Inventory

**Identity/authority chain (3 hand-synced copies of the same frontmatter description):**
- `agents/alchemist.md` — Claude Code agent card (hand-maintained, `model: sonnet`)
- `doctrine/alchemist.md` — operating method (execution loop, self-audit, retry discipline, cheap-worker delegation)
- `src/roster/alchemist.md` — canonical identity/authority/model-tier source (`modelTier: balanced-executor`, `delegationTiers: [mechanical-cheap, balanced-executor]`)

**Skill entrypoint** `skills/alchemist/`:
- `SKILL.md` (kind: entrypoint, target: `authority:alchemist`, `discoverability: explicit`, `hostRequirements: [omniroute]`)
- `dependencies.json` — declares one `HOST_CAPABILITY`: `omniroute`
- `references/manual.md` — relay architecture, invocation contract, runner differences
- `scripts/run-worker.sh`, `scripts/run-worker.ps1` — OmniRoute/Codex CLI worker adapters (exit 0/2/4/5/124)
- `scripts/parse_events.py`, `scripts/viewer.py`, `scripts/tray.ps1`, `scripts/start-stack.vbs`
- `agents/openai.yaml` — Codex-harness projection (`allow_implicit_invocation: false`)
- `model-catalog.json` — Codex model metadata for OmniRoute-routed models
- `evals/evals.json`, `evals/legacy-jfdi.json` — behavioral eval specs (trigger/non-trigger/safety/pressure cases)
- `tests/test_windows_runner.py`, `tests/test_posix_runner.py` (new, untracked at session start) — unittest coverage of the exit-code/invocation contract

**Registry/schema surface:** `src/registry/capabilities.json` (`omniroute` capability + degradation text), `src/registry/skills/index.json` (alchemist entry, `discoverability: explicit`), `skills/manifests/alchemist.json`, `scripts/check-authority-parity.mjs`, `scripts/refresh-local-skill-manifests.mjs`, `schemas/dispatch.v1.schema.json` / `authority-dispatch-v1.schema.json`.

**Doctrine/SSOT:** `docs/LEGION-CANONICAL-SSOT.md` (§5–7, model-tier table), `doctrine/legion.md` (Handoff reference), `AGENTS.md` (root, tier-4 contract chain).

## 2. Architecture docs status

**What exists:** distributed, not centralized — identity/boundary in `src/roster/alchemist.md`, method in `doctrine/alchemist.md`, agent binding in `agents/alchemist.md`, packaging contract in `skills/alchemist/SKILL.md` + `dependencies.json`, cross-role invariants in `docs/LEGION-CANONICAL-SSOT.md` §5–7. The OmniRoute worker relay design is documented informally in `skills/alchemist/references/manual.md` ("Visible relay architecture").

**What does not exist:** No dedicated `docs/architecture/alchemist.md`, ADR, or diagram for the two-layer relay (native subagent → OmniRoute → Codex CLI) anywhere, tracked or archived. `docs/provenance/` holds sage/oracle/worker-capsule archives but no Alchemist-specific counterpart. The only place the worker-relay design is written down is the skill's own `manual.md` — packaging documentation, not architecture documentation, and not cross-referenced from `docs/LEGION-CANONICAL-SSOT.md`.

## 3. Packaging gaps

1. **Manifest stale relative to a shipped test file.** At audit start, `skills/manifests/alchemist.json` (committed at `9aa4b53b`) omitted `tests/test_posix_runner.py` even though the file was present on disk. This is precisely the drift class `node scripts/refresh-local-skill-manifests.mjs --check` (wired into `pnpm legion:check`) exists to catch; CI fails until regenerated. *Fix:* run `node scripts/refresh-local-skill-manifests.mjs alchemist` and commit the result alongside any new file under `skills/alchemist/**`.

2. **The Python test suite has zero execution wiring.** `package.json`'s `"test"` script runs only Node tests; `.github/workflows/ci.yml` → `scripts/ci/right-git-ci.sh` has no pytest/unittest step. `test_posix_runner.py` and `test_windows_runner.py` pin the exact exit-code contract (0/2/4/5/124, `--model` requirement, stdin-only brief, gateway-down message, timeout fallback, Mac/Windows concurrency-cap asymmetry) but nothing in the shipped pipeline ever runs them. *Fix:* add `python -m unittest discover skills/alchemist/tests` to CI, gated on Python availability.

3. **`python-runtime` is an undeclared dependency.** `run-worker.sh` invokes `python3 parse_events.py` unconditionally, yet `skills/alchemist/dependencies.json` declares only `omniroute`. The registry already defines a generic `python-runtime` capability used by Coder for exactly this pattern. If Python is absent, `run-worker.sh` fails with a raw "command not found," not the typed unavailability the capability-class scheme promises. *Fix:* add `python-runtime` to `skills/alchemist/dependencies.json`.

4. **`check-authority-parity.mjs` does not cover `doctrine/alchemist.md`.** The script diffs only `agents/<role>.md` vs `src/roster/<role>.md`, but `doctrine/alchemist.md` also carries a `description:` frontmatter field, currently hand-synced in lockstep. A future edit to only two of the three copies passes `pnpm legion:check` silently. *Fix:* extend the parity check to include doctrine, or document why it's excluded.

5. **Degradation is coherent where declared.** `src/registry/capabilities.json:31-40` (`omniroute`) states "Alchemist exits 4 (gateway down)…" and `run-worker.sh:47-52` implements exactly that, test-verified. No leaked references to unclassified hosts found in `skills/alchemist/**` beyond the undeclared `python3` dependency above.

## 4. Harness gaps

1. **Two independent invocation surfaces layered on one name.** (a) `legion:alchemist` Agent-tool subagent (`agents/alchemist.md`, description-matching or `@alchemist`); (b) `/alchemist` skill (`discoverability: explicit`, `allow_implicit_invocation: false` in the Codex sidecar), which routes back to the agent. The `explicit` discoverability class is shared by `alchemist`, `coder`, `commit`, `covenant` — coherent by design.

2. **The Arcane hook layer is blind to Alchemist's exit-code contract.** `hooks/hooks.json` gates Bash/Write/etc. generically; `engine/bins/legion-hook/src/main.rs` contains zero references to `alchemist` or `omniroute`. Exit codes 0/2/4/5/124 are interpreted only by the Alchemist agent's own prose discipline — Arcane has no typed awareness that a `4` from this command means "capability unavailable." Worker-path observability is self-reported, not receipt-backed.

3. **Manifest "consumers" template overreach.** `skills/manifests/alchemist.json` lists `src/registry/routing/domains.json` as a consumer via `deriveParity`'s hardcoded generic list, but Alchemist (`capabilityClass: null`, an authority) does not participate in domain routing. Minor.

## 5. Agent-visibility gaps — why Oracle is dispatched constantly and Alchemist essentially never

1. **Oracle has an unconditional trigger; Alchemist does not.** `AGENTS.md` rule 7: *"Before any successful final delivery, get fresh Oracle semantic PASS"* — fires on every completed task. Alchemist's only affirmative triggers: explicit `/alchemist` (never semantically suggested), a Sage freeze handoff (`doctrine/legion.md:24-25`), or a locked-domain path. Sage itself is rare, so the Sage→Alchemist chain is doubly gated behind an already-rare event.

2. **Doctrine repeats the negative rule far more than any positive one.** "`execute` does not imply Alchemist" appears in at least four canonical sources (`AGENTS.md:26`, `docs/LEGION-CANONICAL-SSOT.md:220-221`, `:265-271`, tier-4 text). There is no positive symmetric rule reading "route settled, mechanical work to Alchemist." `AGENTS.md` rule 5 ("Cost-route the muscle. Settled, mechanical work goes to the cheapest capable executor") never names Alchemist or its OmniRoute worker path — the only concrete cheap-executor machinery in the repo is Alchemist's own internal `run-worker.sh`/`.ps1` delegation, which only fires *after* Alchemist is already dispatched. Rule 5 is a dangling principle with no reachable implementation for ambient-tier work.

3. **Tier 2 (Ambient) is explicitly "the default for mutations."** Almost all session work is definitionally routed to tier 2 (direct execution) and never reaches tier 4 where Alchemist lives. The recent uncommitted edit to all three identity files *narrows this further*: it added "Do not dispatch for … ordinary ambient mutations" to the description (confirmed via `git diff`). This is a live trend in the same direction as the observed behavior — the description is being tightened, not loosened.

**Diagnosis:** Alchemist's trigger conditions are logically almost unreachable in ordinary sessions: the two feed paths (explicit contract request, Sage freeze) are each independently rare, and the doctrine's only positive routing cue ("cost-route the muscle") is never wired to Alchemist. Oracle has one clause that fires on every task. The asymmetry fully explains the observed behavior.

## 6. Ranked gap list with fixes

| # | Severity | Gap | Evidence | Fix |
|---|----------|-----|----------|-----|
| 1 | **High** | No affirmative, reachable routing cue ever sends ambient/mechanical work to Alchemist, despite `AGENTS.md` rule 5 implying such a path should exist. | `AGENTS.md:11` (rule 5) vs. `AGENTS.md:26`, `docs/LEGION-CANONICAL-SSOT.md:265-271`, `doctrine/legion.md:24-25` | Either reword rule 5 so it doesn't imply an unreachable capability, or define one concrete ambient-tier trigger (e.g., "cheap-worker delegation may be invoked directly for exact, narrow mechanical units without a full contract") and wire it into `doctrine/legion.md`'s routing diagram, which currently omits Alchemist entirely. |
| 2 | **Medium** | Alchemist's tests (`skills/alchemist/tests/*.py`) are never executed by any script or CI job. | `package.json` test script; `.github/workflows/ci.yml`; `scripts/ci/right-git-ci.sh` | Add a Python test step to CI (posix tests self-skip on Windows already). |
| 3 | **Medium** | `skills/manifests/alchemist.json` shipped stale relative to `tests/test_posix_runner.py`. | `git diff` vs HEAD `9aa4b53b` | Regenerate the manifest in the same commit as any `skills/alchemist/**` change; consider a scoped pre-commit hook. |
| 4 | **Medium** | `python-runtime` undeclared HOST_CAPABILITY for a skill whose worker path shells out to `python3` unconditionally. | `skills/alchemist/dependencies.json`; `scripts/run-worker.sh:90` | Add `python-runtime` (already in `src/registry/capabilities.json:56-71`) to `dependencies.json`. |
| 5 | **Low** | Parity check verifies only 2 of 3 hand-synced description copies. | `scripts/check-authority-parity.mjs:11,23` | Include `doctrine/<role>.md` or document the exclusion. |
| 6 | **Low** | Arcane has no typed awareness of the worker exit-code contract; purely self-reported. | `hooks/hooks.json`; `engine/bins/legion-hook/src/main.rs` | Have Arcane's completion-gate recognize/record the run-worker exit code, or document the trust-based design explicitly. |
| 7 | **Low** | No architecture document (current or archived) for the two-layer relay design. | `docs/provenance/` inventory; SSOT never cites `manual.md` | Fold a "worker relay" subsection into the SSOT or cross-reference `manual.md` as canonical. |
| 8 | **Info** | Generic manifest consumers list implies a routing relationship Alchemist doesn't have. | `scripts/refresh-local-skill-manifests.mjs:79-89`; `src/registry/skills/index.json:36` | Scope consumers per `capabilityClass` or accept as template artifact. |

## Status update (same day, commit 24d52058)

Partially remediated by a parallel session — see plugin-system-gaps.md §4 and docs/audits/remediation-status.md for exactly which gaps above are closed vs still open.
