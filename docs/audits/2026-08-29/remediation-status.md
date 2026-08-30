# Remediation Status

Date: 2026-08-29. Tracks the fixes applied against `docs/audits/plugin-system-gaps.md` and the four
subsystem audits. Verification at time of writing: `pnpm legion:check` PASS, `pnpm test` 1348/1348,
`cargo test` (engine, via RightKit) all suites pass, `cargo fmt -p legion-hook --check` clean.

## Fixed and verified

| Fix | Evidence |
|---|---|
| Hook denied every tool call made from a subdirectory (`resolve_git_dir` did not walk ancestors) — a hard fail-closed lockout, reproduced live in this session | `engine/bins/legion-hook/src/main.rs`, test `source_revision_resolves_from_a_subdirectory` |
| `MultiEdit` was matched in `hooks/hooks.json` but unclassified, so every MultiEdit call was denied | `main.rs` FILE_WRITE arm, test `multi_edit_classifies_as_file_write` |
| `legion` / `legion-hook` were undeclared host capabilities with no stated degradation | `src/registry/capabilities.json` |
| Skills shelled out to the `legion` CLI without declaring it | `skills/{audit,audit-fix,audit-visual,research}` frontmatter + `dependencies.json` |
| `agents/sage.md` and `agents/oracle.md` had dropped the negative-boundary clause their roster carries | `agents/*.md`, `src/roster/*.md`, `doctrine/*.md` |
| Sage/Alchemist triggers were abstract states, not observable events | symptom-first descriptions across all three definition files |
| Nothing detected agent-card vs roster description drift | new `scripts/check-authority-parity.mjs`, wired into `pnpm legion:check` |
| `AGENTS.md` gave Oracle a runbook, Sage one sentence, Alchemist only anti-triggers | worked examples at tiers 3 and 4; `doctrine/sage.md` and `doctrine/alchemist.md` added to Canonical sources |
| Advisory-vs-authoritative contradiction for Sage | tier 3 now distinguishes an advisory question from a tier-4 freeze |
| Two skill manuals routed routine execution planning to Sage (the retired Execution-Compile pattern) | `skills/seo/references/manual.md`, `skills/brand-identity/references/manual.md` |
| `src/roster/README.md` documented a retired Claude Code generation path | corrected; Claude Code cards are hand-maintained, parity now enforced |
| Oracle's read-only mandate was prose-only | `tools: Read, Grep, Glob` allowlist on `agents/oracle.md` |
| Dispatch validator rejected canonical `packetType: "oracle"` (only accepted retired `"seer"`) | `validate-dispatch.py`; `"seer"` kept as read_only_alias per `naming-registry.json`; regression tests added |
| No machine-checkable Oracle verdict artifact | `src/packages/contracts/schemas/oracle-completion-validation-v1.schema.json`, registered in `index.mjs` |

## Not done — deliberately left for the owner

1. **Arcane's global fail-open default is unchanged.** With `LEGION_NATIVE_APPLICATION_CONFIG` absent
   (the shipped state) every effect class is still allowed. Flipping it changes the security posture of
   every session, so it is the owner's call. The one-line change is in `authorize_effect`'s `None`
   branch in `engine/bins/legion-hook/src/main.rs`.
2. **Authority doctrine is still unreachable on a standalone install.** `agents/*.md` reference
   `doctrine/*.md` relatively. `${CLAUDE_PLUGIN_ROOT}` is only substituted inside hook *commands*, never
   in agent prose, so anchoring the cards with that token would invent host behaviour. This needs a real
   mechanism decision (self-packaging, a build-time inline, or resolution through the `legion` CLI).
3. **No public distribution channel ships the binaries.** `nativeRelease` is `blocked`, npm is private,
   `packaging/homebrew` and `packaging/winget` are placeholders. Installing today means copying the dev
   checkout, and the copy pulls the whole repo because `marketplace.json` has no file allowlist.
4. **`Stop` still cannot be gated**, so Oracle Completion Validation remains doctrine-only. The receipt
   schema above is the prerequisite; the hook check itself is not implemented.
5. **`mcp__*` effect classification.** Hook matchers can be widened, but `legion_contracts::EffectClass`
   has no `ExternalSideEffect` variant (only `legion_policy_model::EffectClass` does), so classifying MCP
   writes needs that enum extended first.
6. **Pre-existing clippy failures** in `engine/crates/legion-host/src/setup_registry.rs`. CI does not run
   clippy, so they are not gating, but they are real.
7. **Python test suites are not in CI.** `src/lib/dispatch-validator/test_validate_dispatch.py` and
   `skills/alchemist/tests/` run only when invoked directly.
