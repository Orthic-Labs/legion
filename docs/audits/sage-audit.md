# Sage Subsystem Audit

Date: 2026-08-29. Method: read-only inspection of the full Sage definition chain, routing docs, registry, engine, and tests, plus cross-cutting packaging/harness/discoverability analysis. Verification of the relevant Node test subset: 79/79 pass.

## 1. What Sage is, per canon

Exceptional adjudication authority. Owns one question: does a material unresolved decision require authoritative closure beyond the selected capability's routine mandate? Model tier `frontier-judgment` (projected as `opus` for Claude Code). Canonical chain: `src/roster/sage.md` (identity/authority/trigger/tier) → `doctrine/sage.md` (operating method, freeze/handoff protocol) → `agents/sage.md` (live Claude Code subagent card).

## 2. Architecture documentation status

**Doctrine exists and is coherent; an architecture document does not exist.**

- `docs/architecture.md` is a Blueprint-generated stub ("No synthesized components yet") with zero mentions of Sage, dispatch, model tier, or receipts.
- No document states the dispatch path end-to-end. Sage has three runtime entry mechanisms — Task-tool auto-route via the `agents/sage.md` description, explicit `@sage` (regex-detected by `src/packages/arcane/lib/stop-shape.mjs:361`), and `packetType: "sage"` dispatch packets — each documented piecemeal, never assembled.
- The tier→model mapping (`frontier-judgment` → `opus`) is stated nowhere as policy; it is only inferable by diffing `agents/sage.md` against `src/roster/sage.md`.
- Whether a Sage disposition is ever receipted/chained (as Arcane receipts are) is unspecified; in practice it is consumed informally by the calling capability.

## 3. Invocation surfaces

| Surface | Discoverability |
|---|---|
| Task tool via `agents/sage.md` description | Moderate, degraded (Finding A) |
| Explicit `@sage` (AGENTS.md:50; detected by stop-shape) | Low — one prose mention, no `/sage` skill exists |
| Dispatch packets `packetType: "sage"` | Good within the Dispatch skill only |
| Codex `.codex/agents/sage.toml` (live-generated) | Good; carries tier, not literal model |
| Gemini `.gemini/commands/legion/sage.toml` | Explicit only |
| Arcane stop-shape nudge ("dispatch Sage now", stop-shape.mjs:481) | Runtime push, not an entry path |

## 4. Findings

1. **[High] The live routing description has drifted from doctrine.** `agents/sage.md:3` lacks the negative-boundary clause ("Do not dispatch for routine architecture, diagnosis, execution, or independent assurance") that `doctrine/sage.md:3` and `src/roster/sage.md:3` both carry. This is the exact text Claude Code routes on. Commit `889c9850` (2026-08-20) updated doctrine but not the agent card. No test detects this class of drift — `scripts/verify-plugin-parity.mjs:93-94` digests structure, not content.
2. **[High] No architecture document** (§2).
3. **[Critical, discoverability] Sage is structurally under-triggered.** Root cause is threefold:
   - The trigger is an abstract internal state ("a material unresolved decision cannot safely close under the selected capability's routine mandate"), not an observable event with symptom examples — contrast Oracle's "before every successful final delivery."
   - `AGENTS.md` (loaded every session) gives Oracle five reinforcing mentions plus a nine-sentence runbook and a canonical-sources pointer; Sage gets one sentence at tier 3 and no pointer to `doctrine/sage.md`.
   - There is no `skills/sage/` entry and no catalog row in `src/registry/skills/index.json`, so natural-language routing can never surface it; only the Task-tool description and `@sage` remain.
4. **[Medium] Roster README documents a retired generation path.** `src/roster/README.md:11` claims `legion bind --write` projects the roster into Claude Code; `bind/claude-code.mjs` is retired (`write()` returns empty). `agents/sage.md` is hand-maintained — the "never edit generated files" instruction is what allowed Finding 1.
5. **[Medium] Advisory-vs-authoritative contradiction.** `doctrine/legion.md:42` / `AGENTS.md:42`: "Advice is not a contract." `doctrine/sage.md:44-58`: a frozen, recorded, binding disposition. Unreconciled; a reader of the top-level routing doc will conclude Sage output is disposable.
6. **[Medium] Skill manuals over-route to Sage.** `skills/seo/references/manual.md:94` and `skills/brand-identity/references/manual.md:421` say "dispatch Sage to plan" for routine execution planning — the retired Execution-Compile pattern that `doctrine/sage.md:31-33` disclaims.
7. **[Medium, packaging] Doctrine unreachable when installed standalone.** `agents/sage.md` references `doctrine/sage.md` and `src/roster/sage.md` as bare relative paths (no `${CLAUDE_PLUGIN_ROOT}`); a subagent resolves those against the session cwd, so outside this repo the pointers dangle. The dependency-closure gate never inspects `agents/` or `doctrine/`, so this cannot be caught today.
8. **[Low] Engine `model_ceiling` is parsed from agent frontmatter and never consumed** anywhere in `engine/` — inert config, undocumented whether intentional.
9. **[Low] Tier vocabulary drift** — `frontier-judgment` (roster, SSOT:460) vs `"FRONTIER"` (dispatch example); `modelRouting.modelTier` is schema-unconstrained.
10. **[Low] No test covers** agent-card-vs-doctrine content parity, tier→model mapping, or Sage's output contract (the adjudicated-decision/freeze-handoff shape). Existing coverage (semantic-routing acceptance, stop-shape, bind, parity) is solid for routing and projection.

## 5. Recommended fixes, in order

1. Re-add the negative-boundary clause to `agents/sage.md` and rewrite the description symptom-first (concrete triggers: "two valid interpretations produce materially different outcomes", "ownership or scope is disputed between capabilities", "an authoritative ruling is needed to unblock work"), keeping the exclusion clause.
2. Give Sage AGENTS.md parity with Oracle: a worked-example block and a canonical-sources pointer to `doctrine/sage.md`.
3. Add a content-parity check (description drift between `agents/`, `doctrine/`, `src/roster/`) to `legion:check`.
4. Correct `src/roster/README.md` to name the plugin package as the Claude Code install owner.
5. Resolve the advisory-vs-authoritative contradiction in `doctrine/legion.md`/`AGENTS.md` one way.
6. Fix the two skill manuals that route planning to Sage.
7. Anchor or self-package the doctrine references (see `docs/audits/plugin-system-gaps.md`, packaging gap 1).
8. Persist Sage rulings: a durable decision log with supersession, surfaced at session start (see absorption catalog).
