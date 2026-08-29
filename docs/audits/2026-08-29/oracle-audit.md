# Oracle Subsystem Audit — 2026-08-29

Fresh audit; prior documents in `docs/audits/` were not read. Evidence anchored to file:line at read time.

## 1. Inventory

**Identity chain:**
- `src/roster/oracle.md` — canonical identity/authority/tier (`modelTier: frontier-judgment`)
- `doctrine/oracle.md` — canonical method (Completion Validation protocol, PASS/BLOCK format, "No false clean")
- `agents/oracle.md` — Claude Code dispatch card: `model: opus`, `tools: Read, Grep, Glob`
- `docs/LEGION-CANONICAL-SSOT.md` — ownership-boundary references (routing diagram, ownership table, model-tier table)

**Packaging / contracts:**
- `src/packages/oracle/README.md` — a self-authored "name collision notice": the package states outright it "is not the Oracle assurance authority," is a facade over `src/lib/core` (Audit), has no consumer outside its own tests, and "actively misleads anyone looking for the assurance authority."
- `src/packages/oracle/{index.mjs,lib/*,fixtures/*,tests/*}` — the unrelated Audit-facade package
- `src/packages/contracts/schemas/oracle-completion-validation-v1.schema.json` — PASS/BLOCK receipt schema, registered at `src/packages/contracts/index.mjs:37`
- `src/packages/contracts/schemas/authority-dispatch-v1.schema.json:18` — a **different** "oracle" `$def`: the dispatch-packet envelope used by the structured `dispatch` skill
- `src/lib/dispatch-validator/validate-dispatch.py:494-501` — structural validator for `packet_type in ("oracle","seer")`
- `src/lib/cli/commands/completion.mjs` — `legion completion claim|evidence`; the `evidence` subcommand requires `observedAuthority === 'oracle'` but emits an `evidence-capability-receipt-v1`, **not** the `oracle-completion-validation-v1` shape
- `scripts/check-authority-parity.mjs` — compares agent-card descriptions against roster only (doctrine excluded)

**Skills that reference Oracle (none own it):** `skills/dispatch`, `skills/debugger`, `skills/audit-fix`, `skills/covenant` — all only to draw a boundary or require an Oracle PASS as an exit gate. **No `skills/oracle/` directory exists.**

**Harness:** `hooks/hooks.json` wires all events to `legion-hook`; `engine/bins/legion-hook/src/{main.rs,protocol.rs}` contain **zero** Oracle-specific logic.

**Agent frontmatter asymmetry (verified):** `agents/oracle.md` declares `tools: Read, Grep, Glob`; neither `agents/sage.md` nor `agents/alchemist.md` has any `tools:` line — they default to full tool access. Oracle's read-only independence is harness-enforced; Sage/Alchemist boundaries are prose-only.

## 2. Architecture docs status

No dedicated Oracle architecture document exists. What exists: `doctrine/oracle.md` (method prose), `src/roster/oracle.md` (identity card), ~10 scattered lines in the SSOT. None describes how Oracle is wired into the runtime — dispatch mechanics, schema lifecycle, or enforcement. The shipped completion-validation schema's `description` and `subject.digest` fields cite a local audit artifact by path (`docs/audits/oracle-audit.md`) rather than self-contained rationale.

## 3. Packaging gaps

1. **`oracle-completion-validation-v1.schema.json` has no producer and no consumer anywhere in the repo.** Registered and structurally smoke-tested (48/48 pass), but no code constructs `kind: "legion-oracle-completion-validation"`, nothing validates a verdict against it, and the `ocv_` ID pattern is emitted nowhere. Fully aspirational.
2. **`src/packages/oracle/**` is a naming collision with zero external consumers**, still shipped. A code search for "oracle" hits it before the real authority sources; the README itself proposes rename/removal and defers the decision to the repository owner.
3. **Two independently-defined "oracle" schema shapes** (verdict receipt vs dispatch packet) with no cross-reference; nothing states how a dispatch validated against one should produce an artifact validated against the other.

## 4. Harness gaps

1. **No technical enforcement that Oracle ran before Stop — pure honor system.** `engine/bins/legion-hook/src/main.rs:22-30` short-circuits lifecycle events; `protocol.rs:126-134` classifies `Stop` as lifecycle; the branch unconditionally returns allowed ("lifecycle observation accepted"). A session can Stop claiming successful delivery having never dispatched Oracle. The "Universal Completion Validation" language is enforced only by the orchestrating model's choice.
2. **A real completion-gate exists but only orbits the contract chain.** `src/packages/arcane/lib/completion-gate.mjs` (consumed by `legion run close`) mechanically requires Oracle evidence — but the contract chain is reserved for locked domains/dispatched work; the far larger ambient tier has no equivalent gate.
3. **No `/oracle` skill.** Every sibling authority/capability has a `skills/<name>/SKILL.md` entrypoint; Oracle is reachable only via Task dispatch or doctrine prose. No packaged builder for the "one ephemeral chat packet," no receipt capture (by design — doctrine forbids durable artifacts), hence no way to audit "did Oracle run for delivery N" after the fact.
4. **Doctrine/agent-card description drift is unchecked.** `doctrine/oracle.md` frontmatter differs materially from `agents/oracle.md`/`src/roster/oracle.md`; the parity script doesn't cover doctrine.

## 5. Agent / input-contract gaps

1. **Only the rare structured-dispatch path has a machine-checked input contract** (`validate-dispatch.py:494-501`: lens required, read/forbidden scopes disjoint, content-bound reference). The common ambient path — Legion directly dispatching `legion:oracle` — assembles the doctrine's "one ephemeral chat packet" as free text with nothing verifying completeness or verbatim-ness.
2. **Oracle cannot independently retrieve what it's supposed to distrust Legion about.** `tools: Read, Grep, Glob` gives no transcript/session access; Oracle sees only what the distrusted orchestrator pastes into the dispatch prompt. Independence is procedural, not structural, for scope reconstruction. (The certification half — no effects — *is* harness-enforced by the tool restriction.)

## 6. What makes Oracle discoverable — the replicable pattern

Two concrete differences vs Sage/Alchemist:

1. **The trigger is a universal, unambiguous event ("every successful final delivery"), not a judgment call.** Sage/Alchemist triggers require the orchestrator to first judge a rare precondition — a step easily rationalized away. To replicate: give Sage/Alchemist concrete, low-ambiguity checkpoints a router can mechanically recognize.
2. **Oracle's boundary is harness-enforced via `tools:` frontmatter**, not just doctrine prose. To replicate: give Sage a read/analysis-only tool grant (matching "never performs product-state effects") and consider scope restrictions for Alchemist.

## 7. Ranked gap list with fixes

1. **[Critical — Harness]** `Stop` unconditionally allowed with no Oracle-ran check (`main.rs:28-30`, `protocol.rs:126-134`). *Fix:* either explicitly accept the honor-system for the ambient tier and soften the "Universal … policy" doctrine language, or have the Stop branch consult a lightweight per-session "oracle ran" marker for sessions that touched files.
2. **[High — Packaging]** Completion-validation schema fully disconnected — no producer, consumer, or validation. *Fix:* wire Oracle's response into this shape and store it (e.g., alongside `legion completion evidence`), or mark the schema experimental.
3. **[High — Packaging]** `src/packages/oracle/**` collides with the real authority, ships with zero consumers. *Fix:* rename to `audit-facade` (as its own README proposes) or delete — decision explicitly deferred to Adrian.
4. **[Medium — Harness]** No `/oracle` skill / manual invocation entrypoint. *Fix:* thin `skills/oracle/SKILL.md` packaging the ephemeral-packet doctrine into a repeatable procedure, optionally with a packet validator.
5. **[Medium — Agent contract]** Ambient-path dispatch has no structural input contract. *Fix:* minimal checklist/validator Legion runs against its own dispatch prompt (verbatim turns present, diff present, exclusions present, claims present).
6. **[Low — Consistency]** Doctrine description drift uncaught by CI. *Fix:* add doctrine to the parity check or drop its `description:` frontmatter.
7. **[Low — Packaging hygiene]** Shipped schema/README cite a local audit report path. *Fix:* move rationale inline or into doctrine/provenance.
