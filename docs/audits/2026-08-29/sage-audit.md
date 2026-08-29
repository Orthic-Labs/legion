# Sage Subsystem Audit — 2026-08-29

Fresh audit; prior documents in `docs/audits/` were not read. Evidence anchored to file:line at read time.

## 1. Inventory

**Core identity triad** (same pattern as Alchemist/Oracle):
- `agents/sage.md` — Claude Code agent card (hand-maintained, per `src/roster/README.md:13`)
- `doctrine/sage.md` — operating method
- `src/roster/sage.md` — canonical identity/authority/tier source, consumed by `src/lib/roster/index.mjs` (`ROLE_IDS = ['sage','alchemist','oracle']`)

Consistency between the first two is enforced by `scripts/check-authority-parity.mjs`, which diffs only the frontmatter `description:` line of `agents/sage.md` vs `src/roster/sage.md`. It does **not** diff `doctrine/sage.md` content or check for capability-class leaks.

**Registry / plugin surfacing:**
- `src/registry/plugin-surface.json:39-55` — lists `agents/sage.md` among 4 agents (alchemist, covenant-seat, oracle, sage)
- `src/registry/host-projection.json:547-551` — `roles[]` entry with description matching the agent card, used to project Sage into Codex/Gemini CLI bindings via `legion bind --write`
- `.claude-plugin/plugin.json:17` — "sage" in `keywords`
- `.claude-plugin/marketplace.json:9` — "Sage decides" in the plugin description
- `.codex-plugin/plugin.json` — also references Sage

**Contract/schema wiring** (`src/packages/contracts/`):
- `enums.mjs:15-22` — `AUTHORITY_ID` includes `'sage'`
- `enums.mjs:67-73` — `SAGE_CLAIM = ['ADJUDICATION_MADE','SEMANTIC_CONFLICT_RESOLVED','ACCEPTANCE_SEMANTICS_SEALED','ADJUDICATED_CONTRACT_SEALED']`
- `enums.mjs:97-101, 104` — `CLAIMS_BY_AUTHORITY.sage`, `CALLER_AUTHORITY` includes `'SAGE'`
- Referenced across `schemas/authority-dispatch-v1.schema.json`, `execution-contract-v1.schema.json`, `claim-v1.schema.json`, `covenant-request-v1.schema.json`, `amendment-v1.schema.json`, `blocker-v1.schema.json`, etc.

**Hook / enforcement footprint** (`src/packages/arcane/lib/`):
- `stop-shape.mjs:361` — `ESCALATION_EVIDENCE` regex matches `"subagent_type":"(?:legion:)?sage"` or `@sage` in the raw transcript
- `stop-shape.mjs:356-482` — this check fires **only** when the agent is emitting an unescalated "blocker"/stop-short pattern; step one of its own `ESCALATION` ladder (line 371) says *"Resolve it yourself now; dispatch Sage only if material meaning… remains unresolved"*
- `completion-gate.mjs:153-163` — the Oracle-equivalent hard gate: denies completion (`ARC_EVIDENCE_INSUFFICIENT`) without "authenticated execution-bound Oracle evidence." **No equivalent function exists for Sage anywhere in `arcane/`.**

**Skills that mention Sage** (none own it): `skills/architect/SKILL.md:20-23`, `skills/debugger/SKILL.md:22-25`, `skills/alchemist/SKILL.md`, `skills/research/SKILL.md`, `skills/wake/SKILL.md`, `skills/dispatch/references/agent-routing.md:3`, `skills/dispatch/examples/sage-adjudication.json`, `skills/dispatch/examples/sage-adjudication-dispatch.json`.

**Confirmed absent:**
- No `skills/sage/` directory (compare `skills/alchemist/`, `skills/covenant/`, both with `SKILL.md`)
- No `skills/manifests/sage.json` (compare `alchemist.json`, `covenant.json` present)
- No Sage tool in `engine/bins/legion-mcp/src/tools.rs` — Sage is unreachable via the `legion serve --stdio` MCP server; the only invocation path inside Claude Code is the Agent/Task tool's `subagent_type: legion:sage`.

**Archived history:** `docs/provenance/sage-architect-archived.md`, `docs/provenance/sage-diagnose-archived.md` — record that "Sage Architect" and "Sage Diagnose" routes were retired and absorbed into Architect/Debugger.

## 2. Architecture docs status

No dedicated Sage architecture document exists beyond the identity triad — symmetric with Alchemist and Oracle, so not a Sage-specific gap. The closest thing is `docs/LEGION-CANONICAL-SSOT.md`:
- Lines 70-98: primary rules, ownership table (Sage identity → `src/roster/sage.md`, method → doctrine)
- Lines 148-233: authority-attachment model, retirement of "Sage Architect"/"Sage Diagnose"/"Execution Compile" routes
- Lines 265-270: "Never infer: `diagnose → Sage`"
- Lines 456-462: model tier (`Sage → frontier-judgment`)

Gaps: the canonical routing-shape diagram in `doctrine/legion.md:41-59` names **"Oracle Completion Validation under current policy"** as an explicit pipeline stage, but Sage appears nowhere in that diagram — only as prose annotation elsewhere. There is also no schema-referenced output template for a Sage "freeze & hand off" record (`doctrine/sage.md:42-49` is prose-only), unlike Oracle's exact PASS/BLOCK template (`doctrine/oracle.md:33-54`).

## 3. Packaging gaps

Structurally, Sage is wired cleanly: present in `enums.mjs`, all relevant contract schemas, `plugin-surface.json`, `host-projection.json`, `marketplace.json`, `plugin.json` keywords, and parity-checked by `check-authority-parity.mjs` / `pnpm legion:check`. No leaks outside the four capability classes were found — Sage's identity files don't reference undeclared HOST_CAPABILITY/PROJECT_OVERLAY paths.

The gap is coverage of the drift-detection system itself: `docs/agent-rules.md`'s Locked Invariants require refreshing `skills/manifests/*.json` digests after editing "any packaged skill file," but Sage's three identity files are **not skills** and carry no manifest digest at all — the only automated check is the one-line description diff in `check-authority-parity.mjs`, which never inspects `doctrine/sage.md` or runs a capability-class classification pass against it.

## 4. Harness gaps

- **No slash entrypoint.** `/alchemist` and `/covenant` both have `skills/<name>/SKILL.md`; Sage has none. A user cannot explicitly invoke Sage the way they can Alchemist or Covenant.
- **"@sage" is undefined infrastructure.** `AGENTS.md:50`, `docs/agent-rules/legion.md`'s "How dispatch works" section, and `stop-shape.mjs:361` all reference `@sage` as an explicit-invocation convention, but no slash command, hook, or CLI flag actually recognizes it — the only place it is mechanically read is `stop-shape.mjs`'s post-hoc transcript regex.
- **MCP surface offers nothing.** `legion serve --stdio` (`engine/bins/legion-mcp/src/tools.rs`) exposes no Sage tool; Sage exists solely as an agent card for the Task/Agent tool.
- **No mechanical gate.** `completion-gate.mjs:163` hard-denies completion without Oracle evidence unconditionally. Sage's only hook logic (`stop-shape.mjs`) is narrow, reactive, and its own escalation ladder tells the agent to avoid dispatching Sage as step one.
- Agent frontmatter itself (`agents/sage.md:3`) is well-formed (positive+negative trigger pair), structurally on par with Alchemist's and Oracle's — the defect is not in the one-liner but in everything around it.

## 5. Agent-visibility gaps — why Oracle fires and Sage doesn't

1. **Asymmetric mandate strength.** `AGENTS.md:13` (item 7) is an unconditional imperative: *"Before any successful final delivery, get fresh Oracle semantic PASS."* Sage's mandate (`AGENTS.md:22`, tier 3 at `AGENTS.md:42`) is conditional on the dispatching agent first concluding, unaided, that "a material unresolved decision cannot safely close" — a subjective, self-assessed bar. Tier 2 ("ambient") is explicitly the default for almost all mutation work (`AGENTS.md:41`), so the default path never reaches Sage's condition.
2. **Routing diagram omission.** `doctrine/legion.md:41-59` draws Oracle as a named pipeline stage; Sage is absent from the diagram entirely.
3. **Every specialist skill is told to avoid Sage.** `skills/architect/SKILL.md:21-23` — "does not route through Sage for routine decisions"; `skills/debugger/SKILL.md:24-25` — same wording. `doctrine/sage.md:26-32` itself pushes "routine architecture," "routine root-cause hypotheses," and "routine design judgment" explicitly to Architect/Debugger/Designer. The two largest historical trigger categories, "Sage Architect" and "Sage Diagnose," were retired outright (`docs/LEGION-CANONICAL-SSOT.md:96-97, 227-229`) with no replacement positive trigger added anywhere.
4. **The one Sage-aware hook discourages dispatch.** `stop-shape.mjs:371` — first rung of the escalation ladder is "Resolve it yourself now; dispatch Sage only if…" This fires only at Stop-time on blocker language, as an anti-laundering backstop, not a proactive signal.
5. **No discoverable entrypoint** for a user or agent to reach for Sage deliberately, unlike Oracle which is invoked by an unconditional checklist item regardless of discoverability.

Net diagnosis: the system is internally consistent about Sage being rare-and-exceptional, and it is packaged correctly — but every actual mechanism that would surface Sage to a working agent (top-level checklist phrasing, routing diagram, specialist-skill wording, the one hook that mentions it, absence of a slash command) points *away* from dispatching it, while the equivalent mechanisms for Oracle point *unconditionally toward* dispatching it. The historical narrowing (retiring Sage Architect/Sage Diagnose) removed Sage's largest trigger surfaces without adding any compensating signal.

## 6. Ranked gap list with fixes

1. **[HIGH]** No proactive, checklist-level trigger for Sage anywhere, unlike Oracle's unconditional `AGENTS.md:13`. — *Fix:* add a mandatory self-check adjacent to item 7 (e.g., "did this task involve competing interpretations, disputed ownership, or a blocked decision? If yes and it wasn't escalated, say so explicitly") so skipping Sage becomes a recorded judgment, not a silent default.
2. **[HIGH]** Sage is absent from the canonical routing diagram — `doctrine/legion.md:41-59`. — *Fix:* add a conditional branch in the diagram (e.g., `WORK GRAPH → [material ambiguity?] → Sage →`) so it reads as a live branch rather than an omission.
3. **[MEDIUM-HIGH]** Only Sage-aware hook logic is reactive and discouraging — `stop-shape.mjs:361-482`. — *Fix:* either document this as an intentional last-resort design, or add a proactive soft-warning check (e.g., extending `semantic-health.mjs`, which already references sage) that flags likely-unresolved ambiguity before Stop, not just at blocker-laundering time.
4. **[MEDIUM]** Historical narrowing removed Sage's two biggest trigger categories with no replacement — `docs/LEGION-CANONICAL-SSOT.md:96-97,227-229`, `skills/architect/SKILL.md:20-23`, `skills/debugger/SKILL.md:22-25`. — *Fix:* add one concrete positive worked-example trigger per skill (mirroring the SSOT's own "Debugger + Sage" example at `docs/LEGION-CANONICAL-SSOT.md:156-158`) so escalation isn't purely theoretical.
5. **[MEDIUM]** No `/sage` skill/slash surface, asymmetric with `/alchemist` and `/covenant`. — *Fix:* either state explicitly in `doctrine/sage.md`/`AGENTS.md` that Sage is deliberately not user-invokable (an attached authority, not a summoned capability) so this reads as a decision not an oversight, or ship a minimal `/sage` entrypoint for the explicit tier-4 case already permitted by `AGENTS.md:42`.
6. **[LOW-MEDIUM]** "@sage" convention is prose-only, with no registered mechanism — `AGENTS.md:50`, `stop-shape.mjs:361`. — *Fix:* wire it as a real directive (e.g., a `UserPromptSubmit` hook) or remove the phrasing to avoid implying a nonexistent mechanism.
7. **[LOW]** Sage's identity files fall outside the skill-manifest digest/drift-detection system; `check-authority-parity.mjs` only diffs one frontmatter line. — *Fix:* extend that script (or add a sibling check) to also diff `doctrine/sage.md` and run the capability-class classification against all three Sage files.
8. **[LOW]** Sage's "freeze & hand off" output is prose-only (`doctrine/sage.md:42-49`), unlike Oracle's exact copy-pasteable template (`doctrine/oracle.md:33-54`). — *Fix:* add a literal output template block for consistency and greppability.

## Status update (same day, commit 24d52058)

Partially remediated by a parallel session — see plugin-system-gaps.md §4 and docs/audits/remediation-status.md for exactly which gaps above are closed vs still open.
