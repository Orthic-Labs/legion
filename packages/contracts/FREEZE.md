# WP2 Freeze Record — Legion Shared Contracts

**Scope:** `D:/Claude/tools/skills/legion/packages/contracts/` only. Nothing outside
this directory was created, edited, or deleted by this work. Naming throughout is
canonical per `docs/plans/legion/00-CANON.md`: Sage, Alchemist, Seer, Arcane,
Covenant, Legion, Kernel. The archive's `Sorcerer`/`Sentinel` names do not appear
anywhere in the produced contract surface (enforced by `smoke.test.mjs`'s naming
guard test; see judgment-call J-0 below for why `enums.mjs`/`ids.md` are excluded
from that specific scan).

**Read, in order, before this freeze:** `docs/plans/legion/00-CANON.md`,
`docs/plans/legion/ARCHITECTURE.md` (Part III, §33, §6a, §24a, Part XI-A),
`docs/plans/legion/COVENANT.md` (§10, §11, §12), the archive's
`02-FINAL-IMPLEMENTATION-PLAN.md` Workstream C / §7 / §8 / §9, and the existing
sealed schema substrate under `tools/skills/legion/schemas/` and
`tools/skills/legion/lib/contracts/` (read-only; not modified).

**Mid-freeze update incorporated:** the S00 Forge semantic baseline completed
concurrently and is cited where it changed contract design — see "S00 baseline
facts incorporated" below. Its output lives at
`docs/plans/legion/s00-baseline/legacy-semantic-inventory.json` and
`docs/plans/legion/s00-baseline/S00-REPORT.md`; this freeze references that
inventory by path rather than re-stating its contents.

---

## 1. File list with SHA-256 digests

Computed via `sha256sum` over the final state of every file in this package
(POSIX line endings as written; recompute if line endings change on checkout).

```
694e47a95d9e8fe56eb1e1fb422931c1f0b6aeedf38d7d2b0d9bb223ee93c7c0  enums.mjs
e5c54d550171f039dced506ac3e036080227424812b4e6ba7ee8d1e3e7baa39d  ids.md
5e14227b6499fc6c8a85f7299851a9fc63239d5621ed812f543120d4e1cb7aaf  index.mjs
ea03733f69a874aa18ef185b4d38923884b392a3a1f9600c91b62321e392704f  smoke.test.mjs
ddfe6382c01367589841a90763a99e4e96570884f3598741f880794dad7f3596  schemas/amendment-v1.schema.json
eb1c847abb73acf195b0b18a8f71737603c6f3ce722855c594cb57ca2db8d820  schemas/artifact-v1.schema.json
1b762011320ef14c3fbb88fa04be1a7b38d6b2e870e1a1951c293ce1f6642798  schemas/blocker-v1.schema.json
7ac613102e6a93c2a58a81c2ba2f22edaa33515b462dcb56bc583875a7bd67ac  schemas/claim-v1.schema.json
69bd24e42baa0ebcab10dd3af438a44d4a5f30abcb084d4f4026cb34fc209a64  schemas/covenant-record-v1.schema.json
d20c19b62a4cd9d4d6c96c2aa6f02484111895264e75bcb9ea1a3b2e22a05aae  schemas/covenant-request-v1.schema.json
5b0cd86369913048b61e7c5e498a5a74427d617af349c93ef0b175679ab063eb  schemas/effect-receipt-v1.schema.json
f169ea1f54648ed07bb34ef34637a73ce4ead691055a11c79064c95c72890676  schemas/effect-request-v1.schema.json
a5d4103a8ca5250cc4cbb6d03a3716324345b517fd7d64ff33ca3bb800fb272d  schemas/evidence-capability-receipt-v1.schema.json
893164ef22bbc34a8d2bf70fe9b4e26ed30ae0031d48d63076a2f252aca604cd  schemas/execution-contract-v1.schema.json
a676c8b8d859bf7baae13db7381e1c0dc1fa43003a4271a2e1d42cf7418fb24f  schemas/execution-task-v1.schema.json
3c80ed9c32f6defe9ba9bfcfb02783c0bb61a23387bdfa3d41407728361be898  schemas/legacy-envelope-v1.schema.json
5197eea6541a12926ea9dbba8d31222cafb28f3c302e4f391ad3ffaedf20c711  schemas/legion-result-v1.schema.json
41cb7ff6fa4f3ea4206ae37509af6c4ab58adbcfd32ddcb156dabfe56e210d49  schemas/operation-envelope-v1.schema.json
66be53d27a48b7fb5dfe58a6acb5335475193fe00cd8a4ea464ea60254179535  schemas/run-identity-v1.schema.json
a27f2ca9ffd4146f5e52e70c8f40842c44b15c71aeac05b7e2bfe33f95bc8905  schemas/worker-capsule-v1.schema.json
```

16 schema files (15 named object types + the `legacy-envelope-v1` extension
point) + `enums.mjs` + `ids.md` + `index.mjs` + `smoke.test.mjs` = 20 files.

**EC-602 amendment (2026-08-12):** `execution-contract-v1` now admits one optional,
closed `advisoryProfile` binding compiled from a package-owned validated skill manifest.
It only narrows authority; callers cannot supply manifest paths, bytes, booleans, or digests.
No schema version or effect-class vocabulary changed. Digests above bind this amendment.

## 2. Test run result

```
$ node --test smoke.test.mjs
ℹ tests 42
ℹ suites 0
ℹ pass 42
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
```

All 42 assertions pass: every schema parses as valid JSON, declares draft
2020-12 + a unique `$id` + `schemaVersion:{const:1}` + a `kind` const,
sets `additionalProperties:false` at every relevant level, every enum-bearing
property is set-equal to its `enums.mjs` export (or an explicitly documented
subset — e.g. `artifactUnit.latitude` is `{EXACT,BOUNDED}`, a two-value subset
of the three-value `LATITUDE` enum, by design — see J-3), the ID-prefix
grammar in `ids.md` is exercised by at least one schema, `enums.mjs`'s
`assertEnum`/`assertSchemaVersion` behave as documented, and no produced
schema or `index.mjs` contains the superseded archive naming.

No ajv or other JSON Schema validation library was added (none exists in the
legion repo and the task brief explicitly forbids new dependencies); checks
are structural (JSON parse, `$defs`/`properties`/`enum`/`required`/`const`
presence and set-equality against `enums.mjs`), consistent with the task
brief's "structural JSON validity + required-key presence checks are
sufficient."

## 3. Judgment calls

### J-0 — camelCase field naming (global)

ARCHITECTURE.md's prose examples use `snake_case` (`contract_id`,
`source_revision`, `open_questions`). Every existing legion JSON Schema
inspected (`schemas/core/artifact-record-v1.schema.json`,
`schemas/execution-receipt-v1.schema.json`,
`schemas/qualification/release-manifest-v1.schema.json`, etc.) uses
`camelCase` (`schemaVersion`, `sourceRevision`, `dirtyOverlayDigest`). Treated
ARCHITECTURE's prose as conceptual naming, not a wire-format mandate, and
standardized every produced schema on `camelCase` to match the actual
repo-wide JSON Schema convention ("reuse its conventions" per the task
brief). A field-name cross-reference table (prose name -> JSON field) is
implicit in each schema's own field list; flagging here because it's a
repo-wide decision, not a per-schema one.

### J-1 — Non-goal (`NG-#`) included despite absence from the §33 canonical list

ARCHITECTURE §33 lists 16 shared-state object types and does not include
`Non-goal`. §5.2 ("Architect" route output) shows `NG-1 Non-goal` as example
output alongside `R-1`/`D-1`/`I-1`/`AC-1`. §11's canonical `ExecutionContract`
shape explicitly requires a `non_goals[]` array. Included `nonGoals[]` with an
`NG-#` id family in `execution-contract-v1` on the strength of §11's explicit
field plus §5.2's illustrative id, even though §33 never formally registers
`NG-` as a canonical id prefix.

### J-2 — `RA-#`/`E-#`/`P-#`/`AR-#` recorded in `ids.md` but not bound to any schema

§22's evidence-chain diagram uses `RA-12` (remediation artifact), `E-88`
(effect receipt), `P-92` (proof/test evidence), and `AR-12` (fresh Seer
re-audit) — none of which recur elsewhere or appear in the §33 canonical
list, and none of which are in the WP2 task's required schema list. Documented
their existence and meaning in `ids.md` so a future author does not silently
collide with them, but did not create schemas or reserve enum values for
them. **Reviewer should confirm** whether any of the five downstream lanes
this freeze unlocks actually need `RA-#`/`P-#`/`AR-#` as first-class ids (my
current read: `RA-#` collapses into `artifact-v1` + `Blocker.evidenceRefs`,
`P-#` collapses into `evidence-capability-receipt-v1`, and `AR-#` is just
another `covenant-record-v1`/Seer-owned re-audit artifact reference — but this
is inference, not sourced).

### J-3 — OPEN-latitude artifacts live in `openQuestions[]`, not a third `artifacts.open[]` bucket

§11's canonical shape has exactly two artifact buckets (`exact[]`,
`bounded[]`) but §12 names three latitude values (EXACT/BOUNDED/OPEN) and
says OPEN "is not executable. It must return to Sage." Modeled this as: an
artifact can only be placed in `exact[]`/`bounded[]` once it has resolved to
EXACT or BOUNDED latitude; while unresolved, it is represented as an
`openQuestion` entry (`id`, `question`, `blocksArtifacts[]`) in
`openQuestions[]`, which G9 already requires to be empty before the contract
is executable. `execution-contract-v1`'s `artifactUnit.latitude` is
therefore constrained to `{EXACT, BOUNDED}` only (checked in
`smoke.test.mjs`).

### J-4 — `CovenantRequest.convenedBy`

Not in COVENANT §10's suggested field list. Added because ARCHITECTURE §3a
and COVENANT §11 both state, in near-identical language, "Legion may convene;
Legion never disposes" — the orchestrator can trigger a Covenant request
without being `callerAuthority`. Without a field to record that, an
orchestrator-convened request would be indistinguishable from one the caller
authority initiated itself. `convenedBy` is `const: "legion"` when present,
`null`/absent otherwise, and is never equal to `callerAuthority`.

### J-5 — `evidenceClass` values duplicated inline rather than imported

`evidence-capability-receipt-v1.evidenceClass` and its enum values
(`deterministic/measured/interpretive/external/human`) are copied from
legion's existing `EVIDENCE_CLASS` convention
(`tools/skills/legion/lib/contracts/index.mjs` re-exporting from
`providers/security/contracts.mjs`, and mirrored in
`schemas/core/status-enums.schema.json`). Did not `import` that module from
`packages/contracts/enums.mjs` to avoid this new package taking a runtime
dependency on legion's internal provider/audit pipeline (a heavier,
differently-versioned module graph) for the sake of five string literals.
This is a deliberate alignment, not an accidental duplication — flagged per
the "reuse its conventions" instruction, since literal `import` was judged
the wrong form of reuse here.

### J-6 — `ALCHEMIST_STATE` reused verbatim as `DOMAIN_OUTCOME`

ARCHITECTURE §18 states its seven terminal/intermediate Alchemist states
"should be part of Legion's shared state vocabulary, not duplicated ad hoc in
prompts." Took that literally: `enums.mjs`'s `DOMAIN_OUTCOME` is `export const
DOMAIN_OUTCOME = ALCHEMIST_STATE` (the same array reference, not a
parallel list), and `execution-task-v1.status`,
`operation-envelope-v1`'s `OperationResult.domainOutcome`, and
`legion-result-v1.domainOutcome` all use it. One side effect: a task that
hasn't reached a terminal/intermediate Alchemist state yet (e.g. still
running) has no eighth "in progress" value here — that axis is carried by
`INVOCATION_STATE` instead (see J-7), consistent with I-09's orthogonality
requirement.

### J-7 — `INVOCATION_STATE` and `CLAIM_BOUNDARY` are invented enums

Neither ARCHITECTURE nor the archive gives a literal enum for "did the
operation itself run" (`INVOCATION_STATE`) or "what may the result honestly
claim" (`CLAIM_BOUNDARY`) — only the *requirement* that these be tracked as
axes orthogonal to domain outcome (I-09; archive §7.12; I-12 "no false
clean"). Synthesized both from the vocabulary those sections already use:
`INVOCATION_STATE` from Workstream D's "cancellation, resumption, expiry,
input-required handling" and Phase 9's durable terminal states;
`CLAIM_BOUNDARY` from Seer's claim vocabulary (§26) and archive §7.11's
"safe/prohibited claims." **This is the freeze's largest single invention** —
the WP2 task brief explicitly required "invocation state vs domain outcome vs
claim boundary as SEPARATE fields," which is unambiguous about the *shape*
but silent on the *values*. Flagged prominently; see OPEN QUESTIONS below.

### J-8 — `EFFECT_CLASS` list is synthesized, not sourced verbatim

No document gives a closed effect-class enum. Built the twelve-value list from
the containment/policy nouns ARCHITECTURE §24/§24a and archive Workstream E /
Phase 5 actually name (paths, commands, network, process, credentials,
install, VCS, publish, external side effects). Reasonable confidence this is
*complete enough* for WP2's purposes; low confidence it is the *final* set
Arcane will enforce — Workstream E owns the real policy surface.

### J-9 — `MODEL_TIER` normalizes Part XI-A's table into four names

ARCHITECTURE Part XI-A names concrete model classes ("Opus-class",
"MiMo/DeepSeek-flash/Luna-class") per component, not a tier enum. Collapsed
to `FRONTIER | MID | CHEAP_STRICT | NONE` (Arcane's row is literally "no
model," hence `NONE`). `CHEAP_STRICT` bundles "cheap worker, strict profile"
as one tier name rather than splitting tier and profile, since §6a's routing
rule 2 ties latitude width to tier as a unit ("Narrow BOUNDED work ... goes to
cheap workers under a strict profile").

### J-10 — Opaque runtime-handle ID grammar (`run_<ulid>`, `req_<ulid>`, etc.)

Neither source document gives a grammar for Kernel-issued runtime identifiers
(as opposed to the human-facing `R-#`/`D-#`/... sequence ids, which §33 does
specify). Chose ULID-suffixed opaque handles for monotonic sortability and no
coordination requirement, consistent with archive §9.2's "opaque handles
where model-visible path not required." Fully invented; see `ids.md`.

### J-11 — Several `type: string` free-text fields left un-enumerated on purpose

`artifactKind` (artifact-v1), `capability` (evidence-capability-receipt-v1),
`operation` (effect-request/receipt), `subjectType` (claim-v1,
covenant-request-v1) are free strings, not enums. None of the source
documents give closed vocabularies for these, and inventing one risked
silently constraining a downstream lane (e.g. Seer's audit-control naming,
which this freeze must not duplicate per the task brief) more than the WP2
scope warrants. Left open by design, not by oversight.

## 4. S00 baseline facts incorporated (mid-freeze course correction)

The coordinator's S00 Forge baseline (`docs/plans/legion/s00-baseline/`)
completed while this freeze was in progress and required three additions,
made after the initial schema draft:

1. **`effect-receipt-v1.authentication` and
   `evidence-capability-receipt-v1.authentication`** — S00's report found
   Forge's `signature_or_mac` field (`orthic.tool-receipt.v1`,
   `hooks/claude-code/tool-receipt.js:80` per the inventory) is a self-hash
   by the same untrusted process that built the receipt: no secret key, no
   MAC, no signature. Both receipt schemas now require an `authentication`
   object (`issuerIdentity`, `verificationMethod`, `perMessage`,
   `verifiedAt`) so a receipt can state honestly how it knows who is
   asserting it, instead of silently inheriting Forge's self-hash-as-trust
   pattern. `verificationMethod` uses the new `AUTHENTICATION_METHOD` enum
   (`host-connection-trust | capability-signature | unauthenticated`).
2. **`replayDefense` on both receipt schemas** — S00 found no nonce,
   sequence number, or freshness window anywhere in legacy Forge records
   (`consumeRetry` fingerprinting bounds duplicate agent retries, a different
   problem, not adversarial replay). Added a nullable-fields `replayDefense`
   object (`nonce`, `sequence`, `freshnessWindowSeconds`, `freshAt`) as
   greenfield scaffolding — S03 (per the S00 report) is not adapting an
   existing mechanism here, it is designing one, and this freeze only
   reserves the slot.
3. **`operation-envelope-v1`'s `OperationRequest.authorityAssertion`** — S00
   found the one genuine legacy trust primitive (`lib/host.js`'s
   process-identity/code-signing check) authenticates a *connection* once at
   MCP startup, never a message. Added a required `authorityAssertion`
   object (`assertedBy`, `perMessage: boolean`, `verificationMethod`) to
   every operation request so a caller must say explicitly whether this
   specific message's authority claim was re-verified (`perMessage: true`)
   or merely inherited from connection-level trust (`false`) — the gap is
   now visible on every request rather than silently inherited.
4. **`legacy-envelope-v1` bound to the S00 inventory by reference** —
   `legacyKind`'s description now points at
   `legacy-semantic-inventory.json`'s `record_types` list (11 entries,
   including `orthic.tool-receipt.v1` and `orthic.observable-event.v1`) by
   name rather than re-modeling any of their field lists here.
   `provenance.legacyInventoryRef` (default:
   `docs/plans/legion/s00-baseline/legacy-semantic-inventory.json`) and
   `provenance.legacyInventoryRecordType` were added as the binding
   mechanism. `provenance.authenticated` is now `const: false` — structurally
   impossible to set otherwise — directly encoding S00 finding 1 (no legacy
   receipt is ever authenticated in the sense `effect-receipt-v1`/
   `evidence-capability-receipt-v1` now require).

None of these four additions re-model any Forge/legacy record shape; per the
task brief and S00's own report ("no canonical target mapping was produced...
mark mapping as deferred to S01"), that mapping work stays out of this
freeze. `AUTHENTICATION_METHOD` is a new judgment-call enum (effectively
J-12) invented to express the S00 findings — no source document defines it;
it exists only because the coordinator's mid-task instruction required a
field to hold it.

## 5. Notable fields added beyond the source documents (non-exhaustive; the
   judgment calls above cover the largest ones)

- `execution-contract-v1.dependencies[].reason` + `.resourceKey` — §32a
  requires every serial edge to name its dependency/shared-resource/ordering
  reason; no source document gives a field shape for that requirement, so one
  was invented (`reason` enum, optional `resourceKey` for the
  shared-mutable-resource case).
- `execution-task-v1.kernelTaskId` — bridges the ExecutionTask/Kernel-task
  naming collision; see OPEN QUESTIONS below.
- `effect-receipt-v1.match` (boolean) and `.result` (enum) — convenience
  fields summarizing the requested/authorized/observed reconciliation; the
  three-way comparison itself is explicit in source docs, the boolean
  summary field is not.
- `covenant-record-v1.seatRecords[].reusedModel`, `.integrity.mutationDetected`
  — direct encodings of C14 and C7 as checkable booleans rather than leaving
  them as prose invariants.
- `artifact-v1.sensitivity` / `.retention` / `.redaction` — archive §9.2
  requires these exist "on every artifact" but does not give field shapes;
  shapes here mirror `schemas/execution-receipt-v1.schema.json`'s existing
  `redaction` convention.

## OPEN QUESTIONS FOR REVIEWER

1. **`INVOCATION_STATE` and `CLAIM_BOUNDARY` enum values (J-7) are invented,
   not sourced.** The WP2 brief requires the three-field shape; it does not
   supply these two enums' actual values. If Kernel/Arcane implementation
   (Workstream D/E) already has or needs different literal values, this
   freeze's values should be treated as a placeholder proposal, not a sealed
   vocabulary, until confirmed.
2. **ExecutionTask (`T-#.#`) vs. the Kernel's durable lifecycle `task`
   object are never explicitly unified or distinguished in ARCHITECTURE.md or
   the archive**, despite both being called "task." This freeze treats them
   as two related-but-distinct identifiers bridged by
   `execution-task-v1.kernelTaskId`. Needs a decision from whoever owns
   Workstream D/G: are these the same object with two id formats, or
   genuinely two different objects (Sage-owned decision-state task vs.
   Kernel-owned lifecycle task) that happen to share an English name?
3. **`RA-#`/`E-#`/`P-#`/`AR-#` (J-2) are documented but not bound.** Confirm
   whether any of the five downstream build lanes need these promoted to
   first-class ids before they start building on this freeze, or whether my
   read (they collapse into existing objects) is correct.
4. **`EFFECT_CLASS` (J-8) and `MODEL_TIER` (J-9) are synthesized nomenclature
   normalizations, not verbatim source vocabulary.** Workstream E (Arcane)
   and the orchestrator's actual cost-routing implementation are the real
   owners of these lists; this freeze's versions should be reconciled against
   (or explicitly superseded by) whatever those workstreams land on, not
   treated as independently authoritative.
5. **`legacy-envelope-v1.provisionalMappingRef` stays null/provisional by
   design** (per both the WP2 brief and S00's own report, which explicitly
   deferred mapping to S01). Confirm this is still the intended sequencing
   now that S00 is complete — i.e., that WP2 should *not* attempt the mapping
   even though S00's inventory is now available, and that S01 remains the
   right owner.
6. **`AUTHENTICATION_METHOD`'s three values
   (`host-connection-trust | capability-signature | unauthenticated`) are a
   judgment call made under time pressure mid-freeze**, not reviewed against
   whatever S03 (the workstream S00's report says "must design real
   authentication from scratch") ultimately specifies. Treat as a reserved
   slot, not a sealed contract, until S03 exists.
