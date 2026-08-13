# Legion Shared-Contract ID Grammar (WP2 freeze)

Canonical naming per `docs/plans/legion/00-CANON.md`: Sage, Alchemist, Oracle, Arcane,
Covenant, Legion, Kernel. Never use superseded identities.

This file is the single source of truth for ID *shape*. Schemas reference these
patterns; they do not redefine them. Two families exist:

- **Sequence IDs** — short, human-facing, durable-engineering-object identifiers
  drawn directly from ARCHITECTURE.md §33 and COVENANT.md. These are stable
  across a run and are the IDs used in cross-references (`T-4.2 implements D-17`).
- **Opaque runtime handles** — Kernel-issued identifiers for durable task/run
  lifecycle objects (IMPLEMENTATION-PLAN §9). ARCHITECTURE/COVENANT never give
  these a literal grammar; the ULID-based form below is a judgment call
  (FREEZE.md J-10), chosen for monotonic sortability and no coordination
  requirement, consistent with IMPLEMENTATION-PLAN §9.2's "opaque handles
  where model-visible path not required."

## Sequence IDs (ARCHITECTURE §33)

| Object | Prefix | Regex | Example | Source |
|---|---|---|---|---|
| Requirement | `R-` | `^R-\d+$` | `R-2` | ARCHITECTURE §33 |
| Decision | `D-` | `^D-\d+$` | `D-17` | ARCHITECTURE §33 |
| Invariant | `I-` | `^I-\d+$` | `I-4` | ARCHITECTURE §33 |
| Non-goal | `NG-` | `^NG-\d+$` | `NG-1` | ARCHITECTURE §5.2 (illustrative only — not in the §33 canonical list; judgment call J-1, see FREEZE.md) |
| AcceptanceCriterion | `AC-` | `^AC-\d+$` | `AC-8` | ARCHITECTURE §33 |
| ExecutionContract | `EC-` | `^EC-\d+$` | `EC-4`, `EC-44` | ARCHITECTURE §33, §15 |
| ExecutionTask | `T-` | `^T-\d+(\.\d+)*$` | `T-4.2`, `T-3` | ARCHITECTURE §33, §15 (both `T-3` and `T-4.2` forms appear in source text; regex accepts both) |
| Finding (Covenant/Oracle) | `F-` | `^F-\d+$` | `F-31`, `F-12` | ARCHITECTURE §33, §22 |
| Blocker | `B-` | `^B-\d+$` | `B-5`, `B-12` | ARCHITECTURE §33, §15 |
| Amendment | `A-` | `^A-\d+$` | `A-2` | ARCHITECTURE §33, §15 |
| CovenantRequest / CovenantRecord | `CV-` | `^CV-\d+$` | `CV-7`, `CV-9` | ARCHITECTURE §33, §19 |

### Illustrative-only IDs (not in the §33 canonical list)

ARCHITECTURE §22's evidence-chain diagram uses three additional short IDs that
never recur elsewhere in either source document. They are **not** required by
the WP2 task list and **no schema in this freeze binds to them** — they are
recorded here only so a future author does not accidentally collide with them.
Flagged as judgment call J-2 (see FREEZE.md); reviewer should confirm whether
any of these need to become first-class before other lanes build on them.

| ID | Meaning (§22) | Prefix collision risk |
|---|---|---|
| `RA-12` | remediation artifact | none reserved |
| `E-88` | Alchemist actual-effect receipt | none reserved |
| `P-92` | tests/proof evidence | none reserved |
| `AR-12` | fresh Oracle re-audit record | none reserved |

## Opaque runtime handles (judgment call J-10)

Kernel-issued, ULID-suffixed (Crockford base32, 26 chars, monotonic-ish by time).

| Handle | Regex | Example |
|---|---|---|
| `run_id` | `^run_[0-9A-HJKMNP-TV-Z]{26}$` | `run_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| `request_id` (generic operation/effect/covenant request) | `^req_[0-9A-HJKMNP-TV-Z]{26}$` | `req_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| `task_id` (Kernel lifecycle task, distinct from ExecutionTask `T-#.#` — see FREEZE.md open question) | `^ktask_[0-9A-HJKMNP-TV-Z]{26}$` | `ktask_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| Artifact content handle | `^art_[0-9A-HJKMNP-TV-Z]{26}$` | `art_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| Effect receipt | `^eff_[0-9A-HJKMNP-TV-Z]{26}$` | `eff_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| Evidence-capability receipt | `^ev_[0-9A-HJKMNP-TV-Z]{26}$` | `ev_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| Claim | `^clm_[0-9A-HJKMNP-TV-Z]{26}$` | `clm_01J8Z3K9QG7X6M2N4P5R8S0T1V` |
| Worker capsule | `^wc_[0-9A-HJKMNP-TV-Z]{26}$` | `wc_01J8Z3K9QG7X6M2N4P5R8S0T1V` |

Content digests (artifact `digest`, packet `packet_digest` / `packetDigest`,
source revision hashes) use the existing repo-wide convention seen in
`schemas/core/artifact-record-v1.schema.json` and
`schemas/execution-receipt-v1.schema.json`:

```
^sha256:[0-9a-f]{64}$
```

## Open question for reviewer

`ExecutionTask` (`T-#.#`, a Sage/Execution-Compile object per §33) and the
Kernel's durable lifecycle `task` (IMPLEMENTATION-PLAN §9.1/Workstream D,
`task.start`/`task.status`/...) are named identically ("task") in the two
source documents but are not explicitly unified or explicitly distinguished
anywhere in ARCHITECTURE.md or the archive. This freeze treats them as two
related-but-distinct identifiers (`T-#.#` vs `ktask_<ulid>`) with a
`kernelTaskId` cross-reference field on `execution-task-v1`. See
FREEZE.md → OPEN QUESTIONS FOR REVIEWER.
