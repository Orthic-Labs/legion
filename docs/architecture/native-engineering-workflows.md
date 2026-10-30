# Native engineering workflow integration

This operational map consumes the canonical SSOT; it creates no new authority or effect model.
Legion orchestrates, producing capabilities own routine acceptance meaning, Oracle provides
independent read-only assurance, Council provides optional advisory challenge, and Guard gates
typed effects. No workflow mode or diagnostic verdict grants authority.

## Native surfaces

| Surface | Native owner | Result and limit |
|---|---|---|
| `legion work-plan validate --input <json>` | `legion-runtime::workplan` | Validates bounded units, scope exclusivity, dependency DAG, predicates and evidence declarations. Returns ready units; does not dispatch, run tests or verify artifact bytes. |
| `legion review-loop assess --input <json>` | `legion-review::rounds` | Folds stable findings across bounded full/delta review rounds and exact artifact/base bindings. Imported assertions do not authenticate a reviewer or replace Oracle. |
| `legion delivery assess --input <json>` | `legion-runtime::delivery` | Pure readiness assessment of one imported PR snapshot and verification/review proofs. No I/O, watching or merge action. |
| `legion delivery observe --repository owner/name --pr N` | `legion` CLI GitHub observer | One bounded read-only collection through the existing SDK/credential boundary, with revision/policy binding and explicit completeness. No daemon or mutation. |
| `legion quality summarize --input <json> --report <raw-report>` | `legion-audit::quality_observation` | Hashes original report bytes, interprets normalized imported observations and preserves unavailable/partial outcomes. No tool execution or repository-quality verdict. |

Commands emit versioned provenance/digest envelopes with `effectAuthority: none`: imported inputs
carry `inputDigest`, while live observation uses `observationDigest` and optional `proofInputDigest`.
Hashes establish byte identity, not truth. Imported proof records remain assertions even when included beside a
native authenticated transport observation. A successful diagnostic exit code is never admission
for a push, merge or credential read. ADAPT can consume envelopes without linking Legion internals;
this change does not install an ADAPT adapter or claim an earlier design is current implementation.

## Workflow composition

Dispatch loads `skills/dispatch/references/work-plan.md` when executable ownership/dependency
declarations are useful. It remains assignment transport: Legion selects capabilities/roles and
the integration owner retains HEAD, index, receipts, checks and pushes. Native readiness does not
launch workers; real capacity and Guard admission still govern execution. Read-only units declare
read-only access rather than invented write ownership. Source declarations do not resolve symlinks
or replace host filesystem containment.

Commit remains the owner of one frozen diff through verified push, including its existing four
external requests and smaller repair/recheck limit. Its optional native review ledger preserves
finding identity, evidence and exact artifact/base lineage. Resolved findings require independent
evidence; omitted findings remain open. Outcome/safety findings block completion; advisory residue
does not acquire new blocking authority. Review-budget exhaustion returns a blocker and resume
action. Council remains its existing separate optional bounded challenge.

Delivery composes the broader requested outcome above Commit. The terminal choices are branch
pushed, PR ready for the user, and merged when explicitly authorized. For handoff, inspect existing
auto-merge and queue state **before push**, since satisfying existing automation can merge without
a later merge command. A ready handoff requires both disabled auto-merge and no queue entry.
Authorized host mutation is separate from observation; if it is unavailable, report the exact
unperformed action. Merge requires current explicit authorization, a final revision/policy check,
the existing Guard-gated host action, and fresh readback of merged state and merge commit.

Observer defaults are five pages per collection, a 120-second total deadline and 900-second
maximum evidence age. Missing credentials, permissions, unknown or unsupported policy, incomplete
pages, stale/mismatching proofs, required checks/reviews/threads and head/base changes prevent
readiness. Credentials go only to `api.github.com` through the existing provider boundary.
Trusted-host credential injection is not itself a Guard receipt. There is no token discovery,
interactive login, polling, watcher, queue manager or native merge executor.

Wake resumes only on host events or one bounded authorized inspection. In the absence of an
external event source, report pending conditions and a concrete resume action. A chat heartbeat or
sleep loop cannot stand in for the missing source. Neither "full-send" nor "full-stop" alone
defines effect scope, new permissions or an authorized terminal state.

Modernize means reconstructing original intent against the current base and verifying adapted
behavior; textual rebase success alone does not prove it. Takeover recovers intent and contribution
history, transfers the integration owner explicitly and preserves original authorship/attribution.
Neither mode implicitly authorizes history rewrite, merge, erased attribution or expanded scope.

QA retains provider identity/version, source/report digests, scoped paths, execution state and
completeness. Coverage is a measured numerator/denominator or unavailable. Duplication is an
investigation candidate. Mutation assertion detection excludes invalid compilation, timeout,
infrastructure, not-run and unclassified upstream kills; a failed baseline cannot demonstrate
effectiveness. Thresholds apply only to exactly matching scope. Cached observations require all
source/test/fixture/toolchain/dependency/command/config/environment identities to match and remain
imported evidence. No score substitutes for actual project-native behavior checks or assurance.

## Evidence and provenance

Checked-in native examples include `engine/crates/legion-runtime/tests/workplan-ready.json`,
`engine/crates/legion-runtime/tests/delivery-ready.json`,
`engine/crates/legion-review/tests/rounds-approved.json`, and the paired normalized/raw report under
`engine/crates/legion-audit/tests/fixtures/quality-observation/`. These are fixtures, not execution
receipts. Skill evals are structural/model-grading specifications; structural validity alone is
not evidence of model behavior. Actual verification belongs to the repository's admitted CI and
requested host/platform surface.

Pinned idea sources and licensing observations are in `docs/THIRD_PARTY_NOTICES.md`. This is an
original Rust implementation and original Legion prose, with no imported upstream persona,
prompt, plugin metadata, code, scripts or assets.
