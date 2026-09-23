//! wf_port chunk w2_004 (area `skills/covenant/lib`, target crate `legion-runtime`).
//!
//! Source file assigned to this chunk: `skills/covenant/lib/flows.mjs`.
//!
//! Coverage status: ALREADY-NATIVE-VERIFIED, ported under a different module path.
//!
//! `flows.mjs` was already ported by the P9-skill-scripts packet at
//! `legion_runtime::p9_skills::covenant` (see `../../p9_skills/covenant.rs` and its module-level
//! doc comment, and `../../p9_skills/mod.rs`'s packet doc comment). That port is deliberately
//! partial and says so explicitly: the pure, deterministic pieces of `flows.mjs` that do not
//! require provider I/O are ported —
//!
//! - `CONTRACT_BOUNDARIES` (the frozen list of contract-boundary field names used by
//!   `executeBlockerConsult`'s `missingChecks`/`invalidChecks`/`contractSafety` computation) →
//!   `p9_skills::covenant::CONTRACT_BOUNDARIES`.
//! - `aggregateDecisionVerdict` (the fresh-verdict seat-position aggregation used by
//!   `executeDecisionChallenge`) → `p9_skills::covenant::aggregate_decision_verdict`.
//!
//! `runSeats`, `executeDecisionChallenge`, `executeBlockerConsult`, and `executePacketOnly`
//! themselves are NOT ported natively, and this is a deliberate, documented scope decision rather
//! than a gap:
//!
//! - `runSeats` fans a caller-supplied async `runner(seat, packet, stage)` callback out to
//!   independent LLM seat providers (one JS `Promise` chain per `concurrencyKey`, i.e. a
//!   provider-affinity queue), clones/freezes the packet per seat, detects seat-side subject
//!   mutation by comparing `digestValue` before/after, and collects `{seatRecords, findings,
//!   providerMetadata}`. The seat providers are the actual reviewers (separate LLM calls); there
//!   is no deterministic algorithm here to port into Rust — Rust would need to originate its own
//!   provider I/O and callback contract, which is a product decision, not a mechanical port.
//! - `executeDecisionChallenge` / `executeBlockerConsult` / `executePacketOnly` are orchestration
//!   wrappers around `runSeats` plus caller-supplied `synthesize`/`callerDisposition` callbacks
//!   (also provider I/O — a synthesis LLM call) and `contracts.mjs`'s `createCovenantRecord`
//!   (already ported: see `legion_policy::wf_port::wf068::validate` and the copied schema JSON
//!   under `legion-policy/src/wf_port/wf068/schemas_contracts/`). With the provider-IO core
//!   unported, porting the wrapper functions verbatim would just be dead orchestration code with
//!   no runner to call.
//!
//! No new Rust source is added by this module beyond this documentation; the production
//! deterministic logic lives at `p9_skills::covenant` and MUST NOT be duplicated here (see
//! `docs/agent-rules.md`'s "keep one detokenization entry point" style invariant generalized to
//! "don't create a second implementation of the same ported behaviour"). The tests in
//! `tests/wf_w2_004.rs` assert against that production entry point directly.
//!
//! Gap carried forward in the report (`w2_004.md`): if/when the provider-IO orchestration is
//! ported, it belongs in `p9_skills::covenant` (or a sibling module there) as an extension of the
//! existing documented port, not as a second implementation under this `wf_port::w2_004` path.
