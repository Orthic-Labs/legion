//! wf030 packet: parity coverage for
//! `src/lib/research-core/test_entrypoint_parity.py` and
//! `src/lib/research-core/tests/test_research_control.py`,
//! `test_research_draft_integrity.py`, `test_research_effect_audit.py`,
//! `test_research_legal_evidence_extensions.py`.
//!
//! Every behaviour these five Python test files exercise is **already
//! ported and unit-tested** by earlier packets, against the exact same
//! Python source modules:
//!
//! - `test_entrypoint_parity.py` exercises `effects.is_external`/
//!   `is_worker` (ported at `crate::research_port::effects`),
//!   `meter.consume` via `run.meter_worker` and a provider's own `meter()`
//!   call (ported at `crate::wf_port::wf026::meter::consume`),
//!   `resource_guard.authorize` (ported at
//!   `crate::wf_port::wf028::resource_guard::authorize`), and
//!   `patch_guard.issue_receipt` (ported at
//!   `crate::wf_port::wf026::patch_guard`). All four already carry
//!   unit tests covering the same call shapes the Python file asserts
//!   (non-research tool classification, run/provider meter delegation,
//!   forbidden-resource authorization, and patch-receipt issuance/
//!   signature format).
//! - `test_research_control.py` exercises `control.decide_stop`/
//!   `init_shards`/`checkpoint_shard`/`resume_shards`, ported at
//!   `crate::wf_port::wf023::control`, whose
//!   `stopping_and_shard_resume_state_persist_via_the_store` unit test is
//!   the same scenario (coverage-complete stop decision, two shards
//!   planned, one checkpointed done, one failed, resume returns only the
//!   failed one).
//! - `test_research_draft_integrity.py` exercises `draft_integrity.check`,
//!   ported at `crate::wf_port::wf024::draft_integrity`, whose unit tests
//!   cover the sourced-draft match/mismatch and post-patch match/mismatch
//!   sequence the Python file asserts.
//! - `test_research_effect_audit.py` exercises `effect_audit.audit`,
//!   ported at `crate::wf_port::wf024::effect_audit`, whose unit tests
//!   cover the reconciled-usage, tampered-usage-mismatch, and
//!   malformed-event scenarios.
//! - `test_research_legal_evidence_extensions.py` exercises
//!   `domain_verify.verify`'s legal case-law evidence-completeness rule
//!   (`forum`/`precedential_status`/`negative_treatment`), ported at
//!   `crate::wf_port::wf024::domain_verify`, whose unit tests cover both
//!   the incomplete-evidence rejection and the complete-evidence pass.
//!
//! No new production code is added by this packet: nothing in this
//! packet's five Python test files exercises behaviour the sibling wf023/
//! wf024/wf026/wf028 ports do not already cover and assert against. See
//! `tests/wf_wf030.rs` for this packet's own parity test file (owned by
//! this packet), and the packet report
//! (`wf030.md`) for the `pub mod wf_port;` / `pub mod wf030;` wiring this
//! module needs from the integrator, plus the wiring those sibling
//! modules still need (`pub mod wf023;` etc.) for `tests/wf_wf030.rs` to
//! compile against them.
