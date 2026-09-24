//! Port of `src/lib/research-core/{__init__,active_run,citecheck,contradictions,control}.py`
//! (packet wf023, area `src/lib/research-core`, target crate `legion-research`).
//!
//! `__init__.py` is empty (a package marker) — nothing to port.
//!
//! Status and rationale per file are in the packet report at
//! `scratchpad/loss/wf/wf023.md`. In short:
//! - `citecheck.rs`, `contradictions.rs`: full faithful ports, pure
//!   functions, no external dependencies.
//! - `shards.rs`: not one of this chunk's five files, but ported here
//!   because `control.py` depends on it and no canonical `shards.py` port
//!   exists elsewhere in this crate yet (checked via `git grep` at port
//!   time). Delete and rewire if/when one lands.
//! - `active_run.rs`, `control.rs`: faithful ports of the decision logic,
//!   injected against `RunManifest`/`ControlManifest` traits instead of a
//!   concrete `manifest.py` port, which does not exist yet under
//!   `legion-research` (also checked via `git grep`). `control.rs`'s
//!   adaptive-stopping decision itself delegates to the already-ported,
//!   already-verified `crate::research_port::stopping::decide`.

pub mod active_run;
pub mod citecheck;
pub mod contradictions;
pub mod control;
pub mod shards;

pub use active_run::{
    activate, clear, current, executable_runs, run_cli as active_run_cli, selection, PointerValue,
    RunManifest, RunRecord, Selection,
};
pub use citecheck::{check as citecheck_check, CitePair, CiteCheckResult, SentenceRow};
pub use contradictions::{derive as contradictions_derive, Consensus, Contradiction, DeriveResult};
pub use control::{
    checkpoint_shard, decide_stop, init_shards, resume_shards, run_cli as control_run_cli,
    ControlManifest, DecideStopRequest,
};
pub use shards::{
    checkpoint as shard_checkpoint, merge_jsonl, plan as shard_plan, resumable as shard_resumable,
    shard_id, MergeReceipt, ShardPlan, ShardRow, WorkItem, VALID_STATES,
};
