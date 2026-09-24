//! Port of `src/packages/kernel/index.mjs`.
//!
//! The JS file is mostly a barrel of re-exports from `./lib/*.mjs`; every
//! re-exported symbol (`assertContract`/`bindRunIdentity`, `EXIT_CODES`/
//! `KernelError`, the `ID_PREFIXES` family, `JsonlJournal`,
//! `TaskLifecycle`, the model-profile helpers, `negotiateCapabilities`/
//! `OperationRegistry`, `LaneScheduler`/`schedulerOptionsFromArgv`, and
//! `ArtifactStore`/`digestContent`/`EventStore`) already has a Rust owner
//! under `p5_core` (see that module's per-file port table). The one piece
//! of standalone content in the barrel file itself is the
//! `KERNEL_TASK_ID_BRIDGE_DECISION` constant, ported here.

use serde_json::{json, Value};

/// Port of `export const KERNEL_TASK_ID_BRIDGE_DECISION`.
pub fn kernel_task_id_bridge_decision() -> Value {
    json!({
        "decision": "keep-bridge",
        "executionTaskId": "T-#.#",
        "kernelTaskId": "ktask_<ulid>",
        "field": "kernelTaskId",
        "rationale": "ExecutionTask identity is human-facing contract state; Kernel task identity is an opaque durable runtime handle.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_js_literal_shape() {
        let decision = kernel_task_id_bridge_decision();
        assert_eq!(decision["decision"], json!("keep-bridge"));
        assert_eq!(decision["executionTaskId"], json!("T-#.#"));
        assert_eq!(decision["kernelTaskId"], json!("ktask_<ulid>"));
        assert_eq!(decision["field"], json!("kernelTaskId"));
        assert!(decision["rationale"].as_str().unwrap().contains("opaque durable runtime handle"));
    }
}
