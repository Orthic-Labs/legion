//! Ported from src/packages/kernel/lib/scheduler.mjs (packet P5d).
//!
//! JS runs ready lanes concurrently via `Promise.all` (serialized per
//! `concurrencyKey` with a lock, or fully serial with `--serial`). This port
//! keeps the same dependency-driven wave scheduling and the same
//! `--serial` behaviour (one node per wave), but executes each wave's nodes
//! one at a time in Rust — there is no `async`/thread-pool concurrency here,
//! only the ordering guarantees the JS scheduler contract cares about
//! (dependencies satisfied before a node runs, cycles rejected, duplicate
//! lane ids rejected).

use std::collections::{BTreeMap, HashMap, HashSet};

use legion_catalog::json::Value;

use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};

fn usage_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("usage".to_string()),
            ..Default::default()
        },
    )
}

/// Port of `schedulerOptionsFromArgv(argv)`.
pub fn scheduler_options_from_argv(argv: &[String]) -> bool {
    argv.iter().any(|a| a == "--serial")
}

/// Context handed to each lane's `run` closure, mirroring `{ results, nodeId }`.
pub struct LaneContext<'a> {
    pub results: &'a BTreeMap<String, Value>,
    pub node_id: &'a str,
}

/// Lane body: runs one node against the results produced so far.
pub type LaneRun = dyn Fn(&LaneContext) -> Result<Value, KernelError>;

pub struct LaneNode {
    pub id: String,
    pub dependencies: Vec<String>,
    pub concurrency_key: Option<String>,
    pub run: Box<LaneRun>,
}

/// Port of `class LaneScheduler`.
pub struct LaneScheduler {
    pub serial: bool,
}

impl LaneScheduler {
    pub fn new(serial: bool) -> Self {
        LaneScheduler { serial }
    }

    /// Port of `execute(nodes)`.
    #[allow(clippy::result_large_err)]
    pub fn execute(&self, nodes: Vec<LaneNode>) -> Result<BTreeMap<String, Value>, KernelError> {
        let order: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let mut by_id: HashMap<String, LaneNode> = HashMap::new();
        for node in nodes {
            if by_id.contains_key(&node.id) {
                return Err(KernelError::new(
                    "SCOPE_CONFLICT",
                    format!("duplicate lane id: {}", node.id),
                    KernelErrorOptions {
                        category: Some("conflict".to_string()),
                        ..Default::default()
                    },
                ));
            }
            by_id.insert(node.id.clone(), node);
        }
        for node in by_id.values() {
            for dependency in &node.dependencies {
                if !by_id.contains_key(dependency) {
                    return Err(usage_error(format!(
                        "unknown dependency {dependency} for {}",
                        node.id
                    )));
                }
            }
        }

        let mut pending: HashSet<String> = by_id.keys().cloned().collect();
        let mut results: BTreeMap<String, Value> = BTreeMap::new();

        while !pending.is_empty() {
            let mut ready: Vec<String> = pending
                .iter()
                .filter(|id| {
                    by_id[*id]
                        .dependencies
                        .iter()
                        .all(|d| results.contains_key(d))
                })
                .cloned()
                .collect();
            ready.sort();
            if ready.is_empty() {
                return Err(KernelError::new(
                    "PLAN_BINDING_DRIFT",
                    "dependency graph contains a cycle",
                    KernelErrorOptions {
                        category: Some("precondition".to_string()),
                        ..Default::default()
                    },
                ));
            }
            let batch: Vec<String> = if self.serial {
                vec![ready[0].clone()]
            } else {
                ready
            };
            for id in batch {
                let node = &by_id[&id];
                let context = LaneContext {
                    results: &results,
                    node_id: &id,
                };
                let value = (node.run)(&context)?;
                results.insert(id.clone(), value);
                pending.remove(&id);
            }
        }

        Ok(order
            .into_iter()
            .map(|id| (id.clone(), results.remove(&id).unwrap_or(Value::Null)))
            .collect())
    }
}
