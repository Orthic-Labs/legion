#![forbid(unsafe_code)]

pub mod error;
pub mod evaluator;
pub mod explanation;
pub mod precedence;

pub use error::PolicyEvaluationError;
pub use evaluator::{
    decide, evaluate, evaluate_decision, PolicyEvaluation, PolicyEvaluator, PolicyReceipt,
};
pub use explanation::{Explanation, TraceEntry};
pub use legion_policy_model::{PolicyContext, PolicyPack, PolicyRule};
pub use precedence::EvaluationStage;
