#![forbid(unsafe_code)]

pub mod compiler;
pub mod error;
pub mod evidence;
pub mod lexical;
pub mod schema;
pub mod structural;

pub use compiler::{CompiledRules, RuleCompiler};
pub use error::{Result, RuleError};
pub use evidence::{EvidenceSpan, RuleCoverage};
pub use lexical::{LexicalEngine, LexicalEvaluation, SourceFile};
pub use schema::{
    AnalysisRulePack, BlueprintOperation, BlueprintResult, BlueprintSelector, Confidence,
    EvidenceTier, MatchMode, RuleClass, RuleKind, RuleSpec, Severity,
};
pub use structural::{
    evaluate as evaluate_structural, execute_selector, BlueprintSource, StructuralEvaluation,
    StructuralEvidence,
};
