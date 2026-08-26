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
    EvidenceAuthority, EvidenceExtraction, EvidenceSpec, EvidenceTier, MatchMode,
    NativePackManifest, RuleClass, RuleKind, RuleSpec, Severity,
};
pub use structural::{
    evaluate as evaluate_structural, evaluate_optional as evaluate_structural_optional,
    execute_selector, BlueprintSource, StructuralEvaluation, StructuralEvidence,
};
