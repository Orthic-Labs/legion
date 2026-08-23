use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{Result, RuleError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisRulePack {
    pub schema_version: u32,
    pub kind: String,
    pub pack_id: String,
    pub version: String,
    pub class: RuleClass,
    #[serde(default = "default_engine_contract")]
    pub engine_contract: String,
    pub rules: Vec<RuleSpec>,
    #[serde(default)]
    pub source_provenance: BTreeMap<String, String>,
}

impl AnalysisRulePack {
    pub fn canonical_digest(&self) -> Result<String> {
        legion_contracts::canonical_digest(self)
            .map_err(|error| RuleError::InvalidPack(error.to_string()))
    }
}

fn default_engine_contract() -> String {
    "rust-regex-1".into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleClass {
    A,
    B,
    C,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub stable_id: String,
    pub kind: RuleKind,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default)]
    pub data_class: Option<String>,
    #[serde(default)]
    pub lifecycle: Option<String>,
    #[serde(default)]
    pub paths: Vec<PathSelector>,
    #[serde(default)]
    pub matcher: Option<MatcherSpec>,
    #[serde(default)]
    pub companions: CompanionSpec,
    #[serde(default)]
    pub evidence: EvidenceSpec,
    #[serde(default)]
    pub uncertainty: Vec<String>,
    #[serde(default)]
    pub coverage: CoverageSpec,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub selector: Option<BlueprintSelector>,
    #[serde(default)]
    pub implementation_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Lexical,
    Structural,
    Algorithmic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Note,
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathSelector {
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub suffix: Option<String>,
    #[serde(default)]
    pub exact: Option<String>,
}

impl PathSelector {
    pub fn matches(&self, path: &str) -> bool {
        self.prefix
            .as_ref()
            .map(|v| path.starts_with(v))
            .unwrap_or(true)
            && self
                .suffix
                .as_ref()
                .map(|v| path.ends_with(v))
                .unwrap_or(true)
            && self.exact.as_ref().map(|v| path == v).unwrap_or(true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatcherSpec {
    pub mode: MatchMode,
    pub pattern: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    Regex,
    Literal,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionSpec {
    #[serde(default)]
    pub required: Vec<MatcherSpec>,
    #[serde(default)]
    pub negative: Vec<MatcherSpec>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSpec {
    #[serde(default)]
    pub extract: EvidenceExtraction,
    #[serde(default)]
    pub authority: EvidenceAuthority,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceExtraction {
    #[default]
    Span,
    Line,
    Match,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceAuthority {
    #[default]
    Lexical,
    Structural,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageSpec {
    #[serde(default)]
    pub denominator: Option<String>,
    #[serde(default)]
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlueprintSelector {
    pub schema_version: u32,
    pub selector_id: String,
    pub operation: BlueprintOperation,
    #[serde(default)]
    pub repository_id: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    pub expected_evidence_tier: EvidenceTier,
    #[serde(default)]
    pub expected_generation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlueprintOperation {
    Files,
    Symbols,
    References,
    Dependencies,
    Dependents,
    Neighbors,
    Path,
    Impact,
    Flows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceTier {
    Inventory,
    Structural,
    Semantic,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlueprintMatch {
    pub id: String,
    pub path: Option<String>,
    pub symbol: Option<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlueprintResult {
    pub generation: String,
    pub evidence_tier: EvidenceTier,
    pub matches: Vec<BlueprintMatch>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub gaps: Vec<String>,
}
