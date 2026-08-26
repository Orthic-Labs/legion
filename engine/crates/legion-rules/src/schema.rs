use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{Result, RuleError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativePackManifest {
    pub schema_version: u32,
    pub kind: String,
    pub repository: String,
    pub packet_id: String,
    pub baseline_commit: String,
    pub engine_contract: String,
    pub class_a: usize,
    pub class_b: usize,
    pub class_c_excluded: usize,
    pub rule_count: usize,
    pub packs: Vec<AnalysisRulePack>,
}

impl NativePackManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(RuleError::InvalidPack(format!(
                "unsupported native pack manifest schema version {}",
                self.schema_version
            )));
        }
        if self.kind != "legion-native-pack-manifest" {
            return Err(RuleError::InvalidPack(
                "kind must be legion-native-pack-manifest".into(),
            ));
        }
        for (field, value) in [
            ("repository", self.repository.as_str()),
            ("packetId", self.packet_id.as_str()),
            ("baselineCommit", self.baseline_commit.as_str()),
            ("engineContract", self.engine_contract.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if self.engine_contract != "rust-regex-1" {
            return Err(RuleError::InvalidPack(
                "unsupported regex engine contract".into(),
            ));
        }
        if self.packs.is_empty() {
            return Err(RuleError::InvalidPack(
                "native pack manifest must contain at least one pack".into(),
            ));
        }
        let mut pack_ids = std::collections::BTreeSet::new();
        let mut class_a = 0;
        let mut class_b = 0;
        let mut rule_count = 0;
        for pack in &self.packs {
            if pack.engine_contract != self.engine_contract {
                return Err(RuleError::InvalidPack(format!(
                    "pack {} uses a different engine contract",
                    pack.pack_id
                )));
            }
            pack.validate()?;
            if !pack_ids.insert(pack.pack_id.as_str()) {
                return Err(RuleError::InvalidPack(format!(
                    "duplicate native pack id: {}",
                    pack.pack_id
                )));
            }
            match pack.class {
                RuleClass::A => class_a += 1,
                RuleClass::B => class_b += 1,
                RuleClass::C => {
                    return Err(RuleError::UnsupportedClass(
                        "C (Rust provider required)".into(),
                    ))
                }
            }
            rule_count += pack.rules.len();
        }
        if class_a != self.class_a || class_b != self.class_b || rule_count != self.rule_count {
            return Err(RuleError::InvalidPack(
                "native pack manifest counts do not reconcile".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisRulePack {
    pub schema_version: u32,
    pub kind: String,
    pub pack_id: String,
    pub version: String,
    pub class: RuleClass,
    pub engine_contract: String,
    pub rules: Vec<RuleSpec>,
    #[serde(default)]
    pub source_provenance: BTreeMap<String, String>,
}

impl AnalysisRulePack {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(RuleError::InvalidPack(format!(
                "unsupported rule pack schema version {}",
                self.schema_version
            )));
        }
        if self.kind != "analysis-rule-pack" {
            return Err(RuleError::InvalidPack(
                "kind must be analysis-rule-pack".into(),
            ));
        }
        validate_identifier("packId", &self.pack_id)?;
        validate_identifier("version", &self.version)?;
        if self.engine_contract != "rust-regex-1" {
            return Err(RuleError::InvalidPack(
                "unsupported regex engine contract".into(),
            ));
        }
        if self.rules.is_empty() {
            return Err(RuleError::InvalidPack("rules must not be empty".into()));
        }
        if self
            .source_provenance
            .iter()
            .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
        {
            return Err(RuleError::InvalidPack(
                "source provenance keys and values must be non-empty".into(),
            ));
        }

        let mut ids = std::collections::BTreeSet::new();
        let mut stable_ids = std::collections::BTreeSet::new();
        for rule in &self.rules {
            rule.validate(self.class)?;
            if !ids.insert(rule.id.as_str()) {
                return Err(RuleError::DuplicateRule(rule.id.clone()));
            }
            if !stable_ids.insert(rule.stable_id.as_str()) {
                return Err(RuleError::InvalidPack(format!(
                    "duplicate stable rule id: {}",
                    rule.stable_id
                )));
            }
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String> {
        self.validate()?;
        legion_contracts::canonical_digest(self)
            .map_err(|error| RuleError::InvalidPack(error.to_string()))
    }
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

impl RuleSpec {
    pub fn validate(&self, class: RuleClass) -> Result<()> {
        validate_identifier("rule id", &self.id)?;
        validate_identifier("stable rule id", &self.stable_id)?;
        if self.stable_id != self.id {
            return Err(RuleError::InvalidPack(format!(
                "stable id must equal rule id: {}",
                self.id
            )));
        }
        for selector in &self.paths {
            selector.validate()?;
        }
        if self.uncertainty.iter().any(|item| item.trim().is_empty()) {
            return Err(RuleError::InvalidPack(format!(
                "rule {} has an empty uncertainty entry",
                self.id
            )));
        }
        for (field, value) in [
            ("data class", self.data_class.as_deref()),
            ("lifecycle", self.lifecycle.as_deref()),
            ("remediation", self.remediation.as_deref()),
        ] {
            if value.is_some_and(|value| value.trim().is_empty()) {
                return Err(RuleError::InvalidPack(format!(
                    "rule {} has an empty {field}",
                    self.id
                )));
            }
        }
        self.evidence.validate(self.kind)?;
        self.coverage.validate()?;

        match (class, self.kind) {
            (RuleClass::A, RuleKind::Lexical) => {
                let matcher = self.matcher.as_ref().ok_or_else(|| {
                    RuleError::InvalidPack(format!("rule {} has no matcher", self.id))
                })?;
                matcher.validate(&self.id)?;
                validate_companions(&self.id, &self.companions)?;
                if self.selector.is_some() || self.implementation_key.is_some() {
                    return Err(RuleError::InvalidPack(format!(
                        "lexical rule {} cannot declare a selector or implementation key",
                        self.id
                    )));
                }
            }
            (RuleClass::B, RuleKind::Structural) => {
                let selector = self.selector.as_ref().ok_or_else(|| {
                    RuleError::InvalidPack(format!(
                        "structural rule {} has no Blueprint selector",
                        self.id
                    ))
                })?;
                selector.validate()?;
                if self.matcher.is_some()
                    || !self.companions.required.is_empty()
                    || !self.companions.negative.is_empty()
                    || self.implementation_key.is_some()
                {
                    return Err(RuleError::InvalidPack(format!(
                        "structural rule {} declares lexical or executable fields",
                        self.id
                    )));
                }
            }
            (RuleClass::C, RuleKind::Algorithmic) => {
                let implementation = self.implementation_key.as_deref().ok_or_else(|| {
                    RuleError::InvalidPack(format!(
                        "algorithmic rule {} requires implementation key",
                        self.id
                    ))
                })?;
                validate_identifier("implementation key", implementation)?;
                if self.matcher.is_some() || self.selector.is_some() {
                    return Err(RuleError::InvalidPack(format!(
                        "algorithmic rule {} cannot declare declarative selectors",
                        self.id
                    )));
                }
            }
            _ => {
                return Err(RuleError::InvalidPack(format!(
                    "rule {} kind does not match pack class",
                    self.id
                )))
            }
        }
        Ok(())
    }
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
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("prefix", self.prefix.as_deref()),
            ("suffix", self.suffix.as_deref()),
            ("exact", self.exact.as_deref()),
        ] {
            if let Some(value) = value {
                if value.trim().is_empty() {
                    return Err(RuleError::InvalidPack(format!(
                        "path selector {name} must be non-empty when present"
                    )));
                }
                if value.contains('\0') {
                    return Err(RuleError::InvalidPack(format!(
                        "path selector {name} contains NUL"
                    )));
                }
            }
        }
        if self.prefix.is_none() && self.suffix.is_none() && self.exact.is_none() {
            return Err(RuleError::InvalidPack(
                "path selector must declare prefix, suffix, or exact".into(),
            ));
        }
        Ok(())
    }

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

impl MatcherSpec {
    fn validate(&self, rule: &str) -> Result<()> {
        if self.pattern.is_empty() {
            return Err(RuleError::InvalidPack(format!(
                "rule {rule} has an empty matcher pattern"
            )));
        }
        Ok(())
    }
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

impl CoverageSpec {
    fn validate(&self) -> Result<()> {
        if self
            .denominator
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
            || self.gaps.iter().any(|gap| gap.trim().is_empty())
        {
            return Err(RuleError::InvalidPack(
                "coverage fields must be non-empty when present".into(),
            ));
        }
        Ok(())
    }
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

impl BlueprintSelector {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(RuleError::InvalidPack(
                "unsupported Blueprint selector version".into(),
            ));
        }
        validate_identifier("selector id", &self.selector_id)?;
        for (name, value) in [
            ("repositoryId", self.repository_id.as_deref()),
            ("pathPrefix", self.path_prefix.as_deref()),
            ("symbol", self.symbol.as_deref()),
            ("from", self.from.as_deref()),
            ("to", self.to.as_deref()),
            ("expectedGeneration", self.expected_generation.as_deref()),
        ] {
            if value.is_some_and(|value| value.trim().is_empty() || value.contains('\0')) {
                return Err(RuleError::InvalidPack(format!(
                    "Blueprint selector {name} must be non-empty when present"
                )));
            }
        }
        Ok(())
    }
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

impl BlueprintResult {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("Blueprint generation", &self.generation)?;
        let mut ids = std::collections::BTreeSet::new();
        for matched in &self.matches {
            validate_identifier("Blueprint match id", &matched.id)?;
            if !ids.insert(matched.id.as_str()) {
                return Err(RuleError::InvalidPack(format!(
                    "duplicate Blueprint match id: {}",
                    matched.id
                )));
            }
            for (field, value) in [
                ("path", matched.path.as_deref()),
                ("symbol", matched.symbol.as_deref()),
            ] {
                if value.is_some_and(|value| value.is_empty() || value.contains('\0')) {
                    return Err(RuleError::InvalidPack(format!(
                        "Blueprint match {} has invalid {field}",
                        matched.id
                    )));
                }
            }
            if matched.evidence.trim().is_empty() {
                return Err(RuleError::InvalidPack(format!(
                    "Blueprint match {} has no evidence",
                    matched.id
                )));
            }
        }
        if self.gaps.iter().any(|gap| gap.trim().is_empty()) {
            return Err(RuleError::InvalidPack(
                "Blueprint result gaps must be non-empty".into(),
            ));
        }
        Ok(())
    }
}

fn validate_companions(rule: &str, companions: &CompanionSpec) -> Result<()> {
    for matcher in companions.required.iter().chain(companions.negative.iter()) {
        matcher.validate(rule)?;
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(RuleError::InvalidPack(format!(
            "{field} must be a non-empty string"
        )));
    }
    Ok(())
}

impl EvidenceSpec {
    fn validate(&self, kind: RuleKind) -> Result<()> {
        let expected = match kind {
            RuleKind::Lexical => EvidenceAuthority::Lexical,
            RuleKind::Structural => EvidenceAuthority::Structural,
            RuleKind::Algorithmic => return Ok(()),
        };
        if self.authority != expected {
            return Err(RuleError::InvalidPack(
                "evidence authority does not match rule kind".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_selector_is_rejected_by_pack_validation() {
        let pack = AnalysisRulePack {
            schema_version: 1,
            kind: "analysis-rule-pack".into(),
            pack_id: "fixture".into(),
            version: "1".into(),
            class: RuleClass::A,
            engine_contract: "rust-regex-1".into(),
            rules: vec![RuleSpec {
                id: "fixture.rule".into(),
                stable_id: "fixture.rule".into(),
                kind: RuleKind::Lexical,
                severity: Severity::Info,
                confidence: Confidence::High,
                data_class: None,
                lifecycle: None,
                paths: vec![PathSelector {
                    prefix: Some(String::new()),
                    suffix: None,
                    exact: None,
                }],
                matcher: Some(MatcherSpec {
                    mode: MatchMode::Literal,
                    pattern: "needle".into(),
                }),
                companions: CompanionSpec::default(),
                evidence: EvidenceSpec::default(),
                uncertainty: Vec::new(),
                coverage: CoverageSpec::default(),
                remediation: None,
                selector: None,
                implementation_key: None,
            }],
            source_provenance: BTreeMap::new(),
        };

        let error = pack.validate().expect_err("empty path selector must fail");
        assert!(error.to_string().contains("path selector prefix"));
    }

    #[test]
    fn unconstrained_path_selector_is_rejected() {
        let error = (PathSelector {
            prefix: None,
            suffix: None,
            exact: None,
        })
        .validate()
        .expect_err("unconstrained path selector must fail");
        assert!(error
            .to_string()
            .contains("must declare prefix, suffix, or exact"));
    }
}
