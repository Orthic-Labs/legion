use crate::{
    error::{Result, RuleError},
    lexical::LexicalEngine,
    schema::{AnalysisRulePack, BlueprintSelector, RuleClass, RuleKind},
};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct CompiledRules {
    pub pack_id: String,
    pub version: String,
    pub class: RuleClass,
    pub lexical: Option<LexicalEngine>,
    pub structural: Vec<BlueprintSelector>,
}

pub struct RuleCompiler;

impl RuleCompiler {
    pub fn compile(pack: AnalysisRulePack) -> Result<CompiledRules> {
        if pack.schema_version != 1
            || pack.kind != "analysis-rule-pack"
            || pack.pack_id.trim().is_empty()
            || pack.version.trim().is_empty()
        {
            return Err(RuleError::InvalidPack(
                "schema version, kind, pack id, and version are required".into(),
            ));
        }
        if pack.rules.is_empty() {
            return Err(RuleError::InvalidPack("rules must not be empty".into()));
        }
        let mut ids = BTreeSet::new();
        for rule in &pack.rules {
            if rule.id.trim().is_empty() || rule.stable_id.trim().is_empty() {
                return Err(RuleError::InvalidPack(
                    "rule id and stable id are required".into(),
                ));
            }
            if !ids.insert(&rule.id) {
                return Err(RuleError::DuplicateRule(rule.id.clone()));
            }
            if rule.stable_id != rule.id {
                return Err(RuleError::InvalidPack(format!(
                    "stable id must equal rule id: {}",
                    rule.id
                )));
            }
        }
        match pack.class {
            RuleClass::A => Ok(CompiledRules {
                pack_id: pack.pack_id.clone(),
                version: pack.version.clone(),
                class: pack.class,
                lexical: Some(LexicalEngine::compile(&pack)?),
                structural: Vec::new(),
            }),
            RuleClass::B => {
                let mut structural = Vec::new();
                for rule in &pack.rules {
                    if rule.kind != RuleKind::Structural {
                        return Err(RuleError::InvalidPack(format!(
                            "Class B rule {} is not structural",
                            rule.id
                        )));
                    }
                    let selector = rule.selector.clone().ok_or_else(|| {
                        RuleError::InvalidPack(format!(
                            "Class B rule {} has no Blueprint selector",
                            rule.id
                        ))
                    })?;
                    if selector.schema_version != 1 {
                        return Err(RuleError::InvalidPack(format!(
                            "unsupported Blueprint selector version for {}",
                            rule.id
                        )));
                    }
                    structural.push(selector);
                }
                structural.sort_by(|left, right| left.selector_id.cmp(&right.selector_id));
                Ok(CompiledRules {
                    pack_id: pack.pack_id,
                    version: pack.version,
                    class: pack.class,
                    lexical: None,
                    structural,
                })
            }
            RuleClass::C => {
                if pack
                    .rules
                    .iter()
                    .any(|rule| rule.implementation_key.as_deref().unwrap_or("").is_empty())
                {
                    return Err(RuleError::InvalidPack(
                        "Class C rule requires implementation key".into(),
                    ));
                }
                Err(RuleError::UnsupportedClass(
                    "C (Rust provider required)".into(),
                ))
            }
        }
    }

    pub fn compile_json(input: &str) -> Result<CompiledRules> {
        let pack: AnalysisRulePack = serde_json::from_str(input)
            .map_err(|error| RuleError::InvalidPack(error.to_string()))?;
        Self::compile(pack)
    }
}

impl CompiledRules {
    pub fn evaluate_lexical(
        &self,
        files: &[crate::lexical::SourceFile],
    ) -> Option<crate::lexical::LexicalEvaluation> {
        self.lexical.as_ref().map(|engine| engine.evaluate(files))
    }

    pub fn selectors(&self) -> &[BlueprintSelector] {
        &self.structural
    }
}
