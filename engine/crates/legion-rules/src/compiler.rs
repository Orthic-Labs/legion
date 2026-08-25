use crate::{
    error::{Result, RuleError},
    lexical::LexicalEngine,
    schema::{AnalysisRulePack, BlueprintSelector, NativePackManifest, RuleClass, RuleKind},
};
use std::collections::{BTreeMap, BTreeSet};

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

    pub fn compile_manifest(
        manifest: NativePackManifest,
    ) -> Result<BTreeMap<String, CompiledRules>> {
        if manifest.schema_version != 1
            || manifest.kind != "legion-native-pack-manifest"
            || manifest.repository.trim().is_empty()
            || manifest.packet_id.trim().is_empty()
            || manifest.baseline_commit.trim().is_empty()
            || manifest.engine_contract != "rust-regex-1"
        {
            return Err(RuleError::InvalidPack(
                "native pack manifest identity is invalid".into(),
            ));
        }
        let class_a = manifest
            .packs
            .iter()
            .filter(|pack| pack.class == RuleClass::A)
            .count();
        let class_b = manifest
            .packs
            .iter()
            .filter(|pack| pack.class == RuleClass::B)
            .count();
        let rule_count = manifest
            .packs
            .iter()
            .map(|pack| pack.rules.len())
            .sum::<usize>();
        if class_a != manifest.class_a
            || class_b != manifest.class_b
            || rule_count != manifest.rule_count
        {
            return Err(RuleError::InvalidPack(
                "native pack manifest counts do not reconcile".into(),
            ));
        }
        let mut compiled = BTreeMap::new();
        for pack in manifest.packs {
            if pack.engine_contract != manifest.engine_contract {
                return Err(RuleError::InvalidPack(format!(
                    "pack {} uses a different engine contract",
                    pack.pack_id
                )));
            }
            let pack_id = pack.pack_id.clone();
            if compiled
                .insert(pack_id.clone(), Self::compile(pack)?)
                .is_some()
            {
                return Err(RuleError::InvalidPack(format!(
                    "duplicate native pack id: {pack_id}"
                )));
            }
        }
        Ok(compiled)
    }

    pub fn compile_manifest_json(input: &str) -> Result<BTreeMap<String, CompiledRules>> {
        let manifest: NativePackManifest = serde_json::from_str(input)
            .map_err(|error| RuleError::InvalidPack(error.to_string()))?;
        Self::compile_manifest(manifest)
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
