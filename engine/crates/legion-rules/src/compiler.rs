use crate::{
    error::{Result, RuleError},
    lexical::LexicalEngine,
    schema::{AnalysisRulePack, BlueprintSelector, NativePackManifest, RuleClass},
};
use std::collections::BTreeMap;

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
        pack.validate()?;
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
                    let selector = rule.selector.clone().ok_or_else(|| {
                        RuleError::InvalidPack(format!(
                            "Class B rule {} has no Blueprint selector",
                            rule.id
                        ))
                    })?;
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
            RuleClass::C => Err(RuleError::UnsupportedClass(
                "C (Rust provider required)".into(),
            )),
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
        manifest.validate()?;
        let mut compiled = BTreeMap::new();
        for pack in manifest.packs {
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
