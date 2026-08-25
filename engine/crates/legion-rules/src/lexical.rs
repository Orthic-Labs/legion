use crate::{
    error::{Result, RuleError},
    evidence::{EvidenceSpan, RuleCoverage},
    schema::{AnalysisRulePack, MatchMode, MatcherSpec, PathSelector, RuleKind, RuleSpec},
};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

impl SourceFile {
    pub fn text(path: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            bytes: text.into().into_bytes(),
        }
    }
    pub fn normalized_path(&self) -> String {
        normalize_path(&self.path)
    }
}

#[derive(Clone, Debug)]
struct CompiledMatcher {
    regex: Regex,
}

impl CompiledMatcher {
    fn compile(rule: &str, matcher: &MatcherSpec) -> Result<Self> {
        let pattern = match matcher.mode {
            MatchMode::Regex => matcher.pattern.clone(),
            MatchMode::Literal => regex::escape(&matcher.pattern),
        };
        Regex::new(&pattern)
            .map(|regex| Self { regex })
            .map_err(|source| RuleError::InvalidPattern {
                rule: rule.into(),
                source,
            })
    }
    fn is_present(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

#[derive(Clone, Debug)]
struct CompiledLexicalRule {
    spec: RuleSpec,
    paths: Vec<PathSelector>,
    matcher: CompiledMatcher,
    required: Vec<CompiledMatcher>,
    negative: Vec<CompiledMatcher>,
}

#[derive(Clone, Debug)]
pub struct LexicalEngine {
    rules: Vec<CompiledLexicalRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LexicalEvaluation {
    pub findings: Vec<EvidenceSpan>,
    pub coverage: RuleCoverage,
}

impl LexicalEngine {
    pub(crate) fn compile(pack: &AnalysisRulePack) -> Result<Self> {
        if pack.engine_contract != "rust-regex-1" {
            return Err(RuleError::InvalidPack(
                "unsupported regex engine contract".into(),
            ));
        }
        if pack.class != crate::schema::RuleClass::A {
            return Err(RuleError::UnsupportedClass(format!("{:?}", pack.class)));
        }
        let mut rules = Vec::with_capacity(pack.rules.len());
        for spec in &pack.rules {
            if spec.kind != RuleKind::Lexical {
                return Err(RuleError::UnsupportedClass(format!(
                    "rule {} is not lexical",
                    spec.id
                )));
            }
            let matcher = spec.matcher.as_ref().ok_or_else(|| {
                RuleError::InvalidPack(format!("rule {} has no matcher", spec.id))
            })?;
            let required = spec
                .companions
                .required
                .iter()
                .map(|m| CompiledMatcher::compile(&spec.id, m))
                .collect::<Result<Vec<_>>>()?;
            let negative = spec
                .companions
                .negative
                .iter()
                .map(|m| CompiledMatcher::compile(&spec.id, m))
                .collect::<Result<Vec<_>>>()?;
            rules.push(CompiledLexicalRule {
                spec: spec.clone(),
                paths: spec.paths.clone(),
                matcher: CompiledMatcher::compile(&spec.id, matcher)?,
                required,
                negative,
            });
        }
        rules.sort_by(|left, right| left.spec.id.cmp(&right.spec.id));
        Ok(Self { rules })
    }

    pub fn evaluate(&self, files: &[SourceFile]) -> LexicalEvaluation {
        let mut ordered: Vec<(String, &SourceFile)> = files
            .iter()
            .map(|file| (file.normalized_path(), file))
            .collect();
        ordered.sort_by(|left, right| left.0.cmp(&right.0));
        let mut findings = Vec::new();
        for (path, file) in ordered.iter() {
            let text = String::from_utf8_lossy(&file.bytes);
            for rule in &self.rules {
                if !applies(&rule.paths, path) || !rule.required.iter().all(|m| m.is_present(&text)) {
                    continue;
                }
                for matched in rule.matcher.regex.find_iter(&text) {
                    if rule
                        .negative
                        .iter()
                        .any(|matcher| matcher.is_present(matched.as_str()))
                    {
                        continue;
                    }
                    let start = matched.start();
                    let end = matched.end();
                    findings.push(EvidenceSpan::from_text(
                        rule.spec.id.clone(),
                        path.clone(),
                        start,
                        end,
                        matched.as_str().to_owned(),
                        rule.spec.severity,
                        rule.spec.confidence,
                        rule.spec.evidence.authority,
                        rule.spec.uncertainty.clone(),
                        rule.spec.remediation.clone(),
                    ));
                }
            }
        }
        findings.sort_by(|left, right| {
            left.rule_id
                .cmp(&right.rule_id)
                .then(left.path.cmp(&right.path))
                .then(left.byte_start.cmp(&right.byte_start))
                .then(left.byte_end.cmp(&right.byte_end))
        });
        LexicalEvaluation {
            findings,
            coverage: RuleCoverage {
                expected_files: files.len(),
                examined_files: files.len(),
                gaps: Vec::new(),
            },
        }
    }
}

fn applies(selectors: &[PathSelector], path: &str) -> bool {
    selectors.is_empty() || selectors.iter().any(|selector| selector.matches(path))
}

pub fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    let normalized = path.replace('\\', "/");
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            let _ = parts.pop();
        } else {
            parts.push(part);
        }
    }
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        CompanionSpec, Confidence, CoverageSpec, EvidenceSpec, RuleClass, Severity,
    };

    #[test]
    fn negative_companions_apply_to_each_match_not_the_whole_file() {
        let pack = AnalysisRulePack {
            schema_version: 1,
            kind: "analysis-rule-pack".into(),
            pack_id: "fixture".into(),
            version: "1".into(),
            class: RuleClass::A,
            engine_contract: "rust-regex-1".into(),
            rules: vec![RuleSpec {
                id: "unsafe-call".into(),
                stable_id: "unsafe-call".into(),
                kind: RuleKind::Lexical,
                severity: Severity::Warning,
                confidence: Confidence::Medium,
                data_class: None,
                lifecycle: None,
                paths: Vec::new(),
                matcher: Some(MatcherSpec {
                    mode: MatchMode::Regex,
                    pattern: "(?i)(?:login|reset)\\([^\\n]*".into(),
                }),
                companions: CompanionSpec {
                    required: Vec::new(),
                    negative: vec![MatcherSpec {
                        mode: MatchMode::Literal,
                        pattern: "rateLimit".into(),
                    }],
                },
                evidence: EvidenceSpec::default(),
                uncertainty: Vec::new(),
                coverage: CoverageSpec::default(),
                remediation: None,
                selector: None,
                implementation_key: None,
            }],
            source_provenance: Default::default(),
        };
        let engine = LexicalEngine::compile(&pack).unwrap();
        let evaluation = engine.evaluate(&[SourceFile::text(
            "src/auth.rs",
            "login(user, rateLimit);\nreset(user);\n",
        )]);
        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(evaluation.findings[0].text, "reset(user);");
    }
}
