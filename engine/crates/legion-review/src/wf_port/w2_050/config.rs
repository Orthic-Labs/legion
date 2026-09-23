//! Port of `src/lib/review/config.py`.
//!
//! Single loader for `models.yaml`. The Python source schema-validates via
//! `jsonschema` against `models.schema.json`; no JSON Schema validator crate
//! is available in this workspace's `Cargo.lock` (see the crate report for
//! the dependency patch). This port instead validates structurally through
//! `serde`'s required fields plus the same duplicate-juror-id consistency
//! check the Python performs post-schema (`_check_unique_ids`), which is the
//! check that actually guards runtime dispatch correctness.
//!
//! NOTE: requires `serde_yaml.workspace = true` added to this crate's
//! `Cargo.toml` (already a workspace dependency; used by `legion-catalog`
//! and `legion-research`). See the w2_050 report for the exact patch.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Mirrors Python's `ConfigError(ValueError)`: `models.yaml` failed schema
/// or consistency validation.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Deserialize)]
pub struct Juror {
    pub id: String,
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub lens: Option<String>,
    #[serde(default)]
    pub vision: Option<bool>,
    #[serde(default)]
    pub max_images: Option<i64>,
    #[serde(default)]
    pub max_tokens: Option<i64>,
    #[serde(default)]
    pub framing: Option<String>,
    #[serde(default)]
    pub output_schema: Option<String>,
    #[serde(default)]
    pub fallbacks: Vec<JurorFallback>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JurorFallback {
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Panel {
    #[serde(default)]
    pub framing: Option<String>,
    pub jurors: Vec<Juror>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Skill {
    #[serde(default)]
    pub rubric: Option<String>,
    #[serde(default)]
    pub framing: Option<String>,
    #[serde(default)]
    pub output_schema: Option<String>,
    #[serde(default)]
    pub needs_vision_input: Option<bool>,
    pub jurors: Vec<Juror>,
    #[serde(default)]
    pub escalation: Vec<Escalation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Escalation {
    pub trigger: String,
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Provider {
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub command_template: Vec<String>,
    #[serde(default)]
    pub parallel_safe: Option<bool>,
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub timeout_s: Option<f64>,
    #[serde(default)]
    pub min_gap_ms: Option<f64>,
    #[serde(default)]
    pub retry_codes_as_quota: Vec<i64>,
}

/// Mirrors the top-level shape of `models.yaml` after schema validation.
/// Unknown top-level keys (including expanded `_*_jurors` YAML anchors) are
/// preserved via `extra`, matching the schema's `additionalProperties: true`.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelsConfig {
    #[serde(default)]
    pub prompt_version: Option<i64>,
    pub providers: BTreeMap<String, Provider>,
    #[serde(default)]
    pub panels: BTreeMap<String, Panel>,
    pub skills: BTreeMap<String, Skill>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

/// Yield `(label, jurors)` for every seat lineup in the config: each panel's
/// jurors as `panels.<name>`, then each skill's jurors as `skills.<name>`.
/// Matches Python `_collect_lineups` iteration order.
fn collect_lineups(config: &ModelsConfig) -> Vec<(String, &Vec<Juror>)> {
    let mut out = Vec::new();
    for (name, panel) in &config.panels {
        out.push((format!("panels.{name}"), &panel.jurors));
    }
    for (name, skill) in &config.skills {
        out.push((format!("skills.{name}"), &skill.jurors));
    }
    out
}

/// Port of `_check_unique_ids`: within each single lineup, juror `id`s must
/// be unique.
fn check_unique_ids(config: &ModelsConfig) -> Result<(), ConfigError> {
    for (label, jurors) in collect_lineups(config) {
        let mut seen = std::collections::HashSet::new();
        for juror in jurors {
            if !seen.insert(juror.id.as_str()) {
                return Err(ConfigError(format!(
                    "{label}: duplicate juror id {:?} in one lineup",
                    juror.id
                )));
            }
        }
    }
    Ok(())
}

/// Load and validate `models.yaml` from `path` (or `<crate dir>/../models.yaml`
/// equivalent — callers pass the resolved path explicitly, since this port
/// has no notion of `__file__`-relative `ROOT`).
pub fn load_models_config(path: impl AsRef<Path>) -> Result<ModelsConfig, ConfigError> {
    let path: &Path = path.as_ref();
    let raw = std::fs::read_to_string(path)
        .map_err(|e| ConfigError(format!("{}: failed to read: {e}", path.display())))?;
    let config: ModelsConfig = serde_yaml::from_str(&raw)
        .map_err(|e| ConfigError(format!("{}: schema error: {e}", path.display())))?;
    check_unique_ids(&config)?;
    Ok(config)
}

/// Convenience matching the Python default: `<dir>/models.yaml`.
pub fn default_config_path(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join("models.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(label: &str, contents: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "legion-review-wf_w2_050-config-{label}-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    const VALID: &str = r#"
prompt_version: 3
providers:
  openai:
    type: openai
    base_url: https://api.openai.com
panels:
  main:
    jurors:
      - id: a
        provider: openai
        model: gpt-5
skills:
  review:
    rubric: some-rubric
    jurors:
      - id: a
        provider: openai
        model: gpt-5
      - id: b
        provider: openai
        model: gpt-5
"#;

    #[test]
    fn loads_valid_config() {
        let path = write_tmp("valid", VALID);
        let config = load_models_config(&path).expect("should load");
        assert_eq!(config.prompt_version, Some(3));
        assert_eq!(config.skills.len(), 1);
        assert_eq!(config.skills["review"].jurors.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_duplicate_juror_id_within_one_lineup() {
        let dup = r#"
providers:
  openai:
    type: openai
skills:
  review:
    jurors:
      - id: a
        provider: openai
        model: gpt-5
      - id: a
        provider: openai
        model: gpt-5-mini
"#;
        let path = write_tmp("dup", dup);
        let err = load_models_config(&path).expect_err("should reject duplicate id");
        assert!(err.0.contains("duplicate juror id"));
        assert!(err.0.contains("skills.review"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn allows_same_id_across_different_lineups() {
        let path = write_tmp("cross-lineup", VALID);
        // "a" appears in both panels.main and skills.review — that's fine,
        // uniqueness is per-lineup only.
        let config = load_models_config(&path).expect("should load");
        assert_eq!(config.panels["main"].jurors[0].id, "a");
        assert_eq!(config.skills["review"].jurors[0].id, "a");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_required_field_is_schema_error() {
        let bad = r#"
providers:
  openai:
    type: openai
skills:
  review:
    jurors:
      - id: a
        provider: openai
"#; // missing required `model`
        let path = write_tmp("missing-field", bad);
        let err = load_models_config(&path).expect_err("should fail to parse");
        assert!(err.0.contains("schema error"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_is_read_error() {
        let err = load_models_config("/nonexistent/does/not/exist/models.yaml")
            .expect_err("should fail to read");
        assert!(err.0.contains("failed to read"));
    }

    #[test]
    fn default_config_path_matches_python_layout() {
        let dir = Path::new("/some/dir");
        assert_eq!(default_config_path(dir), PathBuf::from("/some/dir/models.yaml"));
    }
}
