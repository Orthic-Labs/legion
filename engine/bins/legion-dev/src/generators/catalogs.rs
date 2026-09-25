//! Port of `scripts/generate-catalogs.mjs`.
//!
//! Rebuilds `qualification/generated-catalogs.json` from
//! `src/registry/providers.json` and `src/registry/coverage/index.json`.
//! `--check` fails (and prints the same drift message) when the checked-in
//! file does not byte-match the freshly rendered content; otherwise it
//! writes the file and prints `wrote <relative path>`.

use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const OUT_REL: &str = "qualification/generated-catalogs.json";

fn pick(src: &Map<String, Value>, keys: &[&str]) -> Value {
    let mut out = Map::new();
    for k in keys {
        if let Some(v) = src.get(*k) {
            out.insert((*k).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Builds the catalogs document. `root` is the audit repo root (contains
/// `src/registry/...`).
pub fn build_catalogs(root: &Path) -> Result<Value, String> {
    let providers = read_json(&root.join("src/registry/providers.json"))?;
    let coverage = read_json(&root.join("src/registry/coverage/index.json"))?;

    let coverage_records = coverage
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let languages: Vec<Value> = coverage_records
        .iter()
        .filter(|r| r.get("kind").and_then(Value::as_str) == Some("language"))
        .filter_map(Value::as_object)
        .map(|o| pick(o, &["id", "tiers", "limitations", "providerVersions"]))
        .collect();

    let frameworks: Vec<Value> = coverage_records
        .iter()
        .filter(|r| r.get("kind").and_then(Value::as_str) == Some("framework"))
        .filter_map(Value::as_object)
        .map(|o| pick(o, &["id", "tiers", "limitations", "providerVersions"]))
        .collect();

    let providers_out: Vec<Value> = providers
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_object)
        .map(|o| pick(o, &["id", "providerVersion", "role", "family", "benchmark", "selectable"]))
        .collect();

    let support: Vec<Value> = coverage_records
        .iter()
        .filter_map(Value::as_object)
        .map(|o| pick(o, &["id", "tiers", "corpusDigest", "artifactDigest", "qualificationDigest"]))
        .collect();

    let mut out = Map::new();
    out.insert("schemaVersion".into(), Value::from(1));
    out.insert(
        "generatedFrom".into(),
        Value::Array(vec![
            Value::from("src/registry/providers.json"),
            Value::from("src/registry/coverage/index.json"),
        ]),
    );
    out.insert("languages".into(), Value::Array(languages));
    out.insert("frameworks".into(), Value::Array(frameworks));
    out.insert("providers".into(), Value::Array(providers_out));
    out.insert("support".into(), Value::Array(support));
    Ok(Value::Object(out))
}

fn render(value: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(value).unwrap())
}

/// `legion-dev generate-catalogs [--check]`
pub fn run(root: &Path, check: bool) -> bool {
    let target: PathBuf = root.join(OUT_REL);
    let expected = match build_catalogs(root) {
        Ok(v) => render(&v),
        Err(e) => {
            eprintln!("generate-catalogs: {e}");
            return false;
        }
    };

    if check {
        let actual = fs::read_to_string(&target).unwrap_or_default();
        if actual != expected {
            eprintln!(
                "catalog drift: {OUT_REL} does not match its canonical registry sources."
            );
            return false;
        }
        println!("qualification catalogs: no drift");
        true
    } else {
        if let Some(parent) = target.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("generate-catalogs: {e}");
                return false;
            }
        }
        if let Err(e) = fs::write(&target, expected) {
            eprintln!("generate-catalogs: {e}");
            return false;
        }
        println!("wrote {OUT_REL}");
        true
    }
}
