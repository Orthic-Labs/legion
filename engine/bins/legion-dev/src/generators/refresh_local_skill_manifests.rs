//! Port of `scripts/refresh-local-skill-manifests.mjs`.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use super::skill_catalog::build_skill_catalog;

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn default_rights_receipt(root: &Path, provenance: &str, license_state: &str) -> Result<Value, String> {
    if provenance != "legion-authored" || license_state != "licensed" {
        return Ok(Value::Null);
    }
    let bytes = fs::read(root.join("LICENSE")).map_err(|e| e.to_string())?;
    let mut o = Map::new();
    o.insert("kind".into(), Value::from("legion-rights-receipt"));
    o.insert("basis".into(), Value::from("repository-license"));
    o.insert("license".into(), Value::from("LICENSE"));
    o.insert("licenseDigest".into(), Value::from(digest_bytes(&bytes)));
    Ok(Value::Object(o))
}

fn files(root: &Path, current: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(current).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".DS_Store" || name == "__pycache__" || name.ends_with(".pyc") {
            continue;
        }
        if name.starts_with('.') && name != ".gitkeep" {
            continue;
        }
        let path = current.join(&name);
        if path.is_dir() {
            files(root, &path, out)?;
        } else {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            out.push(rel);
        }
    }
    Ok(())
}

pub fn derive_parity(bundle: &str, semantic: &Value, package_files: &[String]) -> Value {
    let selected = |pred: &dyn Fn(&str) -> bool| -> Vec<Value> {
        package_files.iter().filter(|p| pred(p)).cloned().map(Value::from).collect()
    };
    let description = semantic.get("description").and_then(Value::as_str).unwrap_or_default();
    let mut o = Map::new();
    o.insert("triggers".into(), Value::Array(vec![Value::from(format!("/{bundle}")), Value::from(description)]));
    o.insert("outputs".into(), Value::Array(selected(&|p| p.starts_with("references/"))));
    o.insert("scripts".into(), Value::Array(selected(&|p| p.starts_with("scripts/") || p.starts_with("hooks/"))));
    o.insert(
        "templates".into(),
        Value::Array(selected(&|p| {
            let has_dir = p.split('/').any(|seg| seg == "assets" || seg == "templates");
            has_dir && p.to_lowercase().contains("template")
        })),
    );
    o.insert(
        "schemas".into(),
        Value::Array(selected(&|p| p.split('/').any(|seg| seg == "schema" || seg == "schemas") || p.ends_with(".schema.json"))),
    );
    o.insert("receipts".into(), Value::Array(selected(&|p| p.ends_with(".receipt.json"))));
    o.insert("evals".into(), Value::Array(selected(&|p| p.split('/').any(|seg| seg == "eval" || seg == "evals"))));
    o.insert(
        "consumers".into(),
        Value::Array(vec![
            Value::from("src/registry/skills/index.json"),
            Value::from("src/registry/routing/domains.json"),
        ]),
    );
    Value::Object(o)
}

pub struct BuiltManifest {
    pub manifest_path: PathBuf,
    pub manifest: Value,
}

pub fn build_local_skill_manifest(root: &Path, bundle: &str) -> Result<BuiltManifest, String> {
    let skill_root = root.join("skills").join(bundle);
    let manifest_path = root.join("skills/manifests").join(format!("{bundle}.json"));
    if !skill_root.join("SKILL.md").is_file() {
        return Err(format!("missing skill entrypoint: {bundle}"));
    }
    let prior: Value = fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Object(Map::new()));

    let (index, _domains) = build_skill_catalog(root)?;
    let semantic = index
        .get("bundles")
        .and_then(Value::as_array)
        .and_then(|arr| arr.iter().find(|b| b.get("id").and_then(Value::as_str) == Some(bundle)))
        .cloned()
        .ok_or_else(|| format!("missing canonical catalog record: {bundle}"))?;

    let mut package_files = Vec::new();
    files(&skill_root, &skill_root, &mut package_files)?;

    let provenance = prior.get("provenance").and_then(Value::as_str).unwrap_or("legion-authored").to_string();
    let license_state = prior.get("licenseState").and_then(Value::as_str).unwrap_or("licensed").to_string();
    let rights_receipt = prior
        .get("rightsReceipt")
        .filter(|v| !v.is_null())
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| default_rights_receipt(root, &provenance, &license_state))?;
    let profiles = prior.get("profiles").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| {
        let mut audit = Map::new();
        audit.insert("mutation".into(), Value::from(false));
        audit.insert("publish".into(), Value::from(false));
        let mut authoring = Map::new();
        authoring.insert("mutation".into(), Value::from(true));
        authoring.insert("publish".into(), Value::from(false));
        authoring.insert("externalOnly".into(), Value::from(true));
        let mut o = Map::new();
        o.insert("audit".into(), Value::Object(audit));
        o.insert("authoring".into(), Value::Object(authoring));
        Value::Object(o)
    });

    let mut file_entries = Vec::new();
    for path in &package_files {
        let bytes = fs::read(skill_root.join(path)).map_err(|e| e.to_string())?;
        let hash = digest_bytes(&bytes);
        let mut o = Map::new();
        o.insert("path".into(), Value::from(path.clone()));
        o.insert("uri".into(), Value::from(format!("legion-skill://{bundle}/{path}")));
        o.insert("digest".into(), Value::from(hash));
        file_entries.push(Value::Object(o));
    }

    let mut manifest = Map::new();
    manifest.insert("schemaVersion".into(), Value::from(1));
    manifest.insert("id".into(), Value::from(bundle));
    manifest.insert("version".into(), prior.get("version").cloned().unwrap_or_else(|| Value::from("1.0.0")));
    manifest.insert("entry".into(), Value::from("SKILL.md"));
    manifest.insert("rootUri".into(), Value::from(format!("legion-skill://{bundle}/")));
    manifest.insert("provenance".into(), Value::from(provenance.clone()));
    manifest.insert("licenseState".into(), Value::from(license_state.clone()));
    manifest.insert("rightsReceipt".into(), rights_receipt);
    manifest.insert("profiles".into(), profiles);
    manifest.insert("parity".into(), derive_parity(bundle, &semantic, &package_files));
    manifest.insert("files".into(), Value::Array(file_entries));

    Ok(BuiltManifest { manifest_path, manifest: Value::Object(manifest) })
}

pub fn refresh_local_skill_manifest(root: &Path, bundle: &str) -> Result<PathBuf, String> {
    let built = build_local_skill_manifest(root, bundle)?;
    let text = format!("{}\n", serde_json::to_string_pretty(&built.manifest).unwrap());
    fs::write(&built.manifest_path, text).map_err(|e| e.to_string())?;
    Ok(built.manifest_path)
}

/// `legion-dev refresh-local-skill-manifests [--check] [BUNDLE...]`. With no
/// bundles given, `--check` checks every catalog bundle (matching the JS
/// default); without `--check` an empty bundle list is a usage error, same
/// as the JS script.
pub fn run_with_args(root: &Path, check: bool, requested: &[String]) -> bool {
    let bundles: Vec<String> = if !requested.is_empty() {
        requested.to_vec()
    } else if check {
        match build_skill_catalog(root) {
            Ok((index, _)) => index
                .get("bundles")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|b| b.get("id").and_then(Value::as_str).map(String::from)).collect())
                .unwrap_or_default(),
            Err(e) => {
                eprintln!("refresh-local-skill-manifests: {e}");
                return false;
            }
        }
    } else {
        vec![]
    };
    if bundles.is_empty() {
        eprintln!("usage: refresh-local-skill-manifests.mjs [--check] BUNDLE...");
        return false;
    }

    if check {
        for bundle in &bundles {
            let built = match build_local_skill_manifest(root, bundle) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("refresh-local-skill-manifests: {e}");
                    return false;
                }
            };
            let expected = format!("{}\n", serde_json::to_string_pretty(&built.manifest).unwrap());
            let actual = fs::read_to_string(&built.manifest_path).unwrap_or_default();
            if actual != expected {
                eprintln!("skill manifest drift: skills/manifests/{bundle}.json");
                return false;
            }
        }
        println!("skill manifests: no drift ({})", bundles.len());
        return true;
    }

    for bundle in &bundles {
        match refresh_local_skill_manifest(root, bundle) {
            Ok(path) => println!("{}", path.display()),
            Err(e) => {
                eprintln!("refresh-local-skill-manifests: {e}");
                return false;
            }
        }
    }
    true
}

/// No-arg entry point kept for the `legion-dev` subcommand signature; runs
/// `--check` over every catalog bundle (matching the JS default when no
/// bundle args are given and `--check` is set), since `legion-dev`'s clap
/// surface for this command carries only `--check`. Use `run_with_args`
/// directly to pass specific bundle ids.
pub fn run(root: &Path, check: bool) -> bool {
    run_with_args(root, check, &[])
}
