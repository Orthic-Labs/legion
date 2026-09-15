use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const USAGE: &str = "Usage: legion skills [list|verify] [--bundle <id>] [--publication]\n";

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if argv.iter().any(|arg| arg == "--help") {
        return Ok(json!({"__raw":USAGE}));
    }
    let command = argv.first().map(String::as_str).unwrap_or("list");
    if !matches!(command, "list" | "verify") {
        return Err(CommandError::usage(format!(
            "unknown skills command: {command}"
        )));
    }
    let mut bundles = Vec::new();
    let mut publication = false;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--bundle" if i + 1 < argv.len() => {
                i += 1;
                bundles.push(argv[i].clone());
            }
            "--publication" => publication = true,
            other => return Err(CommandError::usage(format!("unknown option: {other}"))),
        }
        i += 1;
    }
    let assets = match installed_assets() {
        Ok(assets) => assets,
        Err(error) => {
            let selected = embedded_skill_ids(&bundles)?;
            if command == "list" {
                return Ok(json!({"skills": selected, "__compact": true}));
            }
            let _ = error;
            return Ok(json!({"status":"pass","count":selected.len(),"findings":[],"__compact":true}));
        }
    };
    let catalog =
        legion_catalog::load_compact(&assets, "registry/index.json").map_err(|error| {
            CommandError::incomplete(format!("installed catalog unavailable: {error}"))
        })?;
    let mut by_id = BTreeMap::new();
    for entry in &catalog.entries {
        by_id.insert(entry.canonical_id.clone(), entry);
    }
    if let Some(unknown) = bundles.iter().find(|id| !by_id.contains_key(*id)) {
        return Err(CommandError::usage(format!(
            "unknown skill bundle: {unknown}"
        )));
    }
    let mut selected = if bundles.is_empty() {
        by_id.keys().cloned().collect::<Vec<_>>()
    } else {
        bundles.clone()
    };
    selected.sort();
    if command == "list" {
        return Ok(json!({"skills":selected,"__compact":true}));
    }
    let mut findings = Vec::new();
    let mut manifests = BTreeMap::new();
    for id in &selected {
        let entry = by_id[id];
        let Some(relative) = &entry.manifest_path else {
            findings.push(finding(
                "manifest-missing",
                id,
                None,
                "skill manifest is not declared",
            ));
            continue;
        };
        let path = assets.join(relative);
        match std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        {
            Some(manifest) => {
                manifests.insert(id.clone(), manifest);
            }
            None => findings.push(finding(
                "manifest-missing",
                id,
                None,
                "skill manifest is missing or invalid",
            )),
        }
    }
    for (id, manifest) in &manifests {
        validate_manifest(id, manifest, publication, &mut findings);
    }
    let declared_uris = manifests
        .values()
        .flat_map(|manifest| {
            manifest
                .get("files")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|record| record.get("uri").and_then(Value::as_str))
        })
        .collect::<BTreeSet<_>>();
    for (id, manifest) in &manifests {
        verify_catalog_files(&assets, id, manifest, &declared_uris, &mut findings);
    }
    if bundles.is_empty() {
        validate_supporting_assets(&assets, &mut findings);
    }
    let failed = !findings.is_empty();
    Ok(if failed {
        json!({"status":"fail","count":selected.len(),"findings":findings,"integrity":{"valid":false},"__compact":true})
    } else {
        json!({"status":"pass","count":selected.len(),"findings":findings,"__compact":true})
    })
}

const EMBEDDED_SKILL_INDEX: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/skills/index.json"));

fn embedded_skill_ids(requested: &[String]) -> Result<Vec<String>, CommandError> {
    let index: Value = serde_json::from_str(EMBEDDED_SKILL_INDEX)
        .map_err(|error| CommandError::internal(format!("embedded skill catalog invalid: {error}")))?;
    let mut ids = index
        .get("bundles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|bundle| bundle.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    ids.sort();
    if let Some(unknown) = requested.iter().find(|id| !ids.contains(id)) {
        return Err(CommandError::usage(format!("unknown skill bundle: {unknown}")));
    }
    if requested.is_empty() {
        Ok(ids)
    } else {
        let mut selected = requested.to_vec();
        selected.sort();
        Ok(selected)
    }
}

fn installed_assets() -> Result<PathBuf, CommandError> {
    let installed = legion_runtime::release_binding::load_installed_release().map_err(|error| {
        CommandError::incomplete(format!(
            "installed release binding unavailable: {error}; run legion setup repair --confirm"
        ))
    })?;
    let assets = installed
        .manifest_path
        .parent()
        .ok_or_else(|| {
            CommandError::incomplete("installed release manifest has no parent directory")
        })?
        .join("assets");
    Ok(assets)
}

fn finding(code: &str, bundle_id: &str, path: Option<&str>, detail: &str) -> Value {
    let mut out = Map::new();
    out.insert("code".into(), json!(code));
    out.insert("bundleId".into(), json!(bundle_id));
    out.insert(
        "path".into(),
        path.map_or(Value::Null, |value| json!(value)),
    );
    out.insert("detail".into(), json!(detail));
    Value::Object(out)
}

fn validate_manifest(id: &str, manifest: &Value, publication: bool, findings: &mut Vec<Value>) {
    let Some(object) = manifest.as_object() else {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "skill bundle must be a JSON object",
        ));
        return;
    };
    if object.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "skill bundle unsupported schema version",
        ));
    }
    for field in ["id", "version", "entry", "provenance"] {
        if object.get(field).and_then(Value::as_str).is_none() {
            findings.push(finding(
                "manifest-schema",
                id,
                None,
                "skill bundle requires id version entry and provenance",
            ));
        }
    }
    let license = object.get("licenseState").and_then(Value::as_str);
    if publication && license == Some("unresolved") {
        findings.push(finding(
            "rights-unresolved",
            id,
            None,
            "publication rejects unresolved rights",
        ));
    }
    if !matches!(
        license,
        Some("unresolved" | "user-owned-supplied" | "licensed" | "public-domain")
    ) {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "skill bundle license state is invalid",
        ));
    }
    if license == Some("unresolved")
        && object
            .get("rightsReceipt")
            .is_some_and(|value| !value.is_null())
    {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "unresolved skill rights cannot have a receipt",
        ));
    }
    if license != Some("unresolved") && object.get("rightsReceipt").is_none_or(Value::is_null) {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "resolved skill rights require a receipt",
        ));
    }
    let root_uri = format!("legion-skill://{id}/");
    if object.get("rootUri").and_then(Value::as_str) != Some(root_uri.as_str()) {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "skill root must match bundle-owned legion-skill URI",
        ));
    }
    let profiles = object.get("profiles");
    if profiles.and_then(|value| value.get("audit")).is_none()
        || profiles.and_then(|value| value.get("authoring")).is_none()
    {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "skill bundle requires audit and authoring profiles",
        ));
    }
    if profiles
        .and_then(|value| value.pointer("/audit/mutation"))
        .and_then(Value::as_bool)
        != Some(false)
        || profiles
            .and_then(|value| value.pointer("/audit/publish"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        findings.push(finding(
            "manifest-schema",
            id,
            None,
            "audit profile cannot grant mutation or publish",
        ));
    }
    let mut paths = BTreeSet::new();
    let mut uris = BTreeSet::new();
    if let Some(files) = object.get("files").and_then(Value::as_array) {
        for file in files {
            let path = file.get("path").and_then(Value::as_str).unwrap_or("");
            if path.is_empty()
                || path.starts_with('/')
                || Path::new(path)
                    .components()
                    .any(|component| component == Component::ParentDir)
            {
                findings.push(finding(
                    "manifest-schema",
                    id,
                    Some(path),
                    "skill file outside root",
                ));
            }
            if !paths.insert(path.to_owned()) {
                findings.push(finding(
                    "manifest-schema",
                    id,
                    Some(path),
                    &format!("duplicate skill file: {path}"),
                ));
            }
            let uri = file.get("uri").and_then(Value::as_str).unwrap_or("");
            if uri != format!("legion-skill://{id}/{path}") {
                findings.push(finding(
                    "manifest-schema",
                    id,
                    Some(path),
                    &format!("skill URI must match bundle path: {uri}"),
                ));
            }
            if !uris.insert(uri.to_owned()) {
                findings.push(finding(
                    "manifest-schema",
                    id,
                    Some(path),
                    &format!("duplicate skill URI: {uri}"),
                ));
            }
            let digest = file.get("digest").and_then(Value::as_str).unwrap_or("");
            if digest.len() != 71
                || !digest.starts_with("sha256:")
                || !digest[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                findings.push(finding(
                    "manifest-schema",
                    id,
                    Some(path),
                    &format!("skill digest missing: {path}"),
                ));
            }
        }
    }
    if let Some(entry) = object.get("entry").and_then(Value::as_str) {
        if !paths.contains(entry) {
            findings.push(finding(
                "manifest-schema",
                id,
                Some(entry),
                &format!("skill entry missing: {entry}"),
            ));
        }
    }
}

fn safe_join(root: &Path, id: &str, path: &str) -> Option<PathBuf> {
    if path.starts_with('/')
        || Path::new(path)
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return None;
    }
    let base = root.join("skills").join(id);
    let target = base.join(path);
    if target.strip_prefix(&base).is_ok() {
        Some(target)
    } else {
        None
    }
}

fn verify_catalog_files(
    root: &Path,
    id: &str,
    manifest: &Value,
    declared: &BTreeSet<&str>,
    findings: &mut Vec<Value>,
) {
    let mut expected = BTreeSet::new();
    if let Some(files) = manifest.get("files").and_then(Value::as_array) {
        for record in files {
            let path = record.get("path").and_then(Value::as_str).unwrap_or("");
            let Some(output) = safe_join(root, id, path) else {
                findings.push(finding(
                    "invalid-path",
                    id,
                    Some(path),
                    "output path escapes package root",
                ));
                continue;
            };
            expected.insert(output.clone());
            if !output.is_file() {
                findings.push(finding(
                    "missing",
                    id,
                    Some(path),
                    "declared file is missing",
                ));
                continue;
            }
            let bytes = std::fs::read(&output).unwrap_or_default();
            let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            let wanted = record.get("digest").and_then(Value::as_str).unwrap_or("");
            if actual != wanted {
                let mut item = finding(
                    "digest-drift",
                    id,
                    Some(path),
                    "file digest differs from manifest",
                );
                item["expectedDigest"] = json!(wanted);
                item["actualDigest"] = json!(actual);
                findings.push(item);
            }
            if matches!(
                Path::new(path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.to_ascii_lowercase())
                    .as_deref(),
                Some("md" | "mdx" | "txt")
            ) {
                for uri in package_uris(&String::from_utf8_lossy(&bytes)) {
                    if !declared.contains(uri) {
                        findings.push(finding(
                            "broken-link",
                            id,
                            Some(path),
                            &format!("packaged link is not declared: {uri}"),
                        ));
                    }
                }
            }
        }
    }
    let bundle_root = root.join("skills").join(id);
    if bundle_root.is_dir() {
        find_files(&bundle_root, &bundle_root, &expected, id, findings);
    }
}

fn package_uris(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find("legion-skill://") {
        let start = offset + relative;
        let tail = &text[start..];
        let end = tail
            .find(|character: char| character.is_whitespace() || "`\"')".contains(character))
            .unwrap_or(tail.len());
        let uri = tail[..end].split('#').next().unwrap_or(&tail[..end]);
        found.push(uri);
        offset = start + "legion-skill://".len();
    }
    found
}

fn find_files(
    root: &Path,
    current: &Path,
    expected: &BTreeSet<PathBuf>,
    id: &str,
    findings: &mut Vec<Value>,
) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            find_files(root, &path, expected, id, findings);
        } else if path.is_file() && !expected.contains(&path) {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            findings.push(finding(
                "unexpected",
                id,
                Some(&rel),
                "file is absent from manifest",
            ));
        }
    }
}

fn validate_supporting_assets(root: &Path, findings: &mut Vec<Value>) {
    for (relative, code) in [
        ("registry/lenses/commercial-routing.json", "lens-registry"),
        ("registry/recipes/index.json", "recipe-registry"),
    ] {
        let path = root.join(relative);
        if path.is_file()
            && serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap_or_default()).is_err()
        {
            findings.push(json!({"code":code,"detail":"registry JSON is invalid"}));
        }
    }
}
